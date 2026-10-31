//! Data Safety Dashboard (§4.3).
//!
//! `GET /admin/console/safety` serves the Leptos shell only — the
//! per-bucket safety report this doc used to describe was never built
//! into this handler. See RFC 161.
//!
//! `POST /admin/console/safety/:bucket/verify` is real and unaffected
//! by the above: it is the one cheap write operation — a Security+
//! operator clicks "re-verified" after checking
//! the bucket's config in the Cloudflare dashboard, stamping
//! `last_verified_at`/`last_verified_by` without touching the attested
//! values. The console audits the stamp.

use cesauth_cf::admin::CloudflareBucketSafetyRepository;
use cesauth_core::admin::service::verify_bucket_safety;
use cesauth_core::admin::types::AdminAction;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::admin::operator_json_api::shell(&req, &ctx, "安全性 — cesauth").await
}

/// `POST /admin/console/safety/:bucket/verify`
///
/// Stamp the attestation's `last_verified_at`. Requires Security+.
///
/// **RFC 152 half C — departure from the handoff's class A, stated
/// here rather than guessed past.** The handoff lists this route as
/// class A (a real browser form needing the double-submit token) on the
/// strength of its content-negotiation: "the HTML branch redirects back
/// to its form." That form does not exist on any LIVE route. The only
/// template that renders one — `cesauth_frontend::admin::safety_page`'s
/// `render_row`, with a real `<form method="post" action="...">` — is
/// called from nowhere but its own tests (`grep -rn "safety_page\b"`
/// outside `admin/safety.rs`/`admin/tests.rs`: zero call sites). The
/// LIVE `GET /admin/console/safety` serves the Leptos CSR shell, whose
/// actual component, `ConsoleSafety` in
/// `pages/operator/console.rs`, is a bare placeholder that says so
/// itself: *"検証結果の一覧表示は未実装です(RFC 161)"* ("the result
/// listing is not implemented"). So there is no live GET anywhere that
/// could mint a token and hand it to a form a browser could submit —
/// the premise behind class A's "real browser form" does not hold for
/// this one route, the same way class B's premise would not have held
/// had any of its four turned out to have a real caller (§1 of the
/// handoff). Treated as class B instead: bearer-header-only, no
/// double-submit token, `N/A (bearer)`. If a browser form for this
/// route is ever built (closing RFC 161's gap here), it needs the
/// stage-1 pattern at that point, not before.
pub async fn verify<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond_header_only(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::VerifyBucketSafety) {
        return Ok(r);
    }

    let Some(bucket) = ctx.param("bucket") else {
        return Response::error("missing bucket", 400);
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let safety = CloudflareBucketSafetyRepository::new(&ctx.env);

    let verifier_label = principal.name.clone().unwrap_or_else(|| principal.id.clone());
    match verify_bucket_safety(&safety, bucket, &verifier_label, now).await {
        Ok(state) => {
            audit::write_owned(
                &ctx.env, EventKind::AdminBucketSafetyVerified,
                Some(principal.id.clone()), None, Some(bucket.to_owned()),
            ).await.ok();

            // If the POST came from the HTML form, redirect back to the
            // dashboard. Otherwise (JSON clients) return the new state.
            if render::prefers_json(&req) {
                render::json_response(&serde_json::json!({
                    "ok":     true,
                    "state":  state,
                }))
            } else {
                let mut resp = Response::empty()?.with_status(303);
                let _ = resp.headers_mut().set("location", "/admin/console/safety");
                let _ = resp.headers_mut().set("cache-control", "no-store");
                Ok(resp)
            }
        }
        Err(cesauth_core::ports::PortError::NotFound) => {
            Response::error("unknown bucket", 404)
        }
        Err(e) => {
            Response::error(format!("verify failed: {e}"), 500)
        }
    }
}
