//! Data Safety Dashboard (§4.3).
//!
//! `GET /admin/console/safety` renders the per-bucket safety report.
//! `POST /admin/console/safety/:bucket/verify` is the one cheap write
//! operation — a Security+ operator clicks "re-verified" after checking
//! the bucket's config in the Cloudflare dashboard, stamping
//! `last_verified_at`/`last_verified_by` without touching the attested
//! values. The console audits the stamp.

use cesauth_cf::admin::{CloudflareBucketSafetyRepository, CloudflareThresholdRepository};
use cesauth_core::admin::service::{build_safety_report, verify_bucket_safety};
use cesauth_core::admin::types::AdminAction;
use cesauth_ui as ui;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::ViewConsole) {
        return Ok(r);
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let safety = CloudflareBucketSafetyRepository::new(&ctx.env);
    let thresh = CloudflareThresholdRepository::new(&ctx.env);

    let report = build_safety_report(&safety, &thresh, now)
        .await
        .map_err(|e| worker::Error::RustError(format!("safety: {e}")))?;

    audit::write_owned(
        &ctx.env, EventKind::AdminConsoleViewed,
        Some(principal.id.clone()), None, Some("safety".into()),
    ).await.ok();

    if render::prefers_json(&req) {
        render::json_response(&serde_json::to_value(&report)
            .unwrap_or(serde_json::Value::Null))
    } else {
        render::html_response(ui::admin::safety_page(&principal, &report))
    }
}

/// `POST /admin/console/safety/:bucket/verify`
///
/// Stamp the attestation's `last_verified_at`. Requires Security+.
pub async fn verify<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
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
