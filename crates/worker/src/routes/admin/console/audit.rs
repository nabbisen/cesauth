//! `GET /admin/console/audit` — Audit Log search (§4.4).
//!
//! Query parameters (all optional):
//!
//! | Param      | Meaning                                               |
//! |------------|-------------------------------------------------------|
//! | `prefix`   | R2 key prefix. Defaults to today's `audit/YYYY/MM/DD/`|
//! | `limit`    | Max number of matches. Hard-capped to 200 in adapter. |
//! | `kind`     | Substring match on `kind` (e.g. `auth_failed`).       |
//! | `subject`  | Substring match on `subject` (user / session id).     |
//!
//! The adapter is intentionally simple: list under `prefix`, fetch
//! each object, filter in-adapter. For a month-sized sweep the
//! operator should narrow `prefix` to a week or day to keep round-trip
//! count bounded.

use cesauth_cf::admin::CloudflareAuditQuerySource;
use cesauth_core::admin::service::search_audit;
use cesauth_core::admin::types::{AdminAction, AuditQuery};
use cesauth_ui as ui;
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

    // Parse query params into an AuditQuery.
    let url = req.url()?;
    let mut q = AuditQuery::default();
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "prefix"   => q.prefix = Some(v.into_owned()),
            "limit"    => q.limit  = v.parse::<u32>().ok(),
            "kind"     => q.kind_contains    = Some(v.into_owned()),
            "subject"  => q.subject_contains = Some(v.into_owned()),
            _          => {}
        }
    }

    let source = CloudflareAuditQuerySource::new(&ctx.env);
    let entries = search_audit(&source, &q)
        .await
        .map_err(|e| worker::Error::RustError(format!("audit search: {e}")))?;

    audit::write_owned(
        &ctx.env, EventKind::AdminConsoleViewed,
        Some(principal.id.clone()), None, Some("audit".into()),
    ).await.ok();

    if render::prefers_json(&req) {
        render::json_response(&serde_json::json!({
            "query":   {
                "prefix":  q.prefix,
                "limit":   q.limit,
                "kind":    q.kind_contains,
                "subject": q.subject_contains,
            },
            "results": entries,
        }))
    } else {
        render::html_response(ui::admin::audit_page(&principal, &q, &entries))
    }
}
