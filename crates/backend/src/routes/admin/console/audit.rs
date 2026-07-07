//! `GET /admin/console/audit` — Audit Log viewer (RFC 109, v0.71.0).
//!
//! Query parameters (all optional):
//!
//! | Param      | Meaning                                                |
//! |------------|--------------------------------------------------------|
//! | `prefix`   | Legacy R2 key prefix (v0.31.x compat — D1 ignores it). |
//! | `limit`    | Max number of matches. Hard-capped in adapter.         |
//! | `kind`     | Substring match on `kind` (legacy field).              |
//! | `subject`  | Substring match on `subject` (user / session id).      |
//! | `actor`    | Alias for `subject` — RFC 109 form-field name.         |
//! | `event`    | Exact match on `kind` (RFC 109 dropdown).              |
//! | `from`     | RFC 3339 UTC lower bound (inclusive). Maps to `since`. |
//! | `to`       | RFC 3339 UTC upper bound (inclusive). Maps to `until`. |
//! | `cursor`   | Opaque base64url pagination cursor (server-issued).    |
//!
//! Parsing notes (RFC 109):
//!
//! - `actor` and `subject` are accepted both. The form posts `actor`;
//!   the legacy URL still works.
//! - `from` and `to` are parsed via
//!   [`audit_pagination::parse_rfc3339_to_unix`]. Invalid timestamps
//!   are dropped silently rather than rejected with 400 — the operator
//!   sees the filter not applied; the rest of the page still renders.
//! - `cursor` is passed through verbatim; the adapter calls
//!   `decode_cursor` itself.

use cesauth_cf::admin::CloudflareAuditQuerySource;
use cesauth_core::admin::service::audit_pagination;
use cesauth_core::admin::service::search_audit;
use cesauth_core::admin::types::{AdminAction, AuditQuery};
use cesauth_frontend as ui;
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
            // Legacy params (v0.31.x compat) -------------------------------
            "prefix"   => q.prefix = Some(v.into_owned()),
            "limit"    => q.limit  = v.parse::<u32>().ok(),
            "kind"     => q.kind_contains    = Some(v.into_owned()),
            "subject"  => q.subject_contains = Some(v.into_owned()),
            // RFC 109 (v0.71.0) params -------------------------------------
            // `actor` is the form-field name; aliases to `subject_contains`.
            "actor"    => q.subject_contains = Some(v.into_owned()),
            // `event` is the exact-match dropdown selection.
            "event"    => q.event_exact      = Some(v.into_owned()),
            // RFC 3339 → Unix seconds; invalid values dropped silently
            // so the rest of the page still renders.
            "from"     => q.since = audit_pagination::parse_rfc3339_to_unix(&v),
            "to"       => q.until = audit_pagination::parse_rfc3339_to_unix(&v),
            // Opaque cursor: passed verbatim to the adapter.
            "cursor"   => q.cursor = Some(v.into_owned()),
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
                // RFC 109 fields surfaced in the JSON projection too,
                // so a CLI consumer that calls Accept: application/json
                // sees the same filter shape as the HTML view.
                "event":   q.event_exact,
                "since":   q.since,
                "until":   q.until,
                "cursor":  q.cursor,
            },
            "results": entries,
        }))
    } else {
        render::html_response(ui::admin::audit_page(&principal, &q, &entries))
    }
}
