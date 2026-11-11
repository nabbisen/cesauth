//! `/admin/console/audit` — Audit Log viewer (RFC 131 §0 slice 1).
//!
//! | Route | What it does |
//! |---|---|
//! | `GET /admin/console/audit` | the Leptos shell (CSR `ConsoleAudit`, this slice) |
//! | `GET /admin/console/audit.json` | `{"entries": [...], "csrf_token": "...", "older_cursor": ..., "has_newer": ...}` |
//! | `POST /admin/console/audit/export` | unchanged — `audit_export::export`, already built and authorized |
//!
//! Both GET handlers now call [`auth::ensure_role_allows`] with
//! `AdminAction::ViewConsole` (RFC 161 §6.3's first dropped control —
//! `every_role_may_view_console` already asserts this denies nobody
//! today; it is defence in depth for a future, more restricted role,
//! not a live authorization hole). `page` additionally writes
//! `EventKind::AdminConsoleViewed` (RFC 161 §6.3's second control).
//!
//! **Deliberately not routed through `operator_json_api::shell`**:
//! that helper discards the resolved principal, and widening its
//! contract to add a role check or an audit write would land on the
//! other five not-yet-built consoles too, unreviewed. `page` inlines
//! the two extra steps instead — the same shape `require_system_admin!`
//! already gives the five handlers that use it.
//!
//! **This reverses RFC 154's own classification of `AdminConsoleViewed`
//! as "intentionally unemitted... a decision not to audit, not a
//! gap."** See this slice's implementation report for why that is a
//! deliberate, named reversal and not an oversight.

use worker::{Request, Response, Result, RouteContext};

use cesauth_core::admin::service::{audit_pagination::encode_cursor, search_audit};
use cesauth_core::admin::types::{AdminAction, AuditQuery};
use cesauth_core::admin::service::audit_pagination::parse_rfc3339_to_unix;

use crate::audit::{self, EventKind};
use crate::csrf;
use crate::require_system_admin;

/// Default page size — mirrors the CSR component's own default and
/// the pre-`580eeba` server-rendered viewer's `DEFAULT_LIMIT`.
const DEFAULT_LIMIT: u32 = 100;

/// Extract a `seq=NNN` integer from an [`cesauth_core::admin::types::AdminAuditEntry::key`]
/// field. `None` for a key not in that format, which keeps pagination
/// safe — the `older_cursor` is simply omitted rather than built from
/// a wrong value. Duplicated from the pre-`580eeba` server-rendered
/// viewer (`crates/frontend/src/admin/audit.rs`, not deleted this
/// slice — see §2 of the handoff) rather than shared across crates for
/// a two-line helper.
fn parse_seq_from_key(key: &str) -> Option<i64> {
    key.strip_prefix("seq=").and_then(|s| s.parse::<i64>().ok())
}

// -------------------------------------------------------------------------
// GET /admin/console/audit
// -------------------------------------------------------------------------

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    require_system_admin!(req, ctx, principal, AdminAction::ViewConsole);

    // Best-effort: a failed audit write must not block the page render
    // (same discipline every other `.await.ok()` write site in this
    // crate uses) — the operator already has the data; losing the
    // record of having looked is the lesser failure.
    audit::write_owned(&ctx.env, EventKind::AdminConsoleViewed, Some(principal.id.clone()), None, None)
        .await.ok();

    // RFC 185 §5.3 screen 1 — this is the first route in the project to
    // negotiate: `resolve_locale` reads `Accept-Language` instead of a
    // hardcoded `Locale::Ja`. `mounted_locale()` reads this back from
    // `<html lang>` client-side (D5), which is why the title is composed
    // from the same catalog key the component itself uses, not a second
    // hardcoded string.
    let locale = crate::i18n::resolve_locale(&req);
    let title = format!("{} — cesauth", cesauth_core::i18n::lookup(cesauth_core::i18n::MessageKey::AuditViewerPageTitle, locale));
    crate::routes::leptos_shell::leptos_html_shell(&req, &ctx.env, &title, locale).await
}

// -------------------------------------------------------------------------
// GET /admin/console/audit.json
// -------------------------------------------------------------------------

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    require_system_admin!(req, ctx, _principal, AdminAction::ViewConsole);

    // No AdminConsoleViewed write here — `page` already wrote one for
    // this navigation; a filter/pager re-fetch of this endpoint is
    // continued use of an already-recorded view, not a new one.

    let url = req.url()?;
    let mut actor:  Option<String> = None;
    let mut event:  Option<String> = None;
    let mut since:  Option<i64>    = None;
    let mut until:  Option<i64>    = None;
    let mut cursor: Option<String> = None;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "actor"  if !v.is_empty() => actor  = Some(v.into_owned()),
            "event"  if !v.is_empty() => event  = Some(v.into_owned()),
            "from"   if !v.is_empty() => since  = parse_rfc3339_to_unix(&v),
            "to"     if !v.is_empty() => until  = parse_rfc3339_to_unix(&v),
            "cursor" if !v.is_empty() => cursor = Some(v.into_owned()),
            _ => {}
        }
    }
    let has_newer = cursor.is_some();

    let query = AuditQuery {
        subject_contains: actor,
        event_exact:       event,
        since,
        until,
        cursor,
        limit: Some(DEFAULT_LIMIT),
        ..Default::default()
    };

    let audit_repo = cesauth_cf::admin::CloudflareAuditQuerySource::new(&ctx.env);
    let entries = match search_audit(&audit_repo, &query).await {
        Ok(e)  => e,
        Err(e) => return Response::error(format!("audit search failed: {e}"), 500),
    };

    let older_cursor = if entries.len() >= DEFAULT_LIMIT as usize {
        entries.last()
            .and_then(|e| parse_seq_from_key(&e.key))
            .map(encode_cursor)
    } else {
        None
    };

    let csrf_token = csrf::mint()
        .map_err(|_| worker::Error::RustError("csrf rng failed".into()))?;
    let set_cookie = csrf::set_cookie_header(&csrf_token);

    let mut resp = Response::from_json(&serde_json::json!({
        "entries":      entries,
        "csrf_token":   csrf_token,
        "older_cursor": older_cursor,
        "has_newer":    has_newer,
    }))?;
    resp.headers_mut().append("set-cookie", &set_cookie).ok();
    resp.headers_mut().set("cache-control", "no-store").ok();
    Ok(resp)
}
