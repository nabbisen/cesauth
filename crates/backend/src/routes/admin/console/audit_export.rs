//! `POST /admin/console/audit/export` — export filtered audit rows (RFC 080).
//!
//! v0.71.0 (RFC 109): also accepts the `event`, `since`, `until` form
//! fields the new audit viewer hands off via its export form. The
//! handler stays backward-compatible — the v0.31.x form fields (`kind`,
//! `subject`, `limit`) still work, and unrecognised fields are ignored.

use worker::{Request, Response, RouteContext};

use cesauth_core::admin::{
    service::{export_audit, ExportFormat},
    types::{AdminAction, AuditQuery},
};

use crate::{audit as waudit, audit::EventKind, csrf, require_system_admin};

pub async fn export<D>(mut req: Request, ctx: RouteContext<D>) -> worker::Result<Response> {
    require_system_admin!(req, ctx, principal, AdminAction::ViewConsole);

    // RFC 141 C1-141 item 2 — this is a form POST reachable with a session
    // cookie (`require_system_admin!` admits the cookie path), so
    // `route-contracts.md`'s "required" CSRF column was a claim with no
    // check behind it. Same double-submit pattern as `audit_chain.rs`'s
    // `verify_now`, read before `form_data()` consumes the body.
    let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();
    let form = req.form_data().await?;
    let get  = |key: &str| -> Option<String> {
        form.get(key).and_then(|e| {
            if let worker::FormEntry::Field(v) = e { Some(v) } else { None }
        })
    };
    let csrf_form   = get("csrf").unwrap_or_default();
    let csrf_cookie = csrf::extract_from_cookie_header(&cookie_header).unwrap_or("");
    if !csrf::verify(&csrf_form, csrf_cookie) {
        return Response::error("Bad Request", 400);
    }

    let format = match get("format").as_deref() {
        Some("jsonl") => ExportFormat::Jsonl,
        _             => ExportFormat::Csv,
    };

    let query = AuditQuery {
        // v0.31.x compat fields.
        kind_contains:    get("kind").filter(|s| !s.is_empty()),
        subject_contains: get("subject").filter(|s| !s.is_empty()),
        limit: get("limit")
            .and_then(|s| s.parse::<u32>().ok())
            .map(|n| n.min(10_000)),
        // RFC 109 (v0.71.0) fields the new viewer sends. The viewer's
        // export form passes `subject` for actor, `event` for exact-
        // match event kind, and `since`/`until` as Unix seconds
        // (already converted from RFC 3339 at the viewer's UI layer).
        event_exact: get("event").filter(|s| !s.is_empty()),
        since:       get("since").and_then(|s| s.parse::<i64>().ok()),
        until:       get("until").and_then(|s| s.parse::<i64>().ok()),
        ..Default::default()
    };

    let max_rows: usize = ctx.env
        .var("AUDIT_EXPORT_MAX_ROWS")
        .ok()
        .and_then(|v| v.to_string().parse().ok())
        .unwrap_or(10_000);

    let audit_repo = cesauth_cf::admin::CloudflareAuditQuerySource::new(&ctx.env);
    let result = export_audit(&audit_repo, &query, format, max_rows).await
        .map_err(|e| worker::Error::RustError(format!("audit export failed: {e:?}")))?;

    // Emit audit event for the export operation itself. Filter
    // description prefers the more specific RFC 109 fields when set,
    // falling back to the legacy `kind` substring for older callers.
    let filter_desc = query.event_exact
        .as_deref()
        .or(query.kind_contains.as_deref())
        .unwrap_or("*");
    waudit::write_owned(
        &ctx.env,
        EventKind::AuditExported,
        Some(principal.id.clone()),
        None,
        Some(format!(
            "format={} rows={} truncated={} filter={}",
            format.extension(),
            result.row_count,
            result.truncated,
            filter_desc,
        )),
    ).await.ok(); // best-effort — don't fail the export if audit write fails

    let disp = format!(r#"attachment; filename="{}""#, result.filename);
    let mut resp = Response::ok(result.body)?;
    let h = resp.headers_mut();
    h.set("content-type", result.content_type)?;
    h.set("content-disposition", &disp)?;
    h.set("cache-control", "no-store")?;
    if result.truncated {
        h.set("x-cesauth-export-truncated", "true")?;
    }
    Ok(resp)
}
