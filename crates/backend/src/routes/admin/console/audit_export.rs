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

/// RFC 131 §0 slice 2 follow-up §1. An explicit `limit` from the form
/// (legacy v0.31.x callers) is honoured, clamped to 10,000, unchanged
/// from before this fix. A caller that sends none — every CSR export
/// form, old and new — no longer falls through to
/// `CloudflareAuditQuerySource`'s own `DEFAULT_LIMIT = 50` ("default
/// page size for the admin overview", not an export cap); that was the
/// defect this follow-up exists to close.
///
/// **The default is `max_rows + 1`, not `max_rows`.** `export_audit`
/// detects truncation as `rows.len() > max_rows` and only then slices
/// the result back down to `max_rows` — it needs to see one row past
/// the ceiling to know the ceiling was hit at all. Defaulting to
/// exactly `max_rows` was the first version of this fix, and it looked
/// right until driven over real HTTP with `AUDIT_EXPORT_MAX_ROWS` set
/// low (the follow-up's own evidence requirement, §1's "this path has
/// never been exercised"): the query could then never return more rows
/// than `max_rows`, so `rows.len() > max_rows` could never be true and
/// `truncated` stayed `false` even when rows were genuinely cut —
/// silently reproducing the exact defect this fix exists to close, one
/// layer down. `export_audit`'s own `.take(max_rows)` still bounds the
/// exported file to `max_rows` rows regardless of the `+1` — it only
/// changes whether the true/false that follows is correct.
fn resolve_export_limit(form_limit: Option<&str>, max_rows: usize) -> Option<u32> {
    form_limit
        .and_then(|s| s.parse::<u32>().ok())
        .map(|n| n.min(10_000))
        .or_else(|| Some(max_rows.saturating_add(1) as u32))
}

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

    // Read before building `query` below — the query's own `limit` now
    // defaults to this, so the two can no longer disagree (RFC 131 §0
    // slice 2 follow-up §1). Moved rather than the query built first:
    // `max_rows` has no other dependency, so there was no reason for the
    // read to come after.
    let max_rows: usize = ctx.env
        .var("AUDIT_EXPORT_MAX_ROWS")
        .ok()
        .and_then(|v| v.to_string().parse().ok())
        .unwrap_or(10_000);

    let query = AuditQuery {
        // v0.31.x compat fields.
        kind_contains:    get("kind").filter(|s| !s.is_empty()),
        subject_contains: get("subject").filter(|s| !s.is_empty()),
        limit: resolve_export_limit(get("limit").as_deref(), max_rows),
        // RFC 109 (v0.71.0) fields the new viewer sends. The viewer's
        // export form passes `subject` for actor, `event` for exact-
        // match event kind, and `since`/`until` as Unix seconds
        // (already converted from RFC 3339 at the viewer's UI layer).
        event_exact: get("event").filter(|s| !s.is_empty()),
        since:       get("since").and_then(|s| s.parse::<i64>().ok()),
        until:       get("until").and_then(|s| s.parse::<i64>().ok()),
        ..Default::default()
    };

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_form_limit_defaults_to_max_rows_plus_one() {
        assert_eq!(resolve_export_limit(None, 10_000), Some(10_001));
    }

    #[test]
    fn empty_form_limit_defaults_to_max_rows_plus_one() {
        // `get("limit")` yields `None` for an absent field and
        // `Some("")` for a present-but-empty one; `"".parse::<u32>()`
        // fails either way, so both land on the same branch.
        assert_eq!(resolve_export_limit(Some(""), 10_000), Some(10_001));
    }

    #[test]
    fn unparseable_form_limit_defaults_to_max_rows_plus_one() {
        assert_eq!(resolve_export_limit(Some("not-a-number"), 10_000), Some(10_001));
    }

    #[test]
    fn explicit_form_limit_is_honoured_without_the_plus_one() {
        // An explicit limit is a caller's own page-size request, not the
        // admin-configured ceiling — it is not adjusted to help
        // `export_audit` detect truncation against `max_rows`, which is
        // unchanged, pre-existing behaviour this follow-up does not touch.
        assert_eq!(resolve_export_limit(Some("25"), 10_000), Some(25));
    }

    #[test]
    fn explicit_form_limit_is_clamped_to_ten_thousand() {
        assert_eq!(resolve_export_limit(Some("999999"), 10_000), Some(10_000));
    }

    #[test]
    fn default_respects_a_lowered_max_rows() {
        // `AUDIT_EXPORT_MAX_ROWS` set low (RFC 131 §0 slice 2 follow-up's
        // own truncation-case evidence requirement) must change what a
        // field-omitting caller gets, not just what `export_audit`
        // truncates against.
        assert_eq!(resolve_export_limit(None, 5), Some(6));
    }

    #[test]
    fn the_plus_one_is_what_makes_truncation_detectable() {
        // Reproduces `export_audit`'s own check against this function's
        // result, rather than re-testing `export_audit` itself: with
        // exactly `max_rows` rows available, requesting `max_rows + 1`
        // still returns all of them (not truncated); with one more
        // available than that, the query is capped at `max_rows + 1` and
        // `export_audit`'s `rows.len() > max_rows` becomes true.
        let max_rows = 5usize;
        let query_limit = resolve_export_limit(None, max_rows).unwrap() as usize;
        assert_eq!(query_limit, 6);

        let rows_available_exactly_at_the_cap = 5;
        let returned = rows_available_exactly_at_the_cap.min(query_limit);
        assert!(!(returned > max_rows), "exactly at the cap must not report truncated");

        let rows_available_over_the_cap = 50;
        let returned = rows_available_over_the_cap.min(query_limit);
        assert!(returned > max_rows, "over the cap must report truncated");
    }
}
