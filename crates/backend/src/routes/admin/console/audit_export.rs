//! `POST /admin/console/audit/export` — export filtered audit rows (RFC 080).
//!
//! v0.71.0 (RFC 109): also accepts the `event`, `since`, `until` form
//! fields the new audit viewer hands off via its export form. The
//! handler stays backward-compatible — the v0.31.x form fields (`kind`,
//! `subject`, `limit`) still work, and unrecognised fields are ignored.

use time::OffsetDateTime;
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
///
/// RFC 131 §0 slice 2, round 3 §2. Two more edge cases in the same
/// shape, both low severity and both closed because they're the third
/// instance of it in this one function:
///
/// - A floor of 1. An explicit `limit=0` (no caller sends this today)
///   previously resolved to `Some(0)` — an empty export whose
///   `truncated = 0 > max_rows` is `false`, an empty file claiming
///   completeness, the same lie this function exists to stop telling.
/// - `u32::try_from(..).unwrap_or(u32::MAX)` rather than `as`. The `as`
///   cast wraps on overflow instead of saturating: `max_rows =
///   u32::MAX` made `saturating_add(1)` (correct on the `usize` side)
///   wrap back down to `0` on the cast to `u32`, and `max_rows = 2^32`
///   wrapped to `1` — an absurd admin-configured ceiling silently
///   becoming the one value (`0` or `1`) this function must never
///   return.
fn resolve_export_limit(form_limit: Option<&str>, max_rows: usize) -> Option<u32> {
    let limit = form_limit
        .and_then(|s| s.parse::<u32>().ok())
        .map(|n| n.min(10_000))
        .unwrap_or_else(|| u32::try_from(max_rows.saturating_add(1)).unwrap_or(u32::MAX));
    Some(limit.max(1))
}

/// RFC 187 round 2 §4(b). Every filter dimension actually applied to
/// `query`, named in the export's own `AuditExported` audit event — not
/// just the event-kind one, which left `subject`/`actor`/`since`/
/// `until` unrecorded on an audited export whose point is audit
/// completeness. `"*"` means no filter was applied at all. Pulled out
/// as its own pure function (same reason `resolve_export_limit` is one)
/// so the shape is host-testable without a live `worker::Env`.
fn build_filter_desc(query: &AuditQuery) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(v) = query.event_exact.as_deref().or(query.kind_contains.as_deref()) {
        parts.push(format!("event={v}"));
    }
    if let Some(v) = query.subject_exact.as_deref() {
        parts.push(format!("subject={v}"));
    }
    if let Some(v) = query.actor_exact.as_deref() {
        parts.push(format!("actor={v}"));
    }
    if let Some(v) = query.since {
        parts.push(format!("from={v}"));
    }
    if let Some(v) = query.until {
        parts.push(format!("to={v}"));
    }
    if parts.is_empty() { "*".to_owned() } else { parts.join(",") }
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
    //
    // `0.110.0`-signals-get-readers F-5: shared with `audit::page_json`
    // (`super::resolve_max_rows`) so the viewer's cap line and this
    // route's actual cap cannot drift apart.
    let max_rows: usize = super::resolve_max_rows(&ctx.env);

    let query = AuditQuery {
        // v0.31.x compat fields.
        kind_contains:    get("kind").filter(|s| !s.is_empty()),
        subject_exact: get("subject").filter(|s| !s.is_empty()),
        limit: resolve_export_limit(get("limit").as_deref(), max_rows),
        // RFC 109 (v0.71.0) fields the new viewer sends. The viewer's
        // export form passes `subject` for its own (mislabelled) actor
        // filter, `event` for exact-match event kind, and `since`/`until`
        // as Unix seconds (already converted from RFC 3339 at the
        // viewer's UI layer). RFC 187 round 2 T6/§4(a): `performed_by`
        // is the genuinely new actor filter the viewer's export form
        // now also carries.
        event_exact: get("event").filter(|s| !s.is_empty()),
        actor_exact: get("performed_by").filter(|s| !s.is_empty()),
        since:       get("since").and_then(|s| s.parse::<i64>().ok()),
        until:       get("until").and_then(|s| s.parse::<i64>().ok()),
        ..Default::default()
    };

    let audit_repo = cesauth_cf::admin::CloudflareAuditQuerySource::new(&ctx.env);
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    let result = export_audit(&audit_repo, &query, format, max_rows, now_unix).await
        .map_err(|e| worker::Error::RustError(format!("audit export failed: {e:?}")))?;

    // Emit audit event for the export operation itself. RFC 187 round 2
    // §4(b): `build_filter_desc` used to name only the event-kind
    // dimension, leaving `subject`/`actor`/`since`/`until` unrecorded —
    // an audited export whose own audit record did not say what was
    // filtered, the date range half of which was security-review F-1
    // (`docs/src/expert/security-review-2026-q4.md`).
    let filter_desc = build_filter_desc(&query);
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

    #[test]
    fn explicit_zero_limit_floors_to_one() {
        assert_eq!(resolve_export_limit(Some("0"), 10_000), Some(1));
    }

    #[test]
    fn an_absurd_max_rows_does_not_wrap_to_zero_or_one() {
        assert_eq!(resolve_export_limit(None, u32::MAX as usize), Some(u32::MAX));
    }

    // RFC 187 round 2 §4(b) — build_filter_desc

    #[test]
    fn no_filter_applied_is_a_star() {
        assert_eq!(build_filter_desc(&AuditQuery::default()), "*");
    }

    #[test]
    fn every_dimension_that_is_set_is_named() {
        let q = AuditQuery {
            event_exact:   Some("auth_failed".to_owned()),
            subject_exact: Some("alice".to_owned()),
            actor_exact:   Some("bob".to_owned()),
            since:         Some(1_700_000_000),
            until:         Some(1_700_100_000),
            ..Default::default()
        };
        assert_eq!(
            build_filter_desc(&q),
            "event=auth_failed,subject=alice,actor=bob,from=1700000000,to=1700100000",
        );
    }

    #[test]
    fn event_exact_wins_over_kind_contains_when_both_are_set() {
        let q = AuditQuery {
            event_exact:   Some("auth_failed".to_owned()),
            kind_contains: Some("auth".to_owned()),
            ..Default::default()
        };
        assert_eq!(build_filter_desc(&q), "event=auth_failed");
    }

    #[test]
    fn kind_contains_is_used_for_legacy_callers_with_no_event_exact() {
        let q = AuditQuery {
            kind_contains: Some("auth".to_owned()),
            ..Default::default()
        };
        assert_eq!(build_filter_desc(&q), "event=auth");
    }

    #[test]
    fn subject_and_actor_are_independent_dimensions() {
        // The two filters this cut's own naming confusion is about:
        // confirms they are not conflated into one slot.
        let q = AuditQuery {
            subject_exact: Some("alice".to_owned()),
            ..Default::default()
        };
        assert_eq!(build_filter_desc(&q), "subject=alice");

        let q = AuditQuery {
            actor_exact: Some("bob".to_owned()),
            ..Default::default()
        };
        assert_eq!(build_filter_desc(&q), "actor=bob");
    }
}
