//! Audit log viewer page — RFC 109 (v0.71.0).
//!
//! Replaces the v0.32.0–v0.70.0 audit search page. The new viewer:
//!
//! - is JA-only per ADR-013 (admin console policy);
//! - takes filters as URL query params: `actor`, `event`, `from`, `to`,
//!   `cursor`;
//! - paginates via an opaque base64url cursor over `seq` (server-issued
//!   by `cesauth_core::admin::service::audit_pagination::encode_cursor`);
//! - hands the current filter set off to the RFC 080 export endpoint
//!   (`POST /admin/console/audit/export`), so the operator can `絞り
//!   込む → export` without re-entering the filter.
//!
//! The `tenant` query parameter mentioned in the original RFC 109 draft
//! was dropped at implementation time — the `audit_events` schema has no
//! `tenant_id` column. See RFC 109 §"Scope amendments at implementation
//! time (v0.71.0)" for details.

use crate::escape;
use cesauth_core::admin::scope::ScopeBadge;
use cesauth_core::admin::service::audit_pagination::encode_cursor;
use cesauth_core::admin::types::{AdminAuditEntry, AdminPrincipal, AuditQuery};
use cesauth_core::i18n::{lookup, Locale, MessageKey as MK};
use cesauth_core::routes::admin as routes;

use super::frame::{admin_frame, Tab};

/// Default page size for the audit viewer. Operators can narrow further
/// via the filter form; widening past this needs a config change.
const DEFAULT_LIMIT: u32 = 100;

/// Render the audit log viewer.
///
/// `entries` is the result of `search_audit(...)` already paged — this
/// function does not slice. If `entries.len() == limit`, the renderer
/// emits an `Older →` cursor link; if `q.cursor.is_some()`, it emits a
/// `← Newer` link too.
pub fn audit_page(principal: &AdminPrincipal, q: &AuditQuery, entries: &[AdminAuditEntry]) -> String {
    // ADR-013: admin console is JA-only. The locale is fixed here so a
    // user's Accept-Language header can't shift admin pages to EN.
    let l = Locale::Ja;

    let body = format!(
        "{nav}\n{form}\n{export}\n{schema_note}\n{table}\n{pager}",
        nav         = render_nav(),
        form        = render_filter_form(q, l),
        export      = render_export_form(q),
        schema_note = render_schema_note(l),
        table       = render_results(entries, l),
        pager       = render_pager(q, entries, l),
    );

    admin_frame(
        lookup(MK::AuditViewerPageTitle, l),
        principal.role,
        principal.name.as_deref(),
        Tab::Audit,
        &ScopeBadge::System,
        &body,
    )
}

fn render_nav() -> String {
    // Chain verification link is a sibling read-only surface (RFC 080
    // background; ADR-010). Operators jump between the two.
    format!(
        r##"<p><a href="{chain_url}">Chain verification status →</a></p>"##,
        chain_url = routes::AUDIT_CHAIN,
    )
}

fn render_filter_form(q: &AuditQuery, l: Locale) -> String {
    // Sticky inputs: re-render fills the form with the current query
    // values so the operator can incrementally narrow.
    let actor_val = escape(q.subject_contains.as_deref().unwrap_or(""));
    let event_val = escape(q.event_exact.as_deref().unwrap_or(""));
    let from_val  = q.since.map(unix_to_rfc3339_z).unwrap_or_default();
    let to_val    = q.until.map(unix_to_rfc3339_z).unwrap_or_default();

    format!(
        r##"<section aria-label="{section}">
  <h2>{section}</h2>
  <form method="get" action="{audit_url}">
    <table>
      <tr>
        <th scope="row"><label for="actor">{actor_label}</label></th>
        <td><input id="actor" name="actor" type="text" value="{actor_val}" placeholder="user-id" style="width:100%"></td>
      </tr>
      <tr>
        <th scope="row"><label for="event">{event_label}</label></th>
        <td>
          <input id="event" name="event" type="text" list="audit-event-kinds" value="{event_val}" placeholder="{any}" style="width:100%">
          <datalist id="audit-event-kinds">
            <option value="auth_success"></option>
            <option value="auth_failed"></option>
            <option value="session_revoked"></option>
            <option value="token_introspected"></option>
            <option value="audit_exported"></option>
            <option value="admin_console_viewed"></option>
          </datalist>
        </td>
      </tr>
      <tr>
        <th scope="row">{period_label}</th>
        <td>
          <label for="from" class="visually-hidden">{from_label}</label>
          <input id="from" name="from" type="text" value="{from_val}" placeholder="1970-01-01T00:00:00Z" style="width:14em">
          —
          <label for="to" class="visually-hidden">{to_label}</label>
          <input id="to" name="to" type="text" value="{to_val}" placeholder="1970-01-01T00:00:00Z" style="width:14em">
        </td>
      </tr>
      <tr>
        <th scope="row"></th>
        <td><button type="submit">{submit}</button></td>
      </tr>
    </table>
  </form>
</section>"##,
        section      = lookup(MK::AuditViewerSectionTitle, l),
        audit_url    = routes::AUDIT,
        actor_label  = lookup(MK::AuditViewerActorLabel,  l),
        actor_val    = actor_val,
        event_label  = lookup(MK::AuditViewerEventLabel,  l),
        any          = lookup(MK::AuditViewerEventAny,    l),
        event_val    = event_val,
        period_label = lookup(MK::AuditViewerPeriodLabel, l),
        from_label   = lookup(MK::AuditViewerFromLabel,   l),
        from_val     = escape(&from_val),
        to_label     = lookup(MK::AuditViewerToLabel,     l),
        to_val       = escape(&to_val),
        submit       = lookup(MK::AuditViewerSubmitButton, l),
    )
}

fn render_export_form(q: &AuditQuery) -> String {
    // RFC 080 export inherits the same filter state. We POST the
    // currently-applied filter back to /admin/console/audit/export so
    // the operator gets the same set of rows as a CSV/JSONL stream.
    //
    // CSRF: read-only on this surface (the GET viewer needs no token);
    // the export POST handler validates separately.
    let actor = escape(q.subject_contains.as_deref().unwrap_or(""));
    let event = escape(q.event_exact.as_deref().unwrap_or(""));
    let since = q.since.map(|t| t.to_string()).unwrap_or_default();
    let until = q.until.map(|t| t.to_string()).unwrap_or_default();

    format!(
        r##"<section aria-label="export">
  <form method="post" action="{export_url}" style="margin-top:8px">
    <input type="hidden" name="subject" value="{actor}">
    <input type="hidden" name="event"   value="{event}">
    <input type="hidden" name="since"   value="{since}">
    <input type="hidden" name="until"   value="{until}">
    <button type="submit" name="format" value="csv"   class="secondary" style="margin-right:4px">{export_csv}</button>
    <button type="submit" name="format" value="jsonl" class="secondary">{export_jsonl}</button>
  </form>
</section>"##,
        export_url   = routes::AUDIT_EXPORT,
        actor        = actor,
        event        = event,
        since        = since,
        until        = until,
        // Format buttons keep their identifiers in English by design —
        // CSV and JSONL are file-format names, not natural-language UI.
        export_csv   = "Export CSV",
        export_jsonl = "Export JSONL",
    )
}

fn render_schema_note(l: Locale) -> String {
    format!(
        r#"<p class="note">{}</p>"#,
        lookup(MK::AuditViewerNoteSchemaTenant, l),
    )
}

fn render_results(entries: &[AdminAuditEntry], l: Locale) -> String {
    if entries.is_empty() {
        return format!(
            r#"<section aria-label="Results"><div class="empty">{}</div></section>"#,
            lookup(MK::AuditViewerEmptyState, l),
        );
    }
    let rows: String = entries.iter().map(|e| format!(
        r##"<tr>
  <td class="num muted">{ts}</td>
  <td class="muted">{actor}</td>
  <td><code>{kind}</code></td>
  <td class="muted">{reason}</td>
  <td class="muted">{seq}</td>
</tr>"##,
        ts     = e.ts,
        actor  = escape(e.subject.as_deref().unwrap_or("—")),
        kind   = escape(&e.kind),
        reason = escape(e.reason.as_deref().unwrap_or("")),
        seq    = escape(&e.key),
    )).collect::<Vec<_>>().join("\n");
    format!(
        r##"<section aria-label="Results">
  <table><thead>
    <tr>
      <th scope="col" class="num">{col_time}</th>
      <th scope="col">{col_actor}</th>
      <th scope="col">{col_event}</th>
      <th scope="col">{col_reason}</th>
      <th scope="col">{col_seq}</th>
    </tr>
  </thead><tbody>
{rows}
  </tbody></table>
</section>"##,
        col_time   = lookup(MK::AuditViewerColTime,   l),
        col_actor  = lookup(MK::AuditViewerColActor,  l),
        col_event  = lookup(MK::AuditViewerColEvent,  l),
        col_reason = lookup(MK::AuditViewerColReason, l),
        col_seq    = lookup(MK::AuditViewerColSeq,    l),
        rows = rows,
    )
}

fn render_pager(q: &AuditQuery, entries: &[AdminAuditEntry], l: Locale) -> String {
    // `← Newer` is omitted on the first page (no cursor in current query).
    // `Older →` is omitted when the result set is smaller than the page
    // size — that's the last page by construction.
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT) as usize;
    let mut links: Vec<String> = Vec::new();

    if q.cursor.is_some() {
        // Newer page = drop the cursor entirely (go back to head). This
        // is a coarse "first page" jump rather than true bidirectional
        // pagination; richer prev-cursor tracking is left to a future
        // refinement.
        let url = build_filter_url(q, /*include_cursor=*/ false);
        links.push(format!(
            r#"<a href="{url}">{label}</a>"#,
            url   = escape(&url),
            label = lookup(MK::AuditViewerNewerLink, l),
        ));
    }

    if entries.len() >= limit {
        if let Some(last) = entries.last() {
            // Extract the last entry's seq from its `key` field
            // (formatted as `seq=N` by the AdminAuditEntry projection).
            if let Some(seq) = parse_seq_from_key(&last.key) {
                let next = encode_cursor(seq);
                let url  = build_filter_url_with_cursor(q, &next);
                links.push(format!(
                    r#"<a href="{url}">{label}</a>"#,
                    url   = escape(&url),
                    label = lookup(MK::AuditViewerOlderLink, l),
                ));
            }
        }
    }

    if links.is_empty() {
        return String::new();
    }
    format!(r#"<nav aria-label="pagination"><p>{}</p></nav>"#, links.join(" · "))
}

// -------------------------------------------------------------------------
// URL helpers
// -------------------------------------------------------------------------

/// Build a filter URL preserving the current filter (actor/event/from/to)
/// but optionally dropping the cursor (newer-page link).
fn build_filter_url(q: &AuditQuery, include_cursor: bool) -> String {
    let mut parts: Vec<(&str, String)> = Vec::new();
    if let Some(s) = &q.subject_contains { parts.push(("actor", s.clone())); }
    if let Some(s) = &q.event_exact      { parts.push(("event", s.clone())); }
    if let Some(t) = q.since             { parts.push(("from",  unix_to_rfc3339_z(t))); }
    if let Some(t) = q.until             { parts.push(("to",    unix_to_rfc3339_z(t))); }
    if include_cursor {
        if let Some(c) = &q.cursor       { parts.push(("cursor", c.clone())); }
    }
    encode_query_string(routes::AUDIT, &parts)
}

fn build_filter_url_with_cursor(q: &AuditQuery, cursor: &str) -> String {
    let mut parts: Vec<(&str, String)> = Vec::new();
    if let Some(s) = &q.subject_contains { parts.push(("actor", s.clone())); }
    if let Some(s) = &q.event_exact      { parts.push(("event", s.clone())); }
    if let Some(t) = q.since             { parts.push(("from",  unix_to_rfc3339_z(t))); }
    if let Some(t) = q.until             { parts.push(("to",    unix_to_rfc3339_z(t))); }
    parts.push(("cursor", cursor.to_owned()));
    encode_query_string(routes::AUDIT, &parts)
}

/// Encode a small list of query parameters into a URL string. RFC 3986
/// percent-encoding for the value side, restricted to bytes we actually
/// produce here (alphanumerics, `-_.~:+`). `T` and `Z` are already in the
/// `A`–`Z` range; the `+` is kept for RFC 3339 offset sign. Anything
/// else is hex-encoded.
fn encode_query_string(base: &str, parts: &[(&str, String)]) -> String {
    if parts.is_empty() {
        return base.to_owned();
    }
    let mut out = String::with_capacity(base.len() + 32 * parts.len());
    out.push_str(base);
    out.push('?');
    for (i, (k, v)) in parts.iter().enumerate() {
        if i > 0 { out.push('&'); }
        out.push_str(k);
        out.push('=');
        for b in v.as_bytes() {
            match *b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' |
                b'-' | b'_' | b'.' | b'~' | b':' | b'+' => {
                    out.push(*b as char);
                }
                _ => {
                    out.push('%');
                    out.push_str(&format!("{:02X}", b));
                }
            }
        }
    }
    out
}

/// Unix seconds → minimal RFC 3339 UTC representation
/// (`YYYY-MM-DDTHH:MM:SSZ`). Used for round-tripping the form-input
/// stickiness; the inverse parser lives in `audit_pagination`.
fn unix_to_rfc3339_z(mut ts: i64) -> String {
    if ts < 0 { ts = 0; }  // form values pre-1970 aren't supported
    let secs = (ts % 60) as u32;
    let total_min = ts / 60;
    let mins = (total_min % 60) as u32;
    let total_h = total_min / 60;
    let hour = (total_h % 24) as u32;
    let mut days = total_h / 24;

    // Walk forward from 1970-01-01 day-by-day. The viewer's worst case
    // is a few thousand days — cheap and predictable.
    let mut year: i32 = 1970;
    loop {
        let in_year = if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 { 366 } else { 365 };
        if days < in_year { break; }
        days -= in_year;
        year += 1;
    }
    let dpm = |y: i32, m: u32| -> i64 {
        match m {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11              => 30,
            2 => if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 29 } else { 28 },
            _ => 0,
        }
    };
    let mut month: u32 = 1;
    while month <= 12 {
        let d = dpm(year, month);
        if days < d { break; }
        days -= d;
        month += 1;
    }
    let day = (days + 1) as u32;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{mins:02}:{secs:02}Z")
}

/// Extract a `seq=NNN` integer from an `AdminAuditEntry::key` field.
/// Returns `None` if the key isn't in that format (legacy rows or
/// unexpected projections), which keeps the pager safe — the link is
/// just omitted.
fn parse_seq_from_key(key: &str) -> Option<i64> {
    key.strip_prefix("seq=").and_then(|s| s.parse::<i64>().ok())
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;
    use cesauth_core::admin::service::audit_pagination::{parse_rfc3339_to_unix, encode_cursor};

    fn principal() -> AdminPrincipal {
        AdminPrincipal {
            id: "admin-1".to_owned(),
            role: Role::Super,
            name: Some("op".to_owned()),
            user_id: None,
        }
    }

    fn entry(ts: i64, kind: &str, actor: Option<&str>, seq: i64) -> AdminAuditEntry {
        AdminAuditEntry {
            ts,
            id:      format!("ev-{ts}"),
            kind:    kind.to_owned(),
            subject: actor.map(|s| s.to_owned()),
            client:  None,
            reason:  None,
            key:     format!("seq={seq}"),
        }
    }

    // --- JA labels + scope badge ---------------------------------------

    #[test]
    fn page_renders_in_ja() {
        let html = audit_page(&principal(), &AuditQuery::default(), &[]);
        assert!(html.contains("監査ログ"), "JA page title must appear");
        assert!(html.contains("絞り込み"), "JA section title");
        assert!(html.contains("イベント種別"), "event label");
        assert!(html.contains("期間 (UTC)"), "period label");
    }

    // --- Empty state ---------------------------------------------------

    #[test]
    fn empty_results_shows_empty_state_message() {
        let html = audit_page(&principal(), &AuditQuery::default(), &[]);
        assert!(html.contains("条件に合致するイベントはありません"),
            "JA empty state");
    }

    // --- Filter form stickiness ----------------------------------------

    #[test]
    fn filter_form_round_trips_actor_event_period() {
        let q = AuditQuery {
            subject_contains: Some("alice".to_owned()),
            event_exact:      Some("auth_failed".to_owned()),
            since:            Some(1_735_689_600),  // 2025-01-01T00:00:00Z
            until:            Some(1_735_776_000),  // 2025-01-02T00:00:00Z
            ..Default::default()
        };
        let html = audit_page(&principal(), &q, &[]);
        assert!(html.contains(r#"value="alice""#), "actor sticky");
        assert!(html.contains(r#"value="auth_failed""#), "event sticky");
        assert!(html.contains("2025-01-01T00:00:00Z"), "from sticky");
        assert!(html.contains("2025-01-02T00:00:00Z"), "to sticky");
    }

    // --- unix_to_rfc3339_z is the inverse of parse_rfc3339_to_unix -----

    #[test]
    fn unix_to_rfc3339_z_round_trips_via_parser() {
        for ts in [0_i64, 60, 3600, 86_400, 1_735_689_600, 2_000_000_000] {
            let s = unix_to_rfc3339_z(ts);
            let back = parse_rfc3339_to_unix(&s)
                .unwrap_or_else(|| panic!("re-parse failed for ts={ts} -> {s}"));
            assert_eq!(back, ts, "round-trip ts={ts}");
        }
    }

    #[test]
    fn unix_to_rfc3339_z_handles_negative_as_epoch() {
        // Negative inputs (defensive) clamp to epoch rather than panicking.
        assert_eq!(unix_to_rfc3339_z(-1), "1970-01-01T00:00:00Z");
    }

    // --- Export form inherits filter -----------------------------------

    #[test]
    fn export_form_inherits_actor_event_period() {
        let q = AuditQuery {
            subject_contains: Some("alice".to_owned()),
            event_exact:      Some("auth_failed".to_owned()),
            since:            Some(100),
            until:            Some(200),
            ..Default::default()
        };
        let html = audit_page(&principal(), &q, &[]);
        assert!(html.contains(r#"name="subject" value="alice""#),
            "export form must carry actor (subject) filter");
        assert!(html.contains(r#"name="event"   value="auth_failed""#)
             || html.contains(r#"name="event" value="auth_failed""#),
            "export form must carry event filter");
        assert!(html.contains(r#"name="since"   value="100""#)
             || html.contains(r#"name="since" value="100""#),
            "export form must carry since filter");
        assert!(html.contains(r#"name="until"   value="200""#)
             || html.contains(r#"name="until" value="200""#),
            "export form must carry until filter");
    }

    // --- Pagination links ----------------------------------------------

    #[test]
    fn no_pager_when_result_below_page_size() {
        let entries = vec![entry(10, "k", None, 1), entry(20, "k", None, 2)];
        let q = AuditQuery { limit: Some(100), ..Default::default() };
        let html = audit_page(&principal(), &q, &entries);
        assert!(!html.contains("より古い"), "no Older link on partial page");
        assert!(!html.contains("より新しい"), "no Newer link on head page");
    }

    #[test]
    fn older_link_appears_when_page_is_full() {
        let entries: Vec<_> = (0..5).map(|i| entry(100 - i, "k", None, 100 - i)).collect();
        let q = AuditQuery { limit: Some(5), ..Default::default() };
        let html = audit_page(&principal(), &q, &entries);
        assert!(html.contains("より古い"), "Older link must appear when page is full");
        // Cursor in the Older link should be the encoded seq of the
        // last (oldest) entry in the page.
        let expected = encode_cursor(96);  // last entry seq=100-4
        assert!(html.contains(&expected),
            "Older link must carry cursor for last entry; expected {expected}");
    }

    #[test]
    fn newer_link_appears_when_cursor_in_query() {
        let entries = vec![entry(10, "k", None, 1)];
        let q = AuditQuery {
            cursor: Some(encode_cursor(20)),
            limit:  Some(100),
            ..Default::default()
        };
        let html = audit_page(&principal(), &q, &entries);
        assert!(html.contains("より新しい"),
            "Newer link must appear when query has a cursor");
    }

    // --- Schema note (RFC 109 scope amendment) -------------------------

    #[test]
    fn schema_note_explains_missing_tenant_filter() {
        let html = audit_page(&principal(), &AuditQuery::default(), &[]);
        assert!(html.contains("tenant_id"),
            "page must note that tenant_id filter is not yet available");
    }

    // --- parse_seq_from_key --------------------------------------------

    #[test]
    fn parse_seq_from_key_handles_well_formed_input() {
        assert_eq!(parse_seq_from_key("seq=42"), Some(42));
        assert_eq!(parse_seq_from_key("seq=1"),  Some(1));
    }

    #[test]
    fn parse_seq_from_key_handles_malformed_input() {
        assert_eq!(parse_seq_from_key(""),         None);
        assert_eq!(parse_seq_from_key("seq="),     None);
        assert_eq!(parse_seq_from_key("seq=abc"),  None);
        assert_eq!(parse_seq_from_key("foo=42"),   None);
    }
}
