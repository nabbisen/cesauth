//! In-memory `AuditQuerySource` for tests.
//!
//! v0.71.0 (RFC 109) extended the filter set with `event_exact`, `since`,
//! `until`, and `cursor`. The cursor is opaque from the source's
//! perspective — the service layer (`audit_pagination::decode_cursor`)
//! converts it to a `seq` value, and the in-memory source pages by
//! comparing the entry's `ts` field as a substitute for `seq` (the
//! adapter-test rows don't carry seq separately; they're ordered by ts).
//!
//! This matches the cloudflare D1 adapter's keyset semantics for the
//! purposes of testing the service-layer pagination flow.
//!
//! **RFC 188 Phase 2, D6.** [`InMemoryAuditQuerySource`] above stores
//! already-mapped [`AdminAuditEntry`] rows (tests seed the display
//! shape directly) and has no row-vs-payload distinction to get wrong.
//! The actual double of `CloudflareAuditQuerySource`'s mapper — the one
//! D6 requires to agree with the real adapter — is [`map_row`] below:
//! the identical seven-column comparison against
//! [`cesauth_core::audit::payload::AuditPayloadMirror`], applied to a
//! [`cesauth_core::ports::audit::AuditEventRow`] the same way the
//! Cloudflare adapter's `payload_and_divergence` is. Kept as a
//! duplicate, not a shared function, per this project's established
//! cross-crate pattern (`AuditPayloadMirror`'s own module doc) — the
//! agreement is asserted by tests, not structurally enforced.

use std::sync::Mutex;

use cesauth_core::admin::ports::AuditQuerySource;
use cesauth_core::admin::service::audit_pagination::decode_cursor;
use cesauth_core::admin::types::{AdminAuditEntry, AuditQuery};
use cesauth_core::audit::payload::AuditPayloadMirror;
use cesauth_core::ports::audit::AuditEventRow;
use cesauth_core::ports::{PortError, PortResult};

/// RFC 188 Phase 2, D6 — the double's own copy of
/// `CloudflareAuditQuerySource`'s mapper (T2). Builds the
/// [`AdminAuditEntry`] a real search would produce for one row: the
/// four display fields come from the payload mirror (D1), never the
/// row's columns, and `diverges_from_payload` is set by a full
/// seven-column comparison (D3) — including the three fields this
/// screen never displays (`ip`, `user_agent`, `request_id`). An
/// unparseable payload does not fall back to the columns (D2): it
/// renders the four fields as `None` and is always flagged.
pub fn map_row(row: &AuditEventRow) -> AdminAuditEntry {
    let (mirror, diverges) = match AuditPayloadMirror::parse(&row.payload) {
        Ok(mirror) => {
            let diverges = row.subject    != mirror.subject
                || row.actor      != mirror.actor
                || row.client_id  != mirror.client_id
                || row.ip         != mirror.ip
                || row.user_agent != mirror.user_agent
                || row.reason     != mirror.reason
                || row.request_id != mirror.request_id;
            (mirror, diverges)
        }
        Err(_) => (AuditPayloadMirror::default(), true),
    };
    AdminAuditEntry {
        ts:      row.ts,
        id:      row.id.clone(),
        kind:    row.kind.clone(),
        subject: mirror.subject,
        actor:   mirror.actor,
        client:  mirror.client_id,
        reason:  mirror.reason,
        key:     format!("seq={}", row.seq),
        diverges_from_payload: diverges,
    }
}

#[derive(Debug, Default)]
pub struct InMemoryAuditQuerySource {
    inner: Mutex<Vec<AdminAuditEntry>>,
}

impl InMemoryAuditQuerySource {
    pub fn seed(&self, entries: Vec<AdminAuditEntry>) {
        *self.inner.lock().unwrap() = entries;
    }

    pub fn push(&self, entry: AdminAuditEntry) {
        self.inner.lock().unwrap().push(entry);
    }
}

impl AuditQuerySource for InMemoryAuditQuerySource {
    async fn search(&self, q: &AuditQuery) -> PortResult<Vec<AdminAuditEntry>> {
        let v = self.inner.lock().map_err(|_| PortError::Unavailable)?;

        // Cursor decode: the in-memory source treats the cursor as a `ts`
        // upper bound (the source has no seq column; in production the D1
        // adapter uses seq directly). When set, only entries strictly older
        // than the cursor's ts are returned.
        let cursor_ts: Option<i64> = q.cursor
            .as_deref()
            .and_then(decode_cursor);

        let mut out: Vec<AdminAuditEntry> = v
            .iter()
            // Existing substring filters preserved for backward compat.
            .filter(|e| match &q.kind_contains {
                Some(s) => e.kind.contains(s.as_str()),
                None    => true,
            })
            .filter(|e| match &q.subject_exact {
                Some(s) => e.subject.as_deref().map(|x| x.contains(s.as_str())).unwrap_or(false),
                None    => true,
            })
            // RFC 109 new filters --------------------------------------
            .filter(|e| match &q.event_exact {
                Some(s) => e.kind == *s,
                None    => true,
            })
            .filter(|e| match q.since {
                Some(t) => e.ts >= t,
                None    => true,
            })
            .filter(|e| match q.until {
                Some(t) => e.ts <= t,
                None    => true,
            })
            .filter(|e| match cursor_ts {
                Some(t) => e.ts < t,
                None    => true,
            })
            .cloned()
            .collect();
        // Newest-first for deterministic test output (matches the D1
        // adapter's `ORDER BY seq DESC` semantics under the substitute
        // ordering used here).
        out.sort_by(|a, b| b.ts.cmp(&a.ts));
        if let Some(lim) = q.limit {
            out.truncate(lim as usize);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::service::audit_pagination::encode_cursor;

    fn entry(ts: i64, kind: &str, subj: Option<&str>) -> AdminAuditEntry {
        AdminAuditEntry {
            ts,
            id:      format!("ev-{ts}"),
            kind:    kind.to_owned(),
            subject: subj.map(|s| s.to_owned()),
            actor:   None,
            client:  None,
            reason:  None,
            key:     format!("seq={ts}"),
            diverges_from_payload: false,
        }
    }

    #[tokio::test]
    async fn event_exact_filters_to_exact_kind() {
        let src = InMemoryAuditQuerySource::default();
        src.seed(vec![
            entry(1, "auth_failed",  Some("u1")),
            entry(2, "auth_success", Some("u1")),
            entry(3, "auth_failed",  Some("u2")),
        ]);
        let q = AuditQuery {
            event_exact: Some("auth_failed".to_owned()),
            ..Default::default()
        };
        let out = src.search(&q).await.unwrap();
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|e| e.kind == "auth_failed"));
    }

    #[tokio::test]
    async fn since_bounds_results_inclusive_lower() {
        let src = InMemoryAuditQuerySource::default();
        src.seed(vec![entry(10, "k", None), entry(20, "k", None), entry(30, "k", None)]);
        let q = AuditQuery { since: Some(20), ..Default::default() };
        let out = src.search(&q).await.unwrap();
        assert_eq!(out.iter().map(|e| e.ts).collect::<Vec<_>>(), vec![30, 20]);
    }

    #[tokio::test]
    async fn until_bounds_results_inclusive_upper() {
        let src = InMemoryAuditQuerySource::default();
        src.seed(vec![entry(10, "k", None), entry(20, "k", None), entry(30, "k", None)]);
        let q = AuditQuery { until: Some(20), ..Default::default() };
        let out = src.search(&q).await.unwrap();
        assert_eq!(out.iter().map(|e| e.ts).collect::<Vec<_>>(), vec![20, 10]);
    }

    #[tokio::test]
    async fn date_range_intersects_since_and_until() {
        let src = InMemoryAuditQuerySource::default();
        src.seed(vec![
            entry(5,  "k", None),
            entry(15, "k", None),
            entry(25, "k", None),
            entry(35, "k", None),
        ]);
        let q = AuditQuery {
            since: Some(10),
            until: Some(30),
            ..Default::default()
        };
        let out = src.search(&q).await.unwrap();
        assert_eq!(out.iter().map(|e| e.ts).collect::<Vec<_>>(), vec![25, 15]);
    }

    #[tokio::test]
    async fn cursor_returns_strictly_older_entries() {
        let src = InMemoryAuditQuerySource::default();
        src.seed(vec![entry(10, "k", None), entry(20, "k", None), entry(30, "k", None)]);
        // Cursor at ts=20 → should return only ts=10 (strictly older).
        let q = AuditQuery {
            cursor: Some(encode_cursor(20)),
            ..Default::default()
        };
        let out = src.search(&q).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ts, 10);
    }

    #[tokio::test]
    async fn cursor_combines_with_event_filter() {
        let src = InMemoryAuditQuerySource::default();
        src.seed(vec![
            entry(10, "a", None),
            entry(20, "b", None),
            entry(30, "a", None),
            entry(40, "a", None),
        ]);
        let q = AuditQuery {
            event_exact: Some("a".to_owned()),
            cursor:      Some(encode_cursor(40)),
            limit:       Some(10),
            ..Default::default()
        };
        let out = src.search(&q).await.unwrap();
        // ts=40 excluded by cursor (strict), ts=20 excluded by event_exact,
        // ts=10 and ts=30 remain.
        assert_eq!(out.iter().map(|e| e.ts).collect::<Vec<_>>(), vec![30, 10]);
    }

    #[tokio::test]
    async fn limit_truncates_after_filters() {
        let src = InMemoryAuditQuerySource::default();
        src.seed((0..10).map(|i| entry(i, "k", None)).collect());
        let q = AuditQuery { limit: Some(3), ..Default::default() };
        let out = src.search(&q).await.unwrap();
        assert_eq!(out.len(), 3);
        // Newest-first → ts=9,8,7.
        assert_eq!(out.iter().map(|e| e.ts).collect::<Vec<_>>(), vec![9, 8, 7]);
    }

    #[tokio::test]
    async fn existing_kind_contains_filter_still_works() {
        let src = InMemoryAuditQuerySource::default();
        src.seed(vec![
            entry(1, "auth_failed",  None),
            entry(2, "auth_success", None),
            entry(3, "session_ended", None),
        ]);
        let q = AuditQuery {
            kind_contains: Some("auth".to_owned()),
            ..Default::default()
        };
        let out = src.search(&q).await.unwrap();
        assert_eq!(out.len(), 2);
    }

    // ── RFC 188 Phase 2, D6/test(6) — `map_row` against clean/diverged
    // rows, the double's half of required tests (1)-(4) ────────────────

    fn clean_row(seq: i64) -> AuditEventRow {
        AuditEventRow {
            seq,
            id:            format!("ev-{seq}"),
            ts:             1_700_000_000 + seq,
            kind:          "LoginSuccess".to_owned(),
            subject:       Some("user-1".to_owned()),
            actor:         Some("admin-1".to_owned()),
            client_id:     Some("client-9".to_owned()),
            ip:            Some("203.0.113.5".to_owned()),
            user_agent:    Some("curl/8".to_owned()),
            reason:        Some("pkce_mismatch".to_owned()),
            payload: r#"{"subject":"user-1","actor":"admin-1","client_id":"client-9","ip":"203.0.113.5","user_agent":"curl/8","reason":"pkce_mismatch","request_id":"cf-ray-1"}"#.to_owned(),
            payload_hash:  "deadbeef".to_owned(),
            previous_hash: "prev".to_owned(),
            chain_hash:    "chain".to_owned(),
            created_at:    1_700_000_000 + seq,
            request_id:    Some("cf-ray-1".to_owned()),
        }
    }

    #[test]
    fn map_row_clean_row_is_unmarked_and_renders_the_payload() {
        let out = map_row(&clean_row(1));
        assert!(!out.diverges_from_payload);
        assert_eq!(out.subject, Some("user-1".to_owned()));
        assert_eq!(out.actor,   Some("admin-1".to_owned()));
        assert_eq!(out.client,  Some("client-9".to_owned()));
        assert_eq!(out.reason,  Some("pkce_mismatch".to_owned()));
    }

    #[test]
    fn map_row_diverged_display_field_shows_the_payload_value_not_the_column() {
        // subject, actor, client, reason: one case each — the column
        // disagrees with the payload, and the mapped entry must carry
        // the payload's value, never the column's.
        let cases: [(&dyn Fn(&mut AuditEventRow), &str); 4] = [
            (&|r: &mut AuditEventRow| r.subject = Some("COLUMN-subject".to_owned()), "user-1"),
            (&|r: &mut AuditEventRow| r.actor   = Some("COLUMN-actor".to_owned()),   "admin-1"),
            (&|r: &mut AuditEventRow| r.client_id = Some("COLUMN-client".to_owned()), "client-9"),
            (&|r: &mut AuditEventRow| r.reason  = Some("COLUMN-reason".to_owned()),  "pkce_mismatch"),
        ];
        for (mutate_column, payload_value) in cases {
            let mut row = clean_row(1);
            mutate_column(&mut row);
            let out = map_row(&row);
            assert!(out.diverges_from_payload);
            let shown = [&out.subject, &out.actor, &out.client, &out.reason]
                .into_iter().flatten().any(|v| v == payload_value);
            assert!(shown, "the mapped entry must show the payload's value {payload_value}");
            let shown_values: Vec<&str> = [&out.subject, &out.actor, &out.client, &out.reason]
                .into_iter().flatten().map(String::as_str).collect();
            assert!(!shown_values.iter().any(|v| v.starts_with("COLUMN-")),
                "the column's value must not appear anywhere in the display fields, got {shown_values:?}");
        }
    }

    #[test]
    fn map_row_non_displayed_column_divergence_still_sets_the_flag() {
        for mutate in [
            (&|r: &mut AuditEventRow| r.ip = Some("9.9.9.9".to_owned())) as &dyn Fn(&mut AuditEventRow),
            &|r: &mut AuditEventRow| r.user_agent = Some("other-agent".to_owned()),
            &|r: &mut AuditEventRow| r.request_id = Some("cf-ray-other".to_owned()),
        ] {
            let mut row = clean_row(1);
            mutate(&mut row);
            let out = map_row(&row);
            assert!(out.diverges_from_payload,
                "a divergence in a non-displayed column must still flag the row");
            // Nothing on screen changed.
            assert_eq!(out.subject, Some("user-1".to_owned()));
            assert_eq!(out.actor,   Some("admin-1".to_owned()));
            assert_eq!(out.client,  Some("client-9".to_owned()));
            assert_eq!(out.reason,  Some("pkce_mismatch".to_owned()));
        }
    }

    #[test]
    fn map_row_unparseable_payload_marks_all_four_fields_absent_and_flags() {
        let mut row = clean_row(1);
        row.payload = "not json".to_owned();
        let out = map_row(&row);
        assert!(out.diverges_from_payload);
        assert_eq!(out.subject, None);
        assert_eq!(out.actor,   None);
        assert_eq!(out.client,  None);
        assert_eq!(out.reason,  None);
    }

    // ── RFC 188 Phase 2, required test (7) — the filter residual (D4) ──
    //
    // A row whose `subject` column was changed is NOT returned by a
    // search for the payload's subject, even though `map_row` would
    // display (and flag) that very row with the payload's subject.
    // This is the half of the residual Phase 2 deliberately does not
    // close: the mark tells an operator reading the row that it
    // diverges; it cannot make the row appear for a filter that never
    // reaches it.
    #[tokio::test]
    async fn filter_by_payload_subject_misses_a_row_whose_column_was_changed() {
        use cesauth_core::ports::audit::{AuditEventRepository, AuditSearch, NewAuditEvent};
        use crate::audit::InMemoryAuditEventRepository;

        let repo = InMemoryAuditEventRepository::new();
        repo.append(&NewAuditEvent {
            id:           "ev-1",
            ts:           1_700_000_000,
            kind:         "LoginSuccess",
            subject:      Some("payload-subject"),
            actor:        None,
            client_id:    None,
            ip:           None,
            user_agent:   None,
            reason:       None,
            payload:      r#"{"subject":"payload-subject"}"#,
            payload_hash: "irrelevant-to-this-test",
            created_at:   1_700_000_000,
            request_id:   None,
        }).await.unwrap();
        // Simulate the column-only tamper: the payload (the sealed
        // record) still says "payload-subject"; the indexed column an
        // SQL filter matches on now says something else.
        repo.tamper_set_column(1, "subject", Some("COLUMN-subject".to_owned()));

        // The viewer's half: map_row shows the payload's subject and
        // flags the row (D1/D3) — the row the operator reads is correct.
        let row = repo.rows().into_iter().find(|r| r.seq == 1).unwrap();
        let mapped = map_row(&row);
        assert_eq!(mapped.subject, Some("payload-subject".to_owned()));
        assert!(mapped.diverges_from_payload);

        // The filter's half: a search for the payload's own subject
        // value finds nothing, because the SQL-equivalent filter here
        // matches the column, not the payload (D4's residual).
        let found = repo.search(&AuditSearch {
            subject: Some("payload-subject".to_owned()),
            ..Default::default()
        }).await.unwrap();
        assert!(found.is_empty(),
            "a filter on the payload's subject must not find a row whose column diverges — \
             that is exactly the residual D4 accepts, not a regression");

        // And a search for the (wrong) column value DOES find it —
        // confirming the miss above is the filter working as designed,
        // not an unrelated bug.
        let found_by_column = repo.search(&AuditSearch {
            subject: Some("COLUMN-subject".to_owned()),
            ..Default::default()
        }).await.unwrap();
        assert_eq!(found_by_column.len(), 1);
    }
}
