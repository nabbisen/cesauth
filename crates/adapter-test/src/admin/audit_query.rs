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

use std::sync::Mutex;

use cesauth_core::admin::ports::AuditQuerySource;
use cesauth_core::admin::service::audit_pagination::decode_cursor;
use cesauth_core::admin::types::{AdminAuditEntry, AuditQuery};
use cesauth_core::ports::{PortError, PortResult};

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
            .filter(|e| match &q.subject_contains {
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
            client:  None,
            reason:  None,
            key:     format!("seq={ts}"),
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
}
