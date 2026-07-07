//! Safety controls report assembly (RFC 110b/c/d/e, v0.74.0).
//!
//! Gathers the indicators for the PDF v0.50.1 page 9 "Safety controls"
//! panel. The worker handler calls these helpers to populate a
//! `SafetyControlsReport`, then hands it to `ui::admin::safety_page`.
//!
//! ## Composition (each sub-RFC supplies one field)
//!
//! - **RFC 110b** — `turnstile_configured` is computed by the worker
//!   from `env.var("TURNSTILE_SECRET_KEY").is_ok()`. The service layer
//!   has no role; this module documents the data-flow contract.
//! - **RFC 110c** — `refresh_reuse_count_24h` is computed here, by
//!   `count_refresh_reuse_since(repo, now_unix - 86400)`.
//! - **RFC 110d** — `totp_key_configured` is computed by the worker
//!   from `env.var("TOTP_SECRET_KEY").is_ok()`. Same shape as 110b.
//! - **RFC 110e** — `runbook_url` is read by the worker from
//!   `env.var("RUNBOOK_URL")` (optional config). The renderer omits
//!   the link when None.
//!
//! ## Why split this way
//!
//! Env-var reads are wasm32-only and cannot be unit-tested in the
//! current sandbox. Pulling them out of the service layer lets us
//! ship 110b/d/e as straight-pipe wiring with no host-side data
//! dependencies, while 110c (which needs `AuditEventRepository`) gets
//! a proper service function + adapter-test coverage.

use crate::admin::types::SafetyControlsReport;
use crate::ports::audit::{AuditEventRepository, AuditSearch};
use crate::ports::{PortError, PortResult};

/// On-wire `kind` string for the audit event emitted on detected
/// refresh-token reuse (RFC 9700 §4.14.2 telemetry).
///
/// The corresponding `EventKind` enum lives in
/// `crates/worker/src/audit.rs` (wasm32-only); from `core` we use the
/// stable string contract directly. Tested via
/// `count_refresh_reuse_ignores_other_event_kinds` and the worker's
/// own kind-string test in `audit.rs`.
const EVENT_KIND_REFRESH_TOKEN_REUSE_DETECTED: &str = "refresh_token_reuse_detected";

/// Count `RefreshTokenReuseDetected` audit events that occurred at or
/// after `since_unix`. RFC 110c implementation.
///
/// The audit log carries this event kind as a string
/// `"refresh_token_reuse_detected"` (see
/// [`EVENT_KIND_REFRESH_TOKEN_REUSE_DETECTED`]). We search with the
/// `kind` filter set; the `since` filter is `since_unix` directly.
///
/// Returned value is capped at the page limit (the underlying repository
/// returns at most `limit` rows). For the 24h-window summary, the
/// default limit suffices unless the deployment is under a sustained
/// attack — in that case "many" is the correct operator signal anyway.
pub async fn count_refresh_reuse_since<R>(
    repo:       &R,
    since_unix: i64,
) -> PortResult<u64>
where
    R: AuditEventRepository,
{
    let search = AuditSearch {
        kind:       Some(EVENT_KIND_REFRESH_TOKEN_REUSE_DETECTED.to_owned()),
        since:      Some(since_unix),
        // No upper bound: count everything from `since` to now.
        until:      None,
        subject:    None,
        // 1000 is a soft cap — if the deployment ever sees more in 24h
        // the operator already knows there's a problem; "1000+" is a
        // truthful signal.
        limit:      Some(1000),
        before_seq: None,
    };
    let rows = repo.search(&search).await?;
    u64::try_from(rows.len()).map_err(|_| PortError::Unavailable)
}

/// Assemble a [`SafetyControlsReport`] from worker-supplied indicators
/// plus the audit-event count. RFC 110b/c/d/e composition.
///
/// The worker is responsible for the env-var checks (110b/d/e — wasm32
/// shaped, untestable in this sandbox); this function combines them
/// with the audit-side count (110c — host-buildable, fully tested).
///
/// The RFC 110a slot (`rate_limit_status`) is wired as `None` — when
/// the rate-limit summary lands, this function gains a parameter.
pub async fn compute_safety_controls<R>(
    repo:                     &R,
    now_unix:                 i64,
    turnstile_configured:     bool,
    totp_key_configured:      bool,
    runbook_url:              Option<String>,
) -> PortResult<SafetyControlsReport>
where
    R: AuditEventRepository,
{
    let twenty_four_hours_ago = now_unix.saturating_sub(86_400);
    let refresh_reuse_count_24h = count_refresh_reuse_since(repo, twenty_four_hours_ago).await?;
    Ok(SafetyControlsReport {
        turnstile_configured,
        totp_key_configured,
        refresh_reuse_count_24h,
        runbook_url,
        // RFC 110a deferred — see SafetyControlsReport::rate_limit_status
        // field docs and the rfcs/proposed/110a-... entry.
        rate_limit_status: None,
    })
}

// Re-export RateLimitStatus to make the API surface symmetric — callers
// (when 110a lands) can `use cesauth_core::admin::service::safety_controls::RateLimitStatus`
// without separately reaching into `types`.
pub use crate::admin::types::RateLimitStatus as RateLimitStatusReexport;

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::types::RateLimitStatus;
    use crate::ports::audit::{AuditEventRow, NewAuditEvent};
    use std::sync::Mutex;

    /// In-test stub repository. Only `search()` matters for these tests;
    /// other methods panic on call.
    #[derive(Default)]
    struct StubRepo {
        rows: Mutex<Vec<AuditEventRow>>,
    }

    impl StubRepo {
        fn push(&self, ts: i64, kind: &str) {
            let row = AuditEventRow {
                seq:           self.rows.lock().unwrap().len() as i64 + 1,
                id:            format!("ev-{ts}"),
                ts,
                kind:          kind.to_owned(),
                subject:       None,
                client_id:     None,
                ip:            None,
                user_agent:    None,
                reason:        None,
                payload:       "{}".to_owned(),
                payload_hash:  String::new(),
                previous_hash: String::new(),
                chain_hash:    String::new(),
                created_at:    ts,
                request_id:    None,
            };
            self.rows.lock().unwrap().push(row);
        }
    }

    impl AuditEventRepository for StubRepo {
        async fn append(&self, _ev: &NewAuditEvent<'_>) -> PortResult<AuditEventRow> {
            unimplemented!("safety_controls tests do not exercise append")
        }
        async fn tail(&self) -> PortResult<Option<AuditEventRow>> {
            unimplemented!("safety_controls tests do not exercise tail")
        }
        async fn search(&self, q: &AuditSearch) -> PortResult<Vec<AuditEventRow>> {
            let v = self.rows.lock().unwrap();
            let kind = q.kind.as_deref();
            let since = q.since.unwrap_or(i64::MIN);
            let out: Vec<_> = v.iter()
                .filter(|r| kind.map_or(true, |k| r.kind == k))
                .filter(|r| r.ts >= since)
                .cloned()
                .collect();
            Ok(match q.limit {
                Some(n) => out.into_iter().take(n as usize).collect(),
                None    => out,
            })
        }
        async fn fetch_after_seq(&self, _from_seq: i64, _limit: u32) -> PortResult<Vec<AuditEventRow>> {
            unimplemented!("safety_controls tests do not exercise fetch_after_seq")
        }
        async fn delete_below_seq(
            &self,
            _floor_seq:   i64,
            _older_than:  i64,
            _kind_filter: crate::audit::retention::AuditRetentionKindFilter,
        ) -> PortResult<u32> {
            unimplemented!("safety_controls tests do not exercise delete_below_seq")
        }
    }

    #[tokio::test]
    async fn count_refresh_reuse_filters_to_kind_and_window() {
        let repo = StubRepo::default();
        // 5 reuse events: ts=10, 50, 100, 200, 300.
        for &t in &[10, 50, 100, 200, 300] {
            repo.push(t, EVENT_KIND_REFRESH_TOKEN_REUSE_DETECTED);
        }
        // Also some unrelated events to verify the kind filter works.
        repo.push(150, "auth_success");
        repo.push(250, "auth_failed");

        // Window since=100 → 100, 200, 300 → count == 3.
        let n = count_refresh_reuse_since(&repo, 100).await.unwrap();
        assert_eq!(n, 3, "should count only events at/after since_unix with the right kind");
    }

    #[tokio::test]
    async fn count_refresh_reuse_returns_zero_when_no_events() {
        let repo = StubRepo::default();
        let n = count_refresh_reuse_since(&repo, 0).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn count_refresh_reuse_ignores_other_event_kinds() {
        let repo = StubRepo::default();
        // Only non-reuse events.
        repo.push(10, "auth_success");
        repo.push(20, "auth_failed");
        let n = count_refresh_reuse_since(&repo, 0).await.unwrap();
        assert_eq!(n, 0,
            "kind filter must exclude non-RefreshTokenReuseDetected events");
    }

    #[tokio::test]
    async fn count_refresh_reuse_respects_lower_bound_strictly() {
        let repo = StubRepo::default();
        repo.push(99,  EVENT_KIND_REFRESH_TOKEN_REUSE_DETECTED);
        repo.push(100, EVENT_KIND_REFRESH_TOKEN_REUSE_DETECTED);
        repo.push(101, EVENT_KIND_REFRESH_TOKEN_REUSE_DETECTED);
        // since=100 → includes 100 (inclusive) and 101; excludes 99.
        let n = count_refresh_reuse_since(&repo, 100).await.unwrap();
        assert_eq!(n, 2);
    }

    #[tokio::test]
    async fn compute_safety_controls_assembles_report() {
        let repo = StubRepo::default();
        let now: i64 = 1_000_000;
        // One event in the 24h window (ts = now - 1000), one outside (ts = now - 100000).
        repo.push(now - 1000,   EVENT_KIND_REFRESH_TOKEN_REUSE_DETECTED);
        repo.push(now - 100000, EVENT_KIND_REFRESH_TOKEN_REUSE_DETECTED);

        let report = compute_safety_controls(
            &repo, now, true, false, Some("https://runbook.example/cesauth".into()),
        ).await.unwrap();

        assert_eq!(report.turnstile_configured,     true);
        assert_eq!(report.totp_key_configured,      false);
        assert_eq!(report.refresh_reuse_count_24h,  1, "should count only within 24h window");
        assert_eq!(report.runbook_url.as_deref(),   Some("https://runbook.example/cesauth"));
        assert!(report.rate_limit_status.is_none(),
            "RFC 110a is deferred — rate_limit_status must stay None");
    }

    #[tokio::test]
    async fn compute_safety_controls_uses_24h_window() {
        let repo = StubRepo::default();
        let now: i64 = 2_000_000;
        // Boundary case: an event exactly 24h before now is inclusive.
        repo.push(now - 86_400, EVENT_KIND_REFRESH_TOKEN_REUSE_DETECTED);
        let report = compute_safety_controls(&repo, now, false, false, None).await.unwrap();
        assert_eq!(report.refresh_reuse_count_24h, 1,
            "event at exactly 24h boundary should be counted (inclusive lower bound)");

        // An event 24h + 1s ago should NOT be counted.
        let repo2 = StubRepo::default();
        repo2.push(now - 86_401, EVENT_KIND_REFRESH_TOKEN_REUSE_DETECTED);
        let report2 = compute_safety_controls(&repo2, now, false, false, None).await.unwrap();
        assert_eq!(report2.refresh_reuse_count_24h, 0,
            "event one second past the 24h window must be excluded");
    }

    #[tokio::test]
    async fn compute_safety_controls_clamps_negative_now() {
        // Defensive: a non-sensical now_unix=0 → since = -86400 saturates;
        // helper must not underflow.
        let repo = StubRepo::default();
        let r = compute_safety_controls(&repo, 0, false, false, None).await;
        assert!(r.is_ok());
    }

    #[test]
    fn rate_limit_status_reexport_is_the_same_type() {
        // Compile-time identity check: the reexport is the canonical type.
        let _x: RateLimitStatusReexport = RateLimitStatus {
            throttled_buckets: 0, tripped_clients: 0,
        };
    }
}
