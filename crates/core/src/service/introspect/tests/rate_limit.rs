//! Originally a nested `mod rate_limit` inside
//! `crates/core/src/service/introspect/tests.rs`. Split into its
//! own file in v0.76.0 (test-file modularization continued from
//! v0.75.0; see CHANGELOG).

use super::super::{check_introspection_rate_limit, IntrospectionRateLimitDecision};
use crate::ports::store::{RateLimitDecision, RateLimitStore};
use crate::ports::{PortError, PortResult};
use std::cell::RefCell;
use std::collections::HashMap;

/// Inline in-memory RateLimitStore stub.
/// Same shape as `cesauth_adapter_test::InMemoryRateLimitStore`
/// but RefCell-based (single-threaded tests don't need
/// Mutex). Mirrors the stub-vs-adapter-test pattern used
/// in service::token::tests / service::revoke::tests.
#[derive(Debug, Default)]
struct StubRateLimit {
    map: RefCell<HashMap<String, (i64, u32)>>,  // bucket → (window_start, count)
}

impl RateLimitStore for StubRateLimit {
    async fn hit(
        &self,
        bucket_key:     &str,
        now_unix:       i64,
        window_secs:    i64,
        limit:          u32,
        escalate_after: u32,
    ) -> PortResult<RateLimitDecision> {
        let mut m = self.map.borrow_mut();
        let entry = m.entry(bucket_key.to_owned()).or_insert((now_unix, 0));
        if now_unix.saturating_sub(entry.0) >= window_secs {
            *entry = (now_unix, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        Ok(RateLimitDecision {
            allowed:   entry.1 <= limit,
            count:     entry.1,
            limit,
            resets_in: window_secs.saturating_sub(now_unix.saturating_sub(entry.0)),
            escalate:  entry.1 > escalate_after,
        })
    }
    async fn reset(&self, _: &str) -> PortResult<()> {
        Err(PortError::Unavailable)  // not used in these tests
    }
}

// ----------------- Threshold opt-out -----------------

#[tokio::test]
async fn threshold_zero_always_allows() {
    // Operators who don't want a rate limit at this
    // layer (e.g., they have one upstream at a load
    // balancer) set threshold = 0 and the gate is
    // a no-op.
    let rates = StubRateLimit::default();
    for i in 0..1000 {
        let dec = check_introspection_rate_limit(
            &rates, "any_client", i, 60, 0,
        ).await.unwrap();
        assert_eq!(dec, IntrospectionRateLimitDecision::Allowed,
            "threshold=0 must always allow, denied at iteration {i}");
    }
}

// ----------------- Allow under threshold -----------------

#[tokio::test]
async fn first_n_within_window_allowed_then_n_plus_one_denied() {
    let rates = StubRateLimit::default();
    // First 5 hits allowed.
    for i in 0..5 {
        let dec = check_introspection_rate_limit(
            &rates, "rs_demo", 100 + i, 60, 5,
        ).await.unwrap();
        assert_eq!(dec, IntrospectionRateLimitDecision::Allowed,
            "hit {} of 5 must be allowed", i + 1);
    }
    // 6th hit denied.
    let dec = check_introspection_rate_limit(
        &rates, "rs_demo", 105, 60, 5,
    ).await.unwrap();
    assert!(matches!(dec, IntrospectionRateLimitDecision::Denied { .. }),
        "6th hit must be denied: {dec:?}");
}

// ----------------- retry_after_secs sanity -----------------

#[tokio::test]
async fn denied_decision_carries_retry_after_secs() {
    let rates = StubRateLimit::default();
    for i in 0..3 {
        check_introspection_rate_limit(&rates, "rs_demo", 100 + i, 60, 3)
            .await.unwrap();
    }
    let dec = check_introspection_rate_limit(
        &rates, "rs_demo", 105, 60, 3,
    ).await.unwrap();
    match dec {
        IntrospectionRateLimitDecision::Denied { retry_after_secs } => {
            assert!(retry_after_secs > 0,
                "retry_after_secs must be positive: got {retry_after_secs}");
            assert!(retry_after_secs <= 60,
                "retry_after_secs must not exceed window: got {retry_after_secs}");
        }
        _ => panic!("expected Denied, got {dec:?}"),
    }
}

// ----------------- Per-client isolation -----------------

#[tokio::test]
async fn rate_limit_is_isolated_per_client_id() {
    // RS_A's saturated bucket must NOT affect RS_B.
    // This is the headline property — a chatty
    // resource server doesn't deny service to its
    // peers.
    let rates = StubRateLimit::default();

    // Saturate RS_A.
    for i in 0..5 {
        check_introspection_rate_limit(&rates, "rs_a", 100 + i, 60, 5)
            .await.unwrap();
    }
    let a_denied = check_introspection_rate_limit(
        &rates, "rs_a", 105, 60, 5,
    ).await.unwrap();
    assert!(matches!(a_denied, IntrospectionRateLimitDecision::Denied { .. }));

    // RS_B's first hit must still be allowed.
    let b_allowed = check_introspection_rate_limit(
        &rates, "rs_b", 105, 60, 5,
    ).await.unwrap();
    assert_eq!(b_allowed, IntrospectionRateLimitDecision::Allowed,
        "rs_b must NOT be affected by rs_a's saturated bucket");
}

// ----------------- Window roll -----------------

#[tokio::test]
async fn rate_limit_resets_after_window_rolls() {
    let rates = StubRateLimit::default();

    // Saturate.
    for i in 0..5 {
        check_introspection_rate_limit(&rates, "rs_demo", 100 + i, 60, 5)
            .await.unwrap();
    }
    // Confirm denied.
    let denied = check_introspection_rate_limit(
        &rates, "rs_demo", 105, 60, 5,
    ).await.unwrap();
    assert!(matches!(denied, IntrospectionRateLimitDecision::Denied { .. }));

    // Roll past the 60s window.
    let allowed_again = check_introspection_rate_limit(
        &rates, "rs_demo", 200, 60, 5,
    ).await.unwrap();
    assert_eq!(allowed_again, IntrospectionRateLimitDecision::Allowed,
        "first hit after window roll must be allowed");
}

// ----------------- Defensive boundary -----------------

#[tokio::test]
async fn threshold_one_denies_immediately_after_first_hit() {
    // Edge case: threshold=1 means "exactly one
    // request per window allowed". The store
    // returns allowed=true on the first hit (count
    // <= limit), denied on the second.
    let rates = StubRateLimit::default();
    let first = check_introspection_rate_limit(
        &rates, "rs_strict", 100, 60, 1,
    ).await.unwrap();
    assert_eq!(first, IntrospectionRateLimitDecision::Allowed);
    let second = check_introspection_rate_limit(
        &rates, "rs_strict", 101, 60, 1,
    ).await.unwrap();
    assert!(matches!(second, IntrospectionRateLimitDecision::Denied { .. }));
}
