//! RFC 139 tests 1–3: the decision function at every boundary, and the
//! validating constructor. Every policy is built through `new` (§7.2).

use super::*;

fn family(created_at: i64, last_rotated_at: i64) -> FamilyState {
    FamilyState {
        family_id:         crate::types::FamilyId::from_storage("f"),
        user_id:           crate::types::UserId::from_storage("u"),
        client_id:         crate::types::ClientId::from_storage("c"),
        scopes:            vec![],
        current_jti:       crate::types::Jti::from_storage("j"),
        retired_jtis:      vec![],
        created_at,
        last_rotated_at,
        revoked_at:        None,
        reused_jti:        None,
        reused_at:         None,
        reuse_was_retired: None,
        expired:           None,
        auth_time:         0,
    }
}

fn policy(absolute: i64, idle: i64) -> RefreshLifetime {
    RefreshLifetime::new(absolute, idle).expect("valid test policy")
}

/// Test 1 — absolute: `created_at + abs - 1` is live, `created_at + abs` is not.
#[test]
fn absolute_boundary() {
    let p = policy(1_000, 0); // idle disabled, so only the absolute cap applies
    let f = family(500, 500);
    assert_eq!(f.lifetime(500 + 1_000 - 1, &p), Lifetime::Live);
    assert_eq!(f.lifetime(500 + 1_000, &p), Lifetime::Expired(LifetimeExpiry::Absolute));
    assert_eq!(f.deadline(&p), 1_500);
}

/// Test 2 — idle: `last_rotated_at + idle - 1` is live, `+ idle` is
/// `Expired(Idle)`; idle `0` never idle-expires.
#[test]
fn idle_boundary_and_zero_disables() {
    let p = policy(10_000, 100);
    let f = family(0, 5_000); // rotated recently; absolute deadline far away
    assert_eq!(f.lifetime(5_000 + 100 - 1, &p), Lifetime::Live);
    assert_eq!(f.lifetime(5_000 + 100, &p), Lifetime::Expired(LifetimeExpiry::Idle));
    assert_eq!(f.deadline(&p), 5_100, "deadline is the earlier of the two");

    let no_idle = policy(10_000, 0);
    assert_eq!(f.lifetime(9_999, &no_idle), Lifetime::Live, "idle 0 never idle-expires");
    assert_eq!(f.deadline(&no_idle), 10_000, "only the absolute term when idle is 0");
}

/// Test 3 — both past: `Absolute` wins. The validator rejects abs ≤ 0,
/// idle < 0 and idle > abs, and accepts the boundary values.
#[test]
fn absolute_wins_and_validator_rules() {
    let p = policy(1_000, 100);
    let f = family(0, 0);
    // now = 2_000 is past both 0+1_000 (absolute) and 0+100 (idle).
    assert_eq!(f.lifetime(2_000, &p), Lifetime::Expired(LifetimeExpiry::Absolute));

    assert_eq!(RefreshLifetime::new(0, 0),
        Err(RefreshLifetimeError::AbsoluteNotPositive { absolute_secs: 0 }));
    assert_eq!(RefreshLifetime::new(-1, 0),
        Err(RefreshLifetimeError::AbsoluteNotPositive { absolute_secs: -1 }));
    assert_eq!(RefreshLifetime::new(100, -1),
        Err(RefreshLifetimeError::IdleNegative { idle_secs: -1 }));
    assert_eq!(RefreshLifetime::new(100, 101),
        Err(RefreshLifetimeError::IdleExceedsAbsolute { idle_secs: 101, absolute_secs: 100 }));

    assert!(RefreshLifetime::new(1, 0).is_ok(),   "smallest absolute, idle disabled");
    assert!(RefreshLifetime::new(100, 100).is_ok(), "idle equal to absolute is allowed");
}

/// Test 14 (pure part) — the shipped defaults form a valid policy.
#[test]
fn defaults_are_a_valid_policy() {
    let p = RefreshLifetime::new(2_592_000, DEFAULT_REFRESH_IDLE_TIMEOUT_SECS).expect("defaults");
    assert_eq!(p.absolute_secs(), 2_592_000);
    assert_eq!(p.idle_secs(), 1_209_600);
}
