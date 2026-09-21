//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;
use cesauth_core::ports::store::{
    ActiveSessionStore, AuthChallengeStore, AuthMethod, Challenge, FamilyInit,
    RateLimitStore, RefreshTokenFamilyStore, RotateOutcome,
    SessionState, SessionStatus,
};
use cesauth_core::ports::PortError;
use cesauth_core::types::Scopes;

fn sample_session(id: &str, user: &str, created_at: i64) -> SessionState {
    SessionState {
        session_id:   cesauth_core::types::SessionId::from_storage(id),
        user_id:      cesauth_core::types::UserId::from_storage(user),
        client_id:    cesauth_core::types::ClientId::from_storage("client_a"),
        scopes:       vec!["openid".to_owned()],
        auth_method:  AuthMethod::Passkey,
        created_at,
        last_seen_at: created_at,
        revoked_at:   None,
    }
}

fn sample_auth_code() -> Challenge {
    Challenge::AuthCode {
        client_id: "c".to_owned(),
        redirect_uri:          "https://app/cb".into(),
        user_id: "u".to_owned(),
        scopes:                Scopes(vec!["openid".into()]),
        nonce:                 None,
        code_challenge:        "x".into(),
        code_challenge_method: "S256".into(),
        issued_at:             0,
        expires_at:            60,
        auth_time:             0,
    }
}

#[tokio::test]
async fn auth_code_single_consumption() {
    let store = InMemoryAuthChallengeStore::default();
    store.put(&cesauth_core::types::ChallengeHandle::from_storage("h"), &sample_auth_code()).await.unwrap();
    // First take wins.
    assert!(store.take(&cesauth_core::types::ChallengeHandle::from_storage("h"), 0).await.unwrap().is_some());
    // Second take sees empty. This is the single-consumption invariant.
    assert!(store.take(&cesauth_core::types::ChallengeHandle::from_storage("h"), 0).await.unwrap().is_none());
}

#[tokio::test]
async fn auth_code_put_no_overwrite() {
    let store = InMemoryAuthChallengeStore::default();
    store.put(&cesauth_core::types::ChallengeHandle::from_storage("h"), &sample_auth_code()).await.unwrap();
    assert!(matches!(
        store.put(&cesauth_core::types::ChallengeHandle::from_storage("h"), &sample_auth_code()).await,
        Err(PortError::Conflict)
    ));
}

// -----------------------------------------------------------------------
// RFC 140 — the store enforces expiry at read. `sample_auth_code()`
// expires at 60, so 59 is the last live second and 60 the first
// expired one (expired iff `now_unix >= expires_at`).
// -----------------------------------------------------------------------

fn rfc140_handle() -> cesauth_core::types::ChallengeHandle {
    cesauth_core::types::ChallengeHandle::from_storage("rfc140")
}

/// Test 1: `peek` is live before `expires_at`, absent at it, and does
/// not delete the entry.
#[tokio::test]
async fn rfc140_peek_is_absent_at_expires_at_and_does_not_delete() {
    let store = InMemoryAuthChallengeStore::default();
    let exp = sample_auth_code().expires_at();
    store.put(&rfc140_handle(), &sample_auth_code()).await.unwrap();

    assert!(store.peek(&rfc140_handle(), exp - 1).await.unwrap().is_some());
    assert!(store.peek(&rfc140_handle(), exp).await.unwrap().is_none());
    // Still present: an earlier `now` sees it again.
    assert!(store.peek(&rfc140_handle(), exp - 1).await.unwrap().is_some(),
        "an expired peek must not delete the entry");
}

/// Test 2: single consumption holds with a live `now`.
#[tokio::test]
async fn rfc140_take_before_expires_at_is_single_use() {
    let store = InMemoryAuthChallengeStore::default();
    let exp = sample_auth_code().expires_at();
    store.put(&rfc140_handle(), &sample_auth_code()).await.unwrap();

    assert!(store.take(&rfc140_handle(), exp - 1).await.unwrap().is_some());
    assert!(store.take(&rfc140_handle(), exp - 1).await.unwrap().is_none());
}

/// Test 3: `take` at `expires_at` returns `None` **and removes the
/// entry** — a later `take` with a live `now` finds nothing.
#[tokio::test]
async fn rfc140_take_at_expires_at_returns_none_and_deletes() {
    let store = InMemoryAuthChallengeStore::default();
    let exp = sample_auth_code().expires_at();
    store.put(&rfc140_handle(), &sample_auth_code()).await.unwrap();

    assert!(store.take(&rfc140_handle(), exp).await.unwrap().is_none(),
        "an expired take must never return the value");
    assert!(store.take(&rfc140_handle(), exp - 1).await.unwrap().is_none(),
        "an expired take must delete the entry");
}

/// Test 4: `bump_magic_link_attempts` at `expires_at` is `NotFound`,
/// the variant it returns for an absent entry; before it, it counts.
#[tokio::test]
async fn rfc140_bump_at_expires_at_is_not_found() {
    let store = InMemoryAuthChallengeStore::default();
    let ml = Challenge::MagicLink {
        email_or_user: "a@example.com".to_owned(),
        code_hash:     "h".to_owned(),
        attempts:      0,
        expires_at:    60,
    };
    store.put(&rfc140_handle(), &ml).await.unwrap();

    assert!(matches!(store.bump_magic_link_attempts(&rfc140_handle(), 59).await, Ok(1)));
    assert!(matches!(store.bump_magic_link_attempts(&rfc140_handle(), 60).await, Err(PortError::NotFound)));
}

#[tokio::test]
async fn refresh_reuse_burns_family() {
    let store = InMemoryRefreshTokenFamilyStore::default();
    let init = FamilyInit {
        family_id: cesauth_core::types::FamilyId::from_storage("f"),
        user_id: cesauth_core::types::UserId::from_storage("u"),
        client_id: cesauth_core::types::ClientId::from_storage("c"),
        scopes:    vec!["openid".into()],
        first_jti: cesauth_core::types::Jti::from_storage("j1"),
        now_unix:  0,
        auth_time: 0,
    };
    store.init(&init).await.unwrap();

    // Rotate once legitimately.
    let out = store.rotate(&cesauth_core::types::FamilyId::from_storage("f"), &cesauth_core::types::Jti::from_storage("j1"), &cesauth_core::types::Jti::from_storage("j2"), 10, &default_lifetime()).await.unwrap();
    assert!(matches!(out, RotateOutcome::Rotated { .. }));

    // Present the old jti - reuse detection must fire. v0.34.0:
    // the outcome carries forensic data — `reused_jti` mirrors
    // the presented jti so the worker doesn't have to peek the
    // family again to emit the audit event, and `was_retired`
    // distinguishes the recognized-retired case (= real but
    // rotated-out token) from an unknown-jti case (= forged or
    // shotgun).
    let out = store.rotate(&cesauth_core::types::FamilyId::from_storage("f"), &cesauth_core::types::Jti::from_storage("j1"), &cesauth_core::types::Jti::from_storage("j3"), 20, &default_lifetime()).await.unwrap();
    match out {
        RotateOutcome::ReusedAndRevoked { reused_jti, was_retired } => {
            assert_eq!(reused_jti.as_str(), "j1");
            assert!(was_retired,
                "j1 was rotated out at step 1, so it should be in retired_jtis at the time of presentation");
        }
        other => panic!("expected ReusedAndRevoked, got {other:?}"),
    }

    // The post-revoke peek must surface the forensic fields too —
    // otherwise the admin UI's eventual "show me this family's
    // reuse history" view has nothing to render.
    let fam = store.peek(&cesauth_core::types::FamilyId::from_storage("f")).await.unwrap().expect("family present");
    assert_eq!(fam.reused_jti.as_ref().map(|j| j.as_str()), Some("j1"));
    assert_eq!(fam.reused_at, Some(20));
    assert_eq!(fam.reuse_was_retired, Some(true));
    assert_eq!(fam.revoked_at, Some(20));

    // Even the legitimate new jti no longer rotates - family is dead.
    let out = store.rotate(&cesauth_core::types::FamilyId::from_storage("f"), &cesauth_core::types::Jti::from_storage("j2"), &cesauth_core::types::Jti::from_storage("j4"), 30, &default_lifetime()).await.unwrap();
    assert!(matches!(out, RotateOutcome::AlreadyRevoked));
}

/// **v0.34.0** — Reuse with an unknown jti (one that's not in
/// `retired_jtis` and isn't `current_jti`). This is the
/// "forged or shotgun" subcase: an attacker who doesn't have a
/// valid jti throws something at the family hoping for a hit.
/// `was_retired` MUST be false here so the audit signal is
/// distinguishable from the legitimate-token-leaked case.
#[tokio::test]
async fn refresh_reuse_with_unknown_jti_marks_was_retired_false() {
    let store = InMemoryRefreshTokenFamilyStore::default();
    let init = FamilyInit {
        family_id: cesauth_core::types::FamilyId::from_storage("f"),
        user_id: cesauth_core::types::UserId::from_storage("u"),
        client_id: cesauth_core::types::ClientId::from_storage("c"),
        scopes:    vec!["openid".into()],
        first_jti: cesauth_core::types::Jti::from_storage("j1"),
        now_unix:  0,
        auth_time: 0,
    };
    store.init(&init).await.unwrap();

    // Present a jti the family has never seen (current is j1,
    // retired is empty).
    let out = store.rotate(&cesauth_core::types::FamilyId::from_storage("f"), &cesauth_core::types::Jti::from_storage("totally-fake-jti"), &cesauth_core::types::Jti::from_storage("j2"), 10, &default_lifetime()).await.unwrap();
    match out {
        RotateOutcome::ReusedAndRevoked { reused_jti, was_retired } => {
            assert_eq!(reused_jti.as_str(), "totally-fake-jti");
            assert!(!was_retired,
                "an unknown jti should map to was_retired=false — \
                 the BCP signal that distinguishes 'real token leaked' \
                 from 'attacker guessing without prior knowledge'");
        }
        other => panic!("expected ReusedAndRevoked, got {other:?}"),
    }

    let fam = store.peek(&cesauth_core::types::FamilyId::from_storage("f")).await.unwrap().unwrap();
    assert_eq!(fam.reuse_was_retired, Some(false));
    assert_eq!(fam.reused_jti.as_ref().map(|j| j.as_str()), Some("totally-fake-jti"));
}

/// **v0.34.0** — Once a family is revoked (by reuse OR by
/// admin), subsequent rotation attempts must NOT overwrite the
/// recorded forensic fields. The first reuse is the
/// investigation anchor; any later poke at a dead family is
/// noise from an attacker still holding the stale token.
#[tokio::test]
async fn refresh_reuse_then_more_attempts_preserve_first_forensics() {
    let store = InMemoryRefreshTokenFamilyStore::default();
    let init = FamilyInit {
        family_id: cesauth_core::types::FamilyId::from_storage("f"),
        user_id: cesauth_core::types::UserId::from_storage("u"),
        client_id: cesauth_core::types::ClientId::from_storage("c"),
        scopes:    vec!["openid".into()],
        first_jti: cesauth_core::types::Jti::from_storage("j1"),
        now_unix:  0,
        auth_time: 0,
    };
    store.init(&init).await.unwrap();

    // Rotate, then trigger reuse.
    let _ = store.rotate(&cesauth_core::types::FamilyId::from_storage("f"), &cesauth_core::types::Jti::from_storage("j1"), &cesauth_core::types::Jti::from_storage("j2"), 10, &default_lifetime()).await.unwrap();
    let _ = store.rotate(&cesauth_core::types::FamilyId::from_storage("f"), &cesauth_core::types::Jti::from_storage("j1"), &cesauth_core::types::Jti::from_storage("j3"), 20, &default_lifetime()).await.unwrap();

    let fam_first = store.peek(&cesauth_core::types::FamilyId::from_storage("f")).await.unwrap().unwrap();
    assert_eq!(fam_first.reused_jti.as_ref().map(|j| j.as_str()), Some("j1"));
    assert_eq!(fam_first.reused_at,             Some(20));

    // More attempts, all of which see AlreadyRevoked. The
    // forensic record must NOT mutate.
    let out = store.rotate(&cesauth_core::types::FamilyId::from_storage("f"), &cesauth_core::types::Jti::from_storage("another-jti"), &cesauth_core::types::Jti::from_storage("j4"), 30, &default_lifetime()).await.unwrap();
    assert!(matches!(out, RotateOutcome::AlreadyRevoked));

    let out = store.rotate(&cesauth_core::types::FamilyId::from_storage("f"), &cesauth_core::types::Jti::from_storage("j2"), &cesauth_core::types::Jti::from_storage("j5"), 40, &default_lifetime()).await.unwrap();
    assert!(matches!(out, RotateOutcome::AlreadyRevoked));

    let fam_after = store.peek(&cesauth_core::types::FamilyId::from_storage("f")).await.unwrap().unwrap();
    assert_eq!(fam_after.reused_jti.as_ref().map(|j| j.as_str()), Some("j1"),
        "first reuse jti must be preserved across later attempts");
    assert_eq!(fam_after.reused_at, Some(20),
        "first reuse timestamp must be preserved");
    assert_eq!(fam_after.reuse_was_retired, Some(true));
    assert_eq!(fam_after.revoked_at, Some(20),
        "revoked_at also reflects the first reuse, not later attempts");
}

/// **v0.34.0** — An admin-initiated `revoke()` (not a reuse
/// detection) must NOT populate the reuse forensic fields.
/// They're specifically about reuse, not about the broader
/// "this family is no longer valid" condition. An audit event
/// derived from `peek` after an admin revoke should see
/// `reused_jti = None` and infer "this revocation was an
/// admin action, not a reuse detection".
#[tokio::test]
async fn admin_revoke_does_not_populate_reuse_forensics() {
    let store = InMemoryRefreshTokenFamilyStore::default();
    let init = FamilyInit {
        family_id: cesauth_core::types::FamilyId::from_storage("f"),
        user_id: cesauth_core::types::UserId::from_storage("u"),
        client_id: cesauth_core::types::ClientId::from_storage("c"),
        scopes:    vec!["openid".into()],
        first_jti: cesauth_core::types::Jti::from_storage("j1"),
        now_unix:  0,
        auth_time: 0,
    };
    store.init(&init).await.unwrap();
    store.revoke(&cesauth_core::types::FamilyId::from_storage("f"), 50).await.unwrap();

    let fam = store.peek(&cesauth_core::types::FamilyId::from_storage("f")).await.unwrap().unwrap();
    assert_eq!(fam.revoked_at, Some(50));
    assert!(fam.reused_jti.is_none(),
        "admin revoke must not look like a reuse detection");
    assert!(fam.reused_at.is_none());
    assert!(fam.reuse_was_retired.is_none());
}

#[tokio::test]
async fn rate_limit_window_rolls() {
    let store = InMemoryRateLimitStore::default();
    for i in 0..5 {
        let d = store.hit("k", i, 10, 3, 2).await.unwrap();
        // After 3 hits we're past limit; after 2 we escalate.
        if i < 3 { assert!(d.allowed); } else { assert!(!d.allowed); }
        if i >= 2 { assert!(d.escalate); }
    }
    // Beyond window: fresh counter.
    let d = store.hit("k", 100, 10, 3, 2).await.unwrap();
    assert_eq!(d.count, 1);
    assert!(d.allowed);
    assert!(!d.escalate);
}

// =====================================================================
// ActiveSessionStore — v0.35.0 idle / absolute timeout + list_for_user
// =====================================================================

#[tokio::test]
async fn session_touch_active_bumps_last_seen() {
    let store = InMemoryActiveSessionStore::default();
    let s = sample_session("s1", "u1", 100);
    store.start(&s).await.unwrap();

    // 30 sec later, with a 60-sec idle window — still active.
    let out = store.touch(&cesauth_core::types::SessionId::from_storage("s1"), 130, 60, 0).await.unwrap();
    match out {
        SessionStatus::Active(state) => {
            assert_eq!(state.last_seen_at, 130,
                "touch must update last_seen_at on active sessions");
        }
        other => panic!("expected Active, got {other:?}"),
    }
}

#[tokio::test]
async fn session_touch_idle_window_expired_revokes_atomically() {
    let store = InMemoryActiveSessionStore::default();
    let s = sample_session("s1", "u1", 100);
    store.start(&s).await.unwrap();

    // 90 sec later, with a 60-sec idle window — last_seen_at
    // (100) + 60 = 160 <= 190; idle gate fires.
    let out = store.touch(&cesauth_core::types::SessionId::from_storage("s1"), 190, 60, 0).await.unwrap();
    match out {
        SessionStatus::IdleExpired(state) => {
            assert_eq!(state.revoked_at, Some(190),
                "DO must populate revoked_at atomically with the IdleExpired return");
        }
        other => panic!("expected IdleExpired, got {other:?}"),
    }

    // Subsequent status() reads see Revoked.
    let st = store.status(&cesauth_core::types::SessionId::from_storage("s1")).await.unwrap();
    assert!(matches!(st, SessionStatus::Revoked(_)));
}

#[tokio::test]
async fn session_touch_idle_disabled_when_zero() {
    // Setting idle_timeout_secs = 0 disables the idle gate.
    // This is the operator escape hatch documented in Config.
    let store = InMemoryActiveSessionStore::default();
    let s = sample_session("s1", "u1", 100);
    store.start(&s).await.unwrap();

    // 1 hour later. Without an idle gate, still active.
    let out = store.touch(&cesauth_core::types::SessionId::from_storage("s1"), 100 + 3600, 0, 0).await.unwrap();
    assert!(matches!(out, SessionStatus::Active(_)),
        "idle_timeout_secs=0 must disable the idle gate");
}

#[tokio::test]
async fn session_touch_absolute_lifetime_expires_regardless_of_activity() {
    let store = InMemoryActiveSessionStore::default();
    let s = sample_session("s1", "u1", 100);
    store.start(&s).await.unwrap();

    // Bump activity at t=1900 (30 min after start). Wide
    // idle window (3600) so the bump itself is active. After
    // the bump, last_seen_at = 1900.
    let out1 = store.touch(&cesauth_core::types::SessionId::from_storage("s1"), 1900, 3600, 7200).await.unwrap();
    assert!(matches!(out1, SessionStatus::Active(_)),
        "30-min-old session with 1-hr idle window must be active");

    // Now test absolute. At t=3800 (63 min from start),
    // last_seen_at = 1900 → idle delta = 1900, idle window
    // 3600 → idle gate would NOT fire. But created_at + 3600
    // = 3700 < 3800 → absolute gate fires.
    let out2 = store.touch(&cesauth_core::types::SessionId::from_storage("s1"), 3800, 3600, 3600).await.unwrap();
    match out2 {
        SessionStatus::AbsoluteExpired(state) => {
            assert_eq!(state.revoked_at, Some(3800));
        }
        other => panic!("expected AbsoluteExpired, got {other:?}"),
    }
}

#[tokio::test]
async fn session_touch_absolute_takes_priority_over_idle() {
    // Order matters: a session past BOTH gates should report
    // AbsoluteExpired (the deeper cause). The audit dispatch
    // can then attribute correctly. Test pin.
    let store = InMemoryActiveSessionStore::default();
    let s = sample_session("s1", "u1", 0);
    store.start(&s).await.unwrap();

    // 7200 sec later: last_seen=0+60 idle window exceeded
    // (idle gate would fire), AND created_at + 3600 absolute
    // window exceeded.
    let out = store.touch(&cesauth_core::types::SessionId::from_storage("s1"), 7200, 60, 3600).await.unwrap();
    assert!(matches!(out, SessionStatus::AbsoluteExpired(_)),
        "absolute gate must take priority over idle for forensic clarity");
}

#[tokio::test]
async fn session_touch_already_revoked_is_idempotent() {
    let store = InMemoryActiveSessionStore::default();
    let s = sample_session("s1", "u1", 100);
    store.start(&s).await.unwrap();
    store.revoke(&cesauth_core::types::SessionId::from_storage("s1"), 150).await.unwrap();

    // Subsequent touch must not flip the revoked_at, must
    // not return IdleExpired, must just see Revoked.
    let out = store.touch(&cesauth_core::types::SessionId::from_storage("s1"), 200, 60, 0).await.unwrap();
    match out {
        SessionStatus::Revoked(state) => {
            assert_eq!(state.revoked_at, Some(150),
                "revoked_at must reflect the original revoke time, not a later touch");
        }
        other => panic!("expected Revoked, got {other:?}"),
    }
}

#[tokio::test]
async fn session_touch_unknown_returns_not_started() {
    let store = InMemoryActiveSessionStore::default();
    let out = store.touch(&cesauth_core::types::SessionId::from_storage("never-started"), 100, 60, 0).await.unwrap();
    assert!(matches!(out, SessionStatus::NotStarted));
}

// ----- list_for_user -----

#[tokio::test]
async fn session_list_for_user_returns_only_that_user_newest_first() {
    let store = InMemoryActiveSessionStore::default();
    store.start(&sample_session("s_old",   "alice", 100)).await.unwrap();
    store.start(&sample_session("s_mid",   "alice", 200)).await.unwrap();
    store.start(&sample_session("s_new",   "alice", 300)).await.unwrap();
    store.start(&sample_session("s_other", "bob",   250)).await.unwrap();

    let out = store.list_for_user(&cesauth_core::types::UserId::from_storage("alice"), false, 50).await.unwrap();
    assert_eq!(out.len(), 3);
    assert_eq!(out[0].session_id.as_str(), "s_new", "newest first");
    assert_eq!(out[1].session_id.as_str(), "s_mid");
    assert_eq!(out[2].session_id.as_str(), "s_old");
    // bob's session must not leak in.
    assert!(out.iter().all(|s| s.user_id.as_str() == "alice"));
}

#[tokio::test]
async fn session_list_for_user_excludes_revoked_by_default() {
    let store = InMemoryActiveSessionStore::default();
    store.start(&sample_session("active", "alice", 100)).await.unwrap();
    store.start(&sample_session("dead",   "alice", 200)).await.unwrap();
    store.revoke(&cesauth_core::types::SessionId::from_storage("dead"), 250).await.unwrap();

    let active_only = store.list_for_user(&cesauth_core::types::UserId::from_storage("alice"), false, 50).await.unwrap();
    assert_eq!(active_only.len(), 1);
    assert_eq!(active_only[0].session_id.as_str(), "active");

    let with_revoked = store.list_for_user(&cesauth_core::types::UserId::from_storage("alice"), true, 50).await.unwrap();
    assert_eq!(with_revoked.len(), 2,
        "include_revoked=true must surface revoked sessions for forensic UIs");
}

#[tokio::test]
async fn session_list_for_user_respects_limit() {
    let store = InMemoryActiveSessionStore::default();
    for i in 0..5 {
        store.start(&sample_session(&format!("s{i}"), "alice", 100 + i)).await.unwrap();
    }
    let out = store.list_for_user(&cesauth_core::types::UserId::from_storage("alice"), false, 2).await.unwrap();
    assert_eq!(out.len(), 2,
        "limit must cap the result count");
}

#[tokio::test]
async fn session_list_for_user_empty_when_no_sessions() {
    let store = InMemoryActiveSessionStore::default();
    let out = store.list_for_user(&cesauth_core::types::UserId::from_storage("nobody"), false, 50).await.unwrap();
    assert!(out.is_empty());
}

// =====================================================================
// v0.37.0 — Per-family rate limit behavior (ADR-011 §Q1)
//
// These tests exercise the in-memory RateLimitStore through
// the bucket-key pattern that `rotate_refresh` uses
// (`refresh:<family_id>`). They pin the math the
// production path relies on without requiring a full
// rotate_refresh fixture (which would need PEM keys, a
// ClientRepository mock, and a JwtSigner).
// =====================================================================

#[tokio::test]
async fn refresh_rate_limit_first_5_within_window_allowed_6th_denied() {
    let store = InMemoryRateLimitStore::default();
    let bucket = "refresh:fam_abc123";
    let window = 60;
    let threshold = 5;

    // First 5 attempts within the window are allowed.
    for i in 0..5 {
        let d = store.hit(bucket, i, window, threshold, threshold).await.unwrap();
        assert!(d.allowed, "attempt {i} must be allowed within threshold");
    }

    // 6th attempt within the same window is denied.
    let d = store.hit(bucket, 5, window, threshold, threshold).await.unwrap();
    assert!(!d.allowed,
        "6th attempt must trip the rate limit");
    assert!(d.resets_in > 0,
        "denial must carry a positive resets_in for Retry-After");
}

#[tokio::test]
async fn refresh_rate_limit_isolated_per_family_id() {
    // The bucket key must namespace by family_id so unrelated
    // families don't interfere. A user with two active
    // refresh-token families (e.g., two devices) must not see
    // device A's rate limiting affect device B.
    let store = InMemoryRateLimitStore::default();
    let window = 60;
    let threshold = 5;

    // Saturate family A.
    for i in 0..6 {
        let _ = store.hit("refresh:fam_A", i, window, threshold, threshold).await.unwrap();
    }
    // The 7th hit on A is denied.
    let d_a = store.hit("refresh:fam_A", 6, window, threshold, threshold).await.unwrap();
    assert!(!d_a.allowed);

    // First hit on family B is allowed (independent bucket).
    let d_b = store.hit("refresh:fam_B", 6, window, threshold, threshold).await.unwrap();
    assert!(d_b.allowed,
        "fam_A's saturated bucket must NOT affect fam_B");
}

#[tokio::test]
async fn refresh_rate_limit_resets_after_window_rolls() {
    // After the window expires, the counter resets. A user
    // who legitimately needs to rotate at a steady rate
    // (e.g., long-running background sync that retries every
    // minute) must not get stuck in a permanent denial.
    let store = InMemoryRateLimitStore::default();
    let bucket = "refresh:fam_C";
    let window = 60;
    let threshold = 5;

    // Saturate the bucket within the window.
    for i in 0..6 {
        let _ = store.hit(bucket, i, window, threshold, threshold).await.unwrap();
    }
    // 7th in-window: denied.
    let denied = store.hit(bucket, 7, window, threshold, threshold).await.unwrap();
    assert!(!denied.allowed);

    // Move past the window. The counter should reset.
    let after_window = store.hit(bucket, 100, window, threshold, threshold).await.unwrap();
    assert!(after_window.allowed,
        "after the rate-limit window rolls, attempts must be allowed again");
    assert_eq!(after_window.count, 1,
        "counter must reset to 1 (this attempt) after window roll");
}

// -----------------------------------------------------------------------
// RFC 139 — the family store enforces the lifetime policy at rotation.
// Existing tests above pass the shipped defaults (30 d absolute, 14 d idle),
// inside whose windows their clocks (0..=40) already sit.
// -----------------------------------------------------------------------

fn default_lifetime() -> cesauth_core::ports::store::RefreshLifetime {
    cesauth_core::ports::store::RefreshLifetime::new(
        2_592_000, cesauth_core::ports::store::DEFAULT_REFRESH_IDLE_TIMEOUT_SECS,
    ).expect("shipped defaults are valid")
}

/// Absolute cap 100, idle window 30 — small enough to walk every boundary.
fn rfc139_policy() -> cesauth_core::ports::store::RefreshLifetime {
    cesauth_core::ports::store::RefreshLifetime::new(100, 30).expect("valid policy")
}

fn rfc139_fid() -> cesauth_core::types::FamilyId { cesauth_core::types::FamilyId::from_storage("f139") }
fn rfc139_jti(s: &str) -> cesauth_core::types::Jti { cesauth_core::types::Jti::from_storage(s) }

/// A family created at t=0 with current jti `j1`.
async fn rfc139_family() -> InMemoryRefreshTokenFamilyStore {
    let store = InMemoryRefreshTokenFamilyStore::default();
    store.init(&FamilyInit {
        family_id: rfc139_fid(),
        user_id:   cesauth_core::types::UserId::from_storage("u"),
        client_id: cesauth_core::types::ClientId::from_storage("c"),
        scopes:    vec!["openid".into()],
        first_jti: rfc139_jti("j1"),
        now_unix:  0,
        auth_time: 0,
    }).await.unwrap();
    store
}

/// Test 4 — rotation inside both windows rotates, and `last_rotated_at`
/// advances, so the idle window moves with it.
#[tokio::test]
async fn rfc139_rotation_inside_both_windows_moves_the_idle_window() {
    let store = rfc139_family().await;
    let p = rfc139_policy();

    let out = store.rotate(&rfc139_fid(), &rfc139_jti("j1"), &rfc139_jti("j2"), 29, &p).await.unwrap();
    assert!(matches!(out, RotateOutcome::Rotated { .. }), "got {out:?}");
    assert_eq!(store.peek(&rfc139_fid()).await.unwrap().unwrap().last_rotated_at, 29);

    // 58 is past 0 + 30 (the idle deadline had the window not moved) but
    // before 29 + 30: the window moved, so this rotates too.
    let out = store.rotate(&rfc139_fid(), &rfc139_jti("j2"), &rfc139_jti("j3"), 58, &p).await.unwrap();
    assert!(matches!(out, RotateOutcome::Rotated { .. }), "got {out:?}");
    let fam = store.peek(&rfc139_fid()).await.unwrap().unwrap();
    assert_eq!(fam.last_rotated_at, 58);
    assert_eq!(fam.revoked_at, None);
    assert_eq!(fam.expired, None);
}

/// Test 5 — idle-expired rotate → `Expired(Idle)`; `revoked_at` and `expired`
/// set in the same write, the family not rotated; a later rotate is
/// `AlreadyRevoked`.
#[tokio::test]
async fn rfc139_idle_expired_rotate_revokes_and_records_idle() {
    let store = rfc139_family().await;
    let p = rfc139_policy();

    let out = store.rotate(&rfc139_fid(), &rfc139_jti("j1"), &rfc139_jti("j2"), 30, &p).await.unwrap();
    assert!(matches!(out, RotateOutcome::Expired(cesauth_core::ports::store::LifetimeExpiry::Idle)), "got {out:?}");

    let fam = store.peek(&rfc139_fid()).await.unwrap().unwrap();
    assert_eq!(fam.revoked_at, Some(30));
    assert_eq!(fam.expired, Some(cesauth_core::ports::store::LifetimeExpiry::Idle));
    assert_eq!(fam.current_jti.as_str(), "j1", "an expired family is not rotated");

    let out = store.rotate(&rfc139_fid(), &rfc139_jti("j1"), &rfc139_jti("j3"), 31, &p).await.unwrap();
    assert!(matches!(out, RotateOutcome::AlreadyRevoked), "got {out:?}");
}

/// Test 6 — absolute-expired while recently rotated → `Expired(Absolute)`.
#[tokio::test]
async fn rfc139_absolute_expiry_applies_to_a_recently_rotated_family() {
    let store = rfc139_family().await;
    let p = rfc139_policy();
    for (from, to, at) in [("j1", "j2", 29), ("j2", "j3", 58), ("j3", "j4", 87)] {
        let out = store.rotate(&rfc139_fid(), &rfc139_jti(from), &rfc139_jti(to), at, &p).await.unwrap();
        assert!(matches!(out, RotateOutcome::Rotated { .. }), "rotation at {at}: {out:?}");
    }
    // Idle deadline is 87 + 30 = 117; the absolute cap 0 + 100 comes first.
    let out = store.rotate(&rfc139_fid(), &rfc139_jti("j4"), &rfc139_jti("j5"), 100, &p).await.unwrap();
    assert!(matches!(out, RotateOutcome::Expired(cesauth_core::ports::store::LifetimeExpiry::Absolute)), "got {out:?}");
    let fam = store.peek(&rfc139_fid()).await.unwrap().unwrap();
    assert_eq!(fam.expired, Some(cesauth_core::ports::store::LifetimeExpiry::Absolute));
    assert_eq!(fam.revoked_at, Some(100));
}

/// Test 7 — an expired family presented with a **retired** jti is `Expired`,
/// not reuse-detected; the reuse forensics stay `None` (§10.2's order).
#[tokio::test]
async fn rfc139_expired_family_with_retired_jti_is_expired_not_reuse() {
    let store = rfc139_family().await;
    let p = rfc139_policy();
    let out = store.rotate(&rfc139_fid(), &rfc139_jti("j1"), &rfc139_jti("j2"), 10, &p).await.unwrap();
    assert!(matches!(out, RotateOutcome::Rotated { .. }));

    // j1 is now retired. Present it at 10 + 30 = 40, the idle deadline.
    let out = store.rotate(&rfc139_fid(), &rfc139_jti("j1"), &rfc139_jti("j3"), 40, &p).await.unwrap();
    assert!(matches!(out, RotateOutcome::Expired(cesauth_core::ports::store::LifetimeExpiry::Idle)), "got {out:?}");

    let fam = store.peek(&rfc139_fid()).await.unwrap().unwrap();
    assert_eq!(fam.reused_jti, None);
    assert_eq!(fam.reused_at, None);
    assert_eq!(fam.reuse_was_retired, None);
    assert_eq!(fam.expired, Some(cesauth_core::ports::store::LifetimeExpiry::Idle));
    assert_eq!(fam.revoked_at, Some(40));
}

// -----------------------------------------------------------------------
// C1-117 — `put` counts an expired, never-taken entry as occupied
// (`ports/store.rs`, the first `MUST` of `AuthChallengeStore`).
// -----------------------------------------------------------------------

/// The contract's `put` clause: an entry that is expired for reads but was never
/// taken still occupies its handle, so `put` onto it is `Conflict` and changes
/// nothing. Once a `take` has removed it, the handle is free again.
#[tokio::test]
async fn c1_117_put_over_an_expired_never_taken_entry_is_conflict_and_leaves_it_unchanged() {
    let store = InMemoryAuthChallengeStore::default();
    let exp = sample_auth_code().expires_at();
    let replacement = Challenge::MagicLink {
        email_or_user: "replacement@example.com".to_owned(),
        code_hash:     "h".to_owned(),
        attempts:      0,
        expires_at:    exp + 1_000,
    };
    store.put(&rfc140_handle(), &sample_auth_code()).await.unwrap();

    // Expired for reads, and never taken.
    assert!(store.peek(&rfc140_handle(), exp).await.unwrap().is_none());

    // ... yet it still occupies the handle.
    assert!(matches!(store.put(&rfc140_handle(), &replacement).await, Err(PortError::Conflict)),
        "put onto an expired, never-taken entry must be Conflict");
    match store.peek(&rfc140_handle(), exp - 1).await.unwrap() {
        Some(Challenge::AuthCode { .. }) => {}
        other => panic!("the refused put must leave the original entry unchanged, found {other:?}"),
    }

    // A take (which deletes an expired entry, RFC 140) frees the handle.
    assert!(store.take(&rfc140_handle(), exp).await.unwrap().is_none());
    store.put(&rfc140_handle(), &replacement).await.expect("the handle is free once taken");
}
