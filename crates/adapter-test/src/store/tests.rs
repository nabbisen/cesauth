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
        session_id:   id.to_owned(),
        user_id:      user.to_owned(),
        client_id:    "client_a".to_owned(),
        scopes:       vec!["openid".to_owned()],
        auth_method:  AuthMethod::Passkey,
        created_at,
        last_seen_at: created_at,
        revoked_at:   None,
    }
}

fn sample_auth_code() -> Challenge {
    Challenge::AuthCode {
        client_id:             "c".into(),
        redirect_uri:          "https://app/cb".into(),
        user_id:               "u".into(),
        scopes:                Scopes(vec!["openid".into()]),
        nonce:                 None,
        code_challenge:        "x".into(),
        code_challenge_method: "S256".into(),
        issued_at:             0,
        expires_at:             60,
    }
}

#[tokio::test]
async fn auth_code_single_consumption() {
    let store = InMemoryAuthChallengeStore::default();
    store.put("h", &sample_auth_code()).await.unwrap();
    // First take wins.
    assert!(store.take("h").await.unwrap().is_some());
    // Second take sees empty. This is the single-consumption invariant.
    assert!(store.take("h").await.unwrap().is_none());
}

#[tokio::test]
async fn auth_code_put_no_overwrite() {
    let store = InMemoryAuthChallengeStore::default();
    store.put("h", &sample_auth_code()).await.unwrap();
    assert!(matches!(
        store.put("h", &sample_auth_code()).await,
        Err(PortError::Conflict)
    ));
}

#[tokio::test]
async fn refresh_reuse_burns_family() {
    let store = InMemoryRefreshTokenFamilyStore::default();
    let init = FamilyInit {
        family_id: "f".into(),
        user_id:   "u".into(),
        client_id: "c".into(),
        scopes:    vec!["openid".into()],
        first_jti: "j1".into(),
        now_unix:  0,
    };
    store.init(&init).await.unwrap();

    // Rotate once legitimately.
    let out = store.rotate("f", "j1", "j2", 10).await.unwrap();
    assert!(matches!(out, RotateOutcome::Rotated { .. }));

    // Present the old jti - reuse detection must fire. v0.34.0:
    // the outcome carries forensic data — `reused_jti` mirrors
    // the presented jti so the worker doesn't have to peek the
    // family again to emit the audit event, and `was_retired`
    // distinguishes the recognized-retired case (= real but
    // rotated-out token) from an unknown-jti case (= forged or
    // shotgun).
    let out = store.rotate("f", "j1", "j3", 20).await.unwrap();
    match out {
        RotateOutcome::ReusedAndRevoked { reused_jti, was_retired } => {
            assert_eq!(reused_jti, "j1");
            assert!(was_retired,
                "j1 was rotated out at step 1, so it should be in retired_jtis at the time of presentation");
        }
        other => panic!("expected ReusedAndRevoked, got {other:?}"),
    }

    // The post-revoke peek must surface the forensic fields too —
    // otherwise the admin UI's eventual "show me this family's
    // reuse history" view has nothing to render.
    let fam = store.peek("f").await.unwrap().expect("family present");
    assert_eq!(fam.reused_jti.as_deref(), Some("j1"));
    assert_eq!(fam.reused_at, Some(20));
    assert_eq!(fam.reuse_was_retired, Some(true));
    assert_eq!(fam.revoked_at, Some(20));

    // Even the legitimate new jti no longer rotates - family is dead.
    let out = store.rotate("f", "j2", "j4", 30).await.unwrap();
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
        family_id: "f".into(),
        user_id:   "u".into(),
        client_id: "c".into(),
        scopes:    vec!["openid".into()],
        first_jti: "j1".into(),
        now_unix:  0,
    };
    store.init(&init).await.unwrap();

    // Present a jti the family has never seen (current is j1,
    // retired is empty).
    let out = store.rotate("f", "totally-fake-jti", "j2", 10).await.unwrap();
    match out {
        RotateOutcome::ReusedAndRevoked { reused_jti, was_retired } => {
            assert_eq!(reused_jti, "totally-fake-jti");
            assert!(!was_retired,
                "an unknown jti should map to was_retired=false — \
                 the BCP signal that distinguishes 'real token leaked' \
                 from 'attacker guessing without prior knowledge'");
        }
        other => panic!("expected ReusedAndRevoked, got {other:?}"),
    }

    let fam = store.peek("f").await.unwrap().unwrap();
    assert_eq!(fam.reuse_was_retired, Some(false));
    assert_eq!(fam.reused_jti.as_deref(), Some("totally-fake-jti"));
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
        family_id: "f".into(),
        user_id:   "u".into(),
        client_id: "c".into(),
        scopes:    vec!["openid".into()],
        first_jti: "j1".into(),
        now_unix:  0,
    };
    store.init(&init).await.unwrap();

    // Rotate, then trigger reuse.
    let _ = store.rotate("f", "j1", "j2", 10).await.unwrap();
    let _ = store.rotate("f", "j1", "j3", 20).await.unwrap();

    let fam_first = store.peek("f").await.unwrap().unwrap();
    assert_eq!(fam_first.reused_jti.as_deref(), Some("j1"));
    assert_eq!(fam_first.reused_at,             Some(20));

    // More attempts, all of which see AlreadyRevoked. The
    // forensic record must NOT mutate.
    let out = store.rotate("f", "another-jti", "j4", 30).await.unwrap();
    assert!(matches!(out, RotateOutcome::AlreadyRevoked));

    let out = store.rotate("f", "j2", "j5", 40).await.unwrap();
    assert!(matches!(out, RotateOutcome::AlreadyRevoked));

    let fam_after = store.peek("f").await.unwrap().unwrap();
    assert_eq!(fam_after.reused_jti.as_deref(), Some("j1"),
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
        family_id: "f".into(),
        user_id:   "u".into(),
        client_id: "c".into(),
        scopes:    vec!["openid".into()],
        first_jti: "j1".into(),
        now_unix:  0,
    };
    store.init(&init).await.unwrap();
    store.revoke("f", 50).await.unwrap();

    let fam = store.peek("f").await.unwrap().unwrap();
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
    let out = store.touch("s1", 130, 60, 0).await.unwrap();
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
    let out = store.touch("s1", 190, 60, 0).await.unwrap();
    match out {
        SessionStatus::IdleExpired(state) => {
            assert_eq!(state.revoked_at, Some(190),
                "DO must populate revoked_at atomically with the IdleExpired return");
        }
        other => panic!("expected IdleExpired, got {other:?}"),
    }

    // Subsequent status() reads see Revoked.
    let st = store.status("s1").await.unwrap();
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
    let out = store.touch("s1", 100 + 3600, 0, 0).await.unwrap();
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
    let out1 = store.touch("s1", 1900, 3600, 7200).await.unwrap();
    assert!(matches!(out1, SessionStatus::Active(_)),
        "30-min-old session with 1-hr idle window must be active");

    // Now test absolute. At t=3800 (63 min from start),
    // last_seen_at = 1900 → idle delta = 1900, idle window
    // 3600 → idle gate would NOT fire. But created_at + 3600
    // = 3700 < 3800 → absolute gate fires.
    let out2 = store.touch("s1", 3800, 3600, 3600).await.unwrap();
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
    let out = store.touch("s1", 7200, 60, 3600).await.unwrap();
    assert!(matches!(out, SessionStatus::AbsoluteExpired(_)),
        "absolute gate must take priority over idle for forensic clarity");
}

#[tokio::test]
async fn session_touch_already_revoked_is_idempotent() {
    let store = InMemoryActiveSessionStore::default();
    let s = sample_session("s1", "u1", 100);
    store.start(&s).await.unwrap();
    store.revoke("s1", 150).await.unwrap();

    // Subsequent touch must not flip the revoked_at, must
    // not return IdleExpired, must just see Revoked.
    let out = store.touch("s1", 200, 60, 0).await.unwrap();
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
    let out = store.touch("never-started", 100, 60, 0).await.unwrap();
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

    let out = store.list_for_user("alice", false, 50).await.unwrap();
    assert_eq!(out.len(), 3);
    assert_eq!(out[0].session_id, "s_new", "newest first");
    assert_eq!(out[1].session_id, "s_mid");
    assert_eq!(out[2].session_id, "s_old");
    // bob's session must not leak in.
    assert!(out.iter().all(|s| s.user_id == "alice"));
}

#[tokio::test]
async fn session_list_for_user_excludes_revoked_by_default() {
    let store = InMemoryActiveSessionStore::default();
    store.start(&sample_session("active", "alice", 100)).await.unwrap();
    store.start(&sample_session("dead",   "alice", 200)).await.unwrap();
    store.revoke("dead", 250).await.unwrap();

    let active_only = store.list_for_user("alice", false, 50).await.unwrap();
    assert_eq!(active_only.len(), 1);
    assert_eq!(active_only[0].session_id, "active");

    let with_revoked = store.list_for_user("alice", true, 50).await.unwrap();
    assert_eq!(with_revoked.len(), 2,
        "include_revoked=true must surface revoked sessions for forensic UIs");
}

#[tokio::test]
async fn session_list_for_user_respects_limit() {
    let store = InMemoryActiveSessionStore::default();
    for i in 0..5 {
        store.start(&sample_session(&format!("s{i}"), "alice", 100 + i)).await.unwrap();
    }
    let out = store.list_for_user("alice", false, 2).await.unwrap();
    assert_eq!(out.len(), 2,
        "limit must cap the result count");
}

#[tokio::test]
async fn session_list_for_user_empty_when_no_sessions() {
    let store = InMemoryActiveSessionStore::default();
    let out = store.list_for_user("nobody", false, 50).await.unwrap();
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
