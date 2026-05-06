//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;
use cesauth_core::ports::store::{
    AuthChallengeStore, Challenge, FamilyInit, RateLimitStore, RefreshTokenFamilyStore,
    RotateOutcome,
};
use cesauth_core::ports::PortError;
use cesauth_core::types::Scopes;

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
