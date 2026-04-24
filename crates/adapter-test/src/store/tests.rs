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

    // Present the old jti - reuse detection must fire.
    let out = store.rotate("f", "j1", "j3", 20).await.unwrap();
    assert!(matches!(out, RotateOutcome::ReusedAndRevoked));

    // Even the legitimate new jti no longer rotates - family is dead.
    let out = store.rotate("f", "j2", "j4", 30).await.unwrap();
    assert!(matches!(out, RotateOutcome::AlreadyRevoked));
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
