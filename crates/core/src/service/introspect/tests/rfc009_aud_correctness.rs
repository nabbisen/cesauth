//! Originally a nested `mod rfc009_aud_correctness` inside
//! `crates/core/src/service/introspect/tests.rs`. Split into its
//! own file in v0.76.0 (test-file modularization continued from
//! v0.75.0; see CHANGELOG).

use super::multi_key::{keypair_from_seed, sign_access_token, make_claims, TestAccessClaims};
use super::*;

fn make_token_with_aud(aud: &str) -> String {
    // Use seed 1 which matches fake_keys()
    let (sk, _vk) = keypair_from_seed(1);
    let mut claims = make_claims();
    claims.aud = aud.to_owned();
    sign_access_token(&sk, "k1", &claims)
}

/// **Regression pin (RFC 009)** — pre-v0.50.3 the introspection
/// verifier was called with `expected_aud = issuer` while tokens
/// carry `aud = client.id`. Every valid production access-token
/// introspection returned `{"active":false}`. This test pins the
/// fix: a token with `aud = "client_X"` (the realistic shape)
/// must introspect as active.
#[tokio::test]
async fn access_token_with_aud_equal_to_client_id_introspects_active() {
    let (_, vk) = keypair_from_seed(1);
    let pub_bytes = vk.to_bytes();
    let keys = vec![crate::oidc::introspect::IntrospectionKey {
        kid: "k1", public_key_raw: &pub_bytes,
    }];
    let store = StubFamilyStore::default();

    // AUD = "client_X" (not ISS) — production shape.
    let token = make_token_with_aud(AUD);
    let resp = introspect_token(
        &store, &keys, ISS, 30,
        &IntrospectInput { token: &token, hint: None, now_unix: 200 },
    ).await.unwrap();
    assert!(resp.active,
        "RFC 009 regression: access token with aud=client_id must be active");
    assert_eq!(resp.aud.as_deref(), Some(AUD),
        "aud in response must be populated from the token claim");
}

/// Verifier does not enforce aud equality at all; a token whose
/// aud happens to equal iss (atypical) must also introspect active.
#[tokio::test]
async fn access_token_with_aud_equal_to_iss_is_still_active() {
    let (_, vk) = keypair_from_seed(1);
    let pub_bytes = vk.to_bytes();
    let keys = vec![crate::oidc::introspect::IntrospectionKey {
        kid: "k1", public_key_raw: &pub_bytes,
    }];
    let store = StubFamilyStore::default();
    let token = make_token_with_aud(ISS);
    let resp = introspect_token(
        &store, &keys, ISS, 30,
        &IntrospectInput { token: &token, hint: None, now_unix: 200 },
    ).await.unwrap();
    assert!(resp.active, "token with aud==iss must still be active");
}

/// aud in the response must match the token's aud claim, giving
/// the audience gate (ADR-014 §Q1) something to compare against.
#[tokio::test]
async fn introspect_response_aud_reflects_token_aud_claim() {
    let (_, vk) = keypair_from_seed(1);
    let pub_bytes = vk.to_bytes();
    let keys = vec![crate::oidc::introspect::IntrospectionKey {
        kid: "k1", public_key_raw: &pub_bytes,
    }];
    let store = StubFamilyStore::default();
    let token = make_token_with_aud("resource-server-A");
    let resp = introspect_token(
        &store, &keys, ISS, 30,
        &IntrospectInput { token: &token, hint: None, now_unix: 200 },
    ).await.unwrap();
    assert!(resp.active);
    assert_eq!(resp.aud.as_deref(), Some("resource-server-A"));
}
