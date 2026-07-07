//! Originally a nested `mod multi_key` inside
//! `crates/core/src/service/introspect/tests.rs`. Split into its
//! own file in v0.76.0 (test-file modularization continued from
//! v0.75.0; see CHANGELOG).

use super::*;
use crate::oidc::introspect::IntrospectionKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Serialize;

/// Test harness: a deterministic Ed25519 keypair from
/// a fixed 32-byte seed. Two different seeds give two
/// different keypairs, which is what we need for the
/// rotation-grace-period scenarios.
pub(super) fn keypair_from_seed(seed: u8) -> (SigningKey, VerifyingKey) {
    let bytes = [seed; 32];
    let sk = SigningKey::from_bytes(&bytes);
    let vk = sk.verifying_key();
    (sk, vk)
}

/// Sign an access-token-shaped payload with the given
/// keypair and embed `kid` in the JWT header. Returns
/// the compact JWS string.
///
/// Builds the JWT directly via base64url + ed25519-dalek
/// rather than going through `jsonwebtoken::EncodingKey`.
/// Reason: `EncodingKey::from_ed_der` expects PKCS#8-wrapped
/// DER, not the raw 32-byte Ed25519 seed; assembling the
/// PKCS#8 envelope inline would be 16 magic bytes of
/// noise. The alternative used here — sign the
/// `b64url(header).b64url(payload)` bytes directly with
/// `ed25519_dalek::Signer` and base64-encode the
/// signature — produces the same compact JWS that
/// `jsonwebtoken::decode` consumes.
pub(super) fn sign_access_token(sk: &SigningKey, kid: &str, claims: &TestAccessClaims) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::Signer;

    // JWS Header. JSON form `{"alg":"EdDSA","typ":"JWT","kid":"..."}`.
    // Field ordering doesn't matter for verify (the verifier
    // parses the JSON, not the bytes), but we keep it stable
    // for test readability.
    let header_json = format!(
        r#"{{"alg":"EdDSA","typ":"JWT","kid":"{kid}"}}"#,
        kid = kid,
    );
    let payload_json = serde_json::to_string(claims).expect("serialize claims");

    let header_b64  = URL_SAFE_NO_PAD.encode(header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);

    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = sk.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

/// Mirror of production's `AccessTokenClaims` for test
/// use. Keeps tests decoupled from the production
/// claims struct's serde shape; only needs to satisfy
/// `verify`'s expected claims (iss, aud, exp, plus the
/// cesauth-specific scope/cid/sub/jti).
#[derive(Debug, Serialize)]
pub(super) struct TestAccessClaims {
    pub(super) iss:   String,
    pub(super) aud:   String,
    pub(super) sub:   String,
    pub(super) cid:   String,
    pub(super) scope: String,
    pub(super) jti:   String,
    pub(super) iat:   i64,
    pub(super) exp:   i64,
}

pub(super) fn make_claims() -> TestAccessClaims {
    TestAccessClaims {
        iss:   ISS.into(),
        aud:   AUD.into(),
        sub:   "user_alice".into(),
        cid:   "client_X".into(),
        scope: "openid email".into(),
        jti:   "jti_abc".into(),
        iat:   100,
        // exp is checked against *system clock* by
        // `verify`'s Validation (jsonwebtoken doesn't
        // let us pin "now" — leeway is the only knob).
        // Set to year 4001 so these tests don't need
        // to be revisited in any reasonable future.
        // (`introspect_token`'s `now_unix` parameter
        // controls only the refresh-token freshness
        // check; access-token exp is current-time-based.)
        exp:   64_060_588_800,
    }
}

#[tokio::test]
async fn empty_keys_returns_inactive() {
    // No active signing keys at all → access path
    // returns None (deployment misconfigured); the
    // refresh fallback rejects the not-a-refresh-
    // token input; overall response is inactive.
    let store = StubFamilyStore::default();
    let resp = introspect_token(
        &store, &[], ISS, 30,
        &IntrospectInput {
            token: "eyJhbGc.payload.sig",
            hint:  Some(TokenTypeHint::AccessToken),
            now_unix: 200,
        },
    ).await.unwrap();
    assert!(!resp.active,
        "empty active-key set must yield inactive (deployment misconfigured)");
}

#[tokio::test]
async fn refresh_path_isolated_from_empty_access_keys() {
    // Failure isolation between paths: a missing
    // signing-key configuration must not break
    // refresh-token introspection. Pins that the
    // empty-access-keys condition only affects the
    // access-token path.
    let store = StubFamilyStore::default();
    install_family(&store, "fam_iso", "user_iso", "client_iso",
                   "jti_iso", &["openid"]).await;

    let token = encode_token("fam_iso", "jti_iso", 999_999);
    let resp = introspect_token(
        &store, &[], ISS, 30,
        &IntrospectInput {
            token: &token,
            hint:  Some(TokenTypeHint::RefreshToken),
            now_unix: 200,
        },
    ).await.unwrap();
    assert!(resp.active,
        "refresh-token introspection must work even when the access-token \
         key set is empty — failure isolation between the two paths");
}

#[tokio::test]
async fn single_key_match_verifies_active() {
    // The v0.38.0 baseline: one key in the active
    // set, token signed by that key. Verifies with
    // claims surfaced in the response.
    let (sk, vk) = keypair_from_seed(1);
    let token = sign_access_token(&sk, "k1", &make_claims());
    let pub_bytes = vk.to_bytes();
    let keys = vec![IntrospectionKey { kid: "k1", public_key_raw: &pub_bytes }];

    let store = StubFamilyStore::default();
    let resp = introspect_token(
        &store, &keys, ISS, 30,
        &IntrospectInput {
            token: &token,
            hint:  Some(TokenTypeHint::AccessToken),
            now_unix: 200,
        },
    ).await.unwrap();
    assert!(resp.active, "kid-matched single key must verify");
    assert_eq!(resp.sub.as_deref(),        Some("user_alice"));
    assert_eq!(resp.scope.as_deref(),      Some("openid email"));
    assert_eq!(resp.token_type.as_deref(), Some("Bearer"));
}

#[tokio::test]
async fn multi_key_kid_directed_lookup_picks_correct_key() {
    // The headline case: signing-key rotation grace
    // period. Two active keys, k_old and k_new. A
    // token was signed by k_old (kid=k_old). The
    // active set is ordered [k_new, k_old] (newest
    // first, matching how list_active typically
    // orders). Pre-v0.41.0 introspection would have
    // tried only k_new, failed verify, reported
    // inactive — the bug. Post-v0.41.0 the kid
    // header points at k_old, kid-directed lookup
    // selects k_old, verify succeeds.
    let (sk_old,  vk_old) = keypair_from_seed(1);
    let (_sk_new, vk_new) = keypair_from_seed(2);
    let token = sign_access_token(&sk_old, "k_old", &make_claims());

    let pub_old = vk_old.to_bytes();
    let pub_new = vk_new.to_bytes();
    let keys = vec![
        IntrospectionKey { kid: "k_new", public_key_raw: &pub_new },
        IntrospectionKey { kid: "k_old", public_key_raw: &pub_old },
    ];

    let store = StubFamilyStore::default();
    let resp = introspect_token(
        &store, &keys, ISS, 30,
        &IntrospectInput {
            token: &token,
            hint:  Some(TokenTypeHint::AccessToken),
            now_unix: 200,
        },
    ).await.unwrap();
    assert!(resp.active,
        "token signed by older active key must verify via kid-directed lookup");
    assert_eq!(resp.sub.as_deref(), Some("user_alice"));
}

#[tokio::test]
async fn multi_key_try_each_fallback_when_kid_unknown() {
    // The token's kid header points at a kid that
    // isn't in the active set. The try-each fallback
    // walks all active keys; if any of them verifies,
    // the token is active. In this test the token is
    // signed by k1 but its header claims kid=k_other;
    // k1 is in the active set, so try-each finds it
    // and reports active.
    //
    // (Note: a real cesauth-issued token never has a
    // kid pointing at a non-active key — cesauth sets
    // the kid in the same path that consults the
    // active set. The test exercises defensive code.)
    let (sk, vk) = keypair_from_seed(1);
    let token = sign_access_token(&sk, "k_other_typo", &make_claims());
    let pub_bytes = vk.to_bytes();
    let keys = vec![IntrospectionKey { kid: "k1", public_key_raw: &pub_bytes }];

    let store = StubFamilyStore::default();
    let resp = introspect_token(
        &store, &keys, ISS, 30,
        &IntrospectInput {
            token: &token,
            hint:  Some(TokenTypeHint::AccessToken),
            now_unix: 200,
        },
    ).await.unwrap();
    assert!(resp.active,
        "kid mismatch must fall through to try-each, not stop at lookup miss");
}

#[tokio::test]
async fn forged_kid_with_unknown_signature_rejected() {
    // Adversarial: token claims kid=k_known but is
    // actually signed by an attacker key the active
    // set doesn't have. kid-directed lookup picks
    // k_known, verify fails (signature doesn't match
    // k_known's public key), try-each walks the
    // remaining keys (just k_known again — no-op),
    // returns inactive. The cryptographic check is
    // the gate; the kid header is only a hint.
    let (sk_attacker, _vk_attacker) = keypair_from_seed(99);
    let (_sk_known,    vk_known)    = keypair_from_seed(1);

    let token = sign_access_token(&sk_attacker, "k_known", &make_claims());
    let pub_known = vk_known.to_bytes();
    let keys = vec![IntrospectionKey { kid: "k_known", public_key_raw: &pub_known }];

    let store = StubFamilyStore::default();
    let resp = introspect_token(
        &store, &keys, ISS, 30,
        &IntrospectInput {
            token: &token,
            hint:  Some(TokenTypeHint::AccessToken),
            now_unix: 200,
        },
    ).await.unwrap();
    assert!(!resp.active,
        "forged kid with bogus signature MUST report inactive — \
         kid is untrusted; signature is the gate");
}

#[tokio::test]
async fn token_signed_by_retired_key_reports_inactive() {
    // The flip side of rotation: once a key has been
    // retired (removed from the active set), tokens
    // signed by it must NOT verify. This is the
    // property that makes rotation actually rotate.
    // After the operator pulls k_old out, the only
    // active key is k_new; a token still bearing
    // kid=k_old can no longer be introspected as
    // active.
    let (sk_old,  _vk_old) = keypair_from_seed(1);
    let (_sk_new,  vk_new) = keypair_from_seed(2);
    let token = sign_access_token(&sk_old, "k_old", &make_claims());
    let pub_new = vk_new.to_bytes();
    let keys = vec![IntrospectionKey { kid: "k_new", public_key_raw: &pub_new }];

    let store = StubFamilyStore::default();
    let resp = introspect_token(
        &store, &keys, ISS, 30,
        &IntrospectInput {
            token: &token,
            hint:  Some(TokenTypeHint::AccessToken),
            now_unix: 200,
        },
    ).await.unwrap();
    assert!(!resp.active,
        "token signed by retired key MUST report inactive — \
         rotation removes the verify path");
}
