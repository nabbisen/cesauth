//! Unit tests for `service::introspect::introspect_token`.
//!
//! These tests exercise the **refresh-token introspection path**
//! using the in-memory `RefreshTokenFamilyStore` from
//! adapter-test. The access-token (JWT) path is not tested here
//! because it would require a real Ed25519 keypair fixture; the
//! `verify` function it delegates to has its own coverage in the
//! jwt module.

use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::ports::store::{FamilyInit, RefreshTokenFamilyStore};

/// Stub family store that we control directly. Mirrors the
/// in-memory adapter's surface but without the dev-dep cycle
/// (cesauth-adapter-test depends on cesauth-core, so core
/// can't depend back on adapter-test for tests).
#[derive(Default)]
struct StubFamilyStore {
    map: std::sync::Mutex<std::collections::HashMap<String, crate::ports::store::FamilyState>>,
}

use crate::ports::{PortError, PortResult};
use crate::ports::store::{FamilyState, RotateOutcome};

impl RefreshTokenFamilyStore for StubFamilyStore {
    async fn init(&self, init: &FamilyInit) -> PortResult<()> {
        let mut m = self.map.lock().unwrap();
        if m.contains_key(&init.family_id) {
            return Err(PortError::Conflict);
        }
        m.insert(init.family_id.clone(), FamilyState {
            family_id:       init.family_id.clone(),
            user_id:         init.user_id.clone(),
            client_id:       init.client_id.clone(),
            scopes:          init.scopes.clone(),
            current_jti:     init.first_jti.clone(),
            retired_jtis:    Vec::new(),
            created_at:      init.now_unix,
            last_rotated_at: init.now_unix,
            revoked_at:      None,
            reused_jti:        None,
            reused_at:         None,
            reuse_was_retired: None,
        });
        Ok(())
    }

    async fn rotate(
        &self, _family_id: &str, _presented_jti: &str, _new_jti: &str, _now_unix: i64,
    ) -> PortResult<RotateOutcome> {
        unimplemented!("introspect_token must not call rotate")
    }

    async fn peek(&self, family_id: &str) -> PortResult<Option<FamilyState>> {
        let m = self.map.lock().unwrap();
        Ok(m.get(family_id).cloned())
    }

    async fn revoke(&self, family_id: &str, now_unix: i64) -> PortResult<()> {
        let mut m = self.map.lock().unwrap();
        if let Some(f) = m.get_mut(family_id) {
            if f.revoked_at.is_none() {
                f.revoked_at = Some(now_unix);
            }
        }
        Ok(())
    }
}

fn encode_token(family_id: &str, jti: &str, exp: i64) -> String {
    let raw = format!("{family_id}.{jti}.{exp}");
    URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

const FAKE_PUBKEY: [u8; 32] = [0u8; 32];
const ISS: &str = "https://cesauth.example";
const AUD: &str = "https://cesauth.example";

/// **v0.41.0** — Single-key introspection-key slice, used
/// by all the existing refresh-token tests. v0.41.0
/// changed `introspect_token`'s signature to take
/// `&[IntrospectionKey<'_>]`; the tests don't exercise
/// the multi-key path here (they exercise the
/// access-token path on the multi-key tests below), so
/// the helper just produces a one-element slice using
/// `FAKE_PUBKEY`. The refresh-token paths these tests
/// hit don't consult the keys at all — `FAKE_PUBKEY`
/// being all-zeros is fine.
fn fake_keys() -> Vec<crate::oidc::introspect::IntrospectionKey<'static>> {
    vec![crate::oidc::introspect::IntrospectionKey {
        kid:            "k1",
        public_key_raw: &FAKE_PUBKEY,
    }]
}

async fn install_family(
    store: &StubFamilyStore,
    family_id: &str,
    user_id: &str,
    client_id: &str,
    first_jti: &str,
    scopes: &[&str],
) {
    store.init(&FamilyInit {
        family_id: family_id.into(),
        user_id:   user_id.into(),
        client_id: client_id.into(),
        scopes:    scopes.iter().map(|s| s.to_string()).collect(),
        first_jti: first_jti.into(),
        now_unix:  100,
    }).await.unwrap();
}

#[tokio::test]
async fn refresh_token_active_returns_active_response_with_claims() {
    let store = StubFamilyStore::default();
    install_family(&store, "fam1", "user_alice", "client_X",
                   "jti_current", &["openid", "profile"]).await;

    let token = encode_token("fam1", "jti_current", 999_999);
    let resp = introspect_token(
        &store, &fake_keys(), ISS, AUD, 30,
        &IntrospectInput {
            token: &token,
            hint:  Some(TokenTypeHint::RefreshToken),
            now_unix: 200,
        },
    ).await.unwrap();

    assert!(resp.active, "current refresh token must be active");
    assert_eq!(resp.client_id.as_deref(), Some("client_X"));
    assert_eq!(resp.sub.as_deref(),       Some("user_alice"));
    assert_eq!(resp.jti.as_deref(),       Some("jti_current"));
    assert_eq!(resp.scope.as_deref(),     Some("openid profile"));
    assert_eq!(resp.token_type, None,
        "refresh tokens have no Bearer Authorization-header role");
    // exp comes from the encoded token's third field.
    assert_eq!(resp.exp, Some(999_999));
}

#[tokio::test]
async fn refresh_token_with_retired_jti_is_inactive_with_no_other_claims() {
    // The privacy MUST from RFC 7662 §2.2: an inactive
    // response carries no other claims. Pinning here that
    // the claim fields are all None.
    let store = StubFamilyStore::default();
    install_family(&store, "fam1", "u", "c", "current_jti", &["openid"]).await;
    // Manually populate retired_jtis to simulate a rotation
    // having happened.
    {
        let mut m = store.map.lock().unwrap();
        m.get_mut("fam1").unwrap().retired_jtis.push("old_jti".into());
    }

    let token = encode_token("fam1", "old_jti", 999_999);
    let resp = introspect_token(
        &store, &fake_keys(), ISS, AUD, 30,
        &IntrospectInput { token: &token, hint: Some(TokenTypeHint::RefreshToken), now_unix: 200 },
    ).await.unwrap();

    assert!(!resp.active);
    // The privacy invariant: nothing else may leak.
    assert!(resp.scope.is_none(),     "leak via scope");
    assert!(resp.client_id.is_none(), "leak via client_id");
    assert!(resp.sub.is_none(),       "leak via sub");
    assert!(resp.jti.is_none(),       "leak via jti");
    assert!(resp.exp.is_none(),       "leak via exp");
    assert!(resp.iat.is_none(),       "leak via iat");
}

#[tokio::test]
async fn refresh_token_revoked_family_is_inactive() {
    let store = StubFamilyStore::default();
    install_family(&store, "fam_dead", "u", "c", "j1", &["openid"]).await;
    store.revoke("fam_dead", 150).await.unwrap();

    let token = encode_token("fam_dead", "j1", 999_999);
    let resp = introspect_token(
        &store, &fake_keys(), ISS, AUD, 30,
        &IntrospectInput { token: &token, hint: Some(TokenTypeHint::RefreshToken), now_unix: 200 },
    ).await.unwrap();

    assert!(!resp.active,
        "revoked family must report inactive even though the jti is the family's current");
    assert!(resp.client_id.is_none(),
        "RFC 7662 §2.2 — no other claims on inactive");
}

#[tokio::test]
async fn refresh_token_unknown_family_is_inactive() {
    let store = StubFamilyStore::default();
    let token = encode_token("never_existed", "j1", 999_999);
    let resp = introspect_token(
        &store, &fake_keys(), ISS, AUD, 30,
        &IntrospectInput { token: &token, hint: Some(TokenTypeHint::RefreshToken), now_unix: 200 },
    ).await.unwrap();

    assert!(!resp.active);
}

#[tokio::test]
async fn malformed_token_is_inactive_not_error() {
    // RFC 7662 §2.2 requires that ANY token fail to a
    // {"active": false} response — including malformed
    // input. We do not return 400 for malformed tokens
    // (that would let an attacker probe whether a token
    // was structurally valid).
    let store = StubFamilyStore::default();
    let resp = introspect_token(
        &store, &fake_keys(), ISS, AUD, 30,
        &IntrospectInput { token: "this is not a valid token", hint: None, now_unix: 200 },
    ).await.unwrap();

    assert!(!resp.active);
}

#[tokio::test]
async fn empty_token_is_inactive_not_error() {
    let store = StubFamilyStore::default();
    let resp = introspect_token(
        &store, &fake_keys(), ISS, AUD, 30,
        &IntrospectInput { token: "", hint: None, now_unix: 200 },
    ).await.unwrap();
    assert!(!resp.active);
}

#[tokio::test]
async fn hint_access_with_actually_refresh_token_falls_through_to_refresh_check() {
    // The hint is advisory per RFC 7662 §2.1: even if the
    // client says access_token, we try refresh as a
    // fallback before declaring inactive.
    let store = StubFamilyStore::default();
    install_family(&store, "fam2", "u", "c", "jti_current", &["openid"]).await;

    let token = encode_token("fam2", "jti_current", 999_999);
    let resp = introspect_token(
        &store, &fake_keys(), ISS, AUD, 30,
        &IntrospectInput {
            token: &token,
            hint: Some(TokenTypeHint::AccessToken),  // wrong hint
            now_unix: 200,
        },
    ).await.unwrap();

    assert!(resp.active,
        "wrong hint must not prevent successful introspection \
         (RFC 7662 §2.1: hint is advisory)");
}

#[tokio::test]
async fn token_type_hint_parse_recognizes_registered_values() {
    assert_eq!(TokenTypeHint::parse("access_token"),  Some(TokenTypeHint::AccessToken));
    assert_eq!(TokenTypeHint::parse("refresh_token"), Some(TokenTypeHint::RefreshToken));
}

#[tokio::test]
async fn token_type_hint_parse_ignores_unknown_values() {
    // RFC 7662 §2.1: unrecognized hints should be ignored
    // (return None so the caller falls back to "try both").
    assert_eq!(TokenTypeHint::parse("id_token"),       None);
    assert_eq!(TokenTypeHint::parse("garbage"),        None);
    assert_eq!(TokenTypeHint::parse(""),               None);
    assert_eq!(TokenTypeHint::parse("access_tokens"),  None);
}

// =====================================================================
// IntrospectionResponse privacy constructor invariant
// =====================================================================

#[test]
fn inactive_response_has_no_claim_fields_set() {
    let r = IntrospectionResponse::inactive();
    assert!(!r.active);
    assert!(r.scope.is_none());
    assert!(r.client_id.is_none());
    assert!(r.token_type.is_none());
    assert!(r.exp.is_none());
    assert!(r.iat.is_none());
    assert!(r.sub.is_none());
    assert!(r.jti.is_none());
}

#[test]
fn inactive_response_serializes_with_only_active_field() {
    // The skip_serializing_if attributes mean the JSON
    // produced for an inactive response is just
    // {"active":false}. This is the wire-level pin of the
    // RFC 7662 §2.2 MUST.
    let r = IntrospectionResponse::inactive();
    let json = serde_json::to_string(&r).unwrap();
    assert_eq!(json, r#"{"active":false}"#,
        "inactive response wire form must be exactly bare-active per RFC 7662 §2.2");
}

#[test]
fn active_access_response_includes_token_type_bearer() {
    let r = IntrospectionResponse::active_access(
        "openid email".into(), "client_X".into(),
        "user_alice".into(),   "jti_abc".into(),
        100, 200,
    );
    assert_eq!(r.token_type.as_deref(), Some("Bearer"));
    assert!(r.active);
}

#[test]
fn active_refresh_response_omits_token_type() {
    // Refresh tokens aren't HTTP Bearer; their use is
    // scoped to /token. Don't claim a Bearer role.
    let r = IntrospectionResponse::active_refresh(
        "openid".into(), "client_X".into(),
        "user_alice".into(), "jti_curr".into(),
        100, 200,
    );
    assert!(r.token_type.is_none());
    assert!(r.active);
}

// =====================================================================
// v0.41.0 — multi-key access-token introspection (ADR-014 §Q4)
// =====================================================================
//
// These tests exercise the kid-directed lookup + try-each
// fallback. Real Ed25519 signing+verification works in
// tests because v0.41.0 enabled jsonwebtoken's
// `rust_crypto` feature (the previous bare `ed25519-dalek`
// opt-dep didn't install a CryptoProvider, so verify
// would have panicked at runtime). See workspace
// `Cargo.toml` for the rationale.

mod multi_key {
    use super::*;
    use crate::oidc::introspect::IntrospectionKey;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use serde::Serialize;

    /// Test harness: a deterministic Ed25519 keypair from
    /// a fixed 32-byte seed. Two different seeds give two
    /// different keypairs, which is what we need for the
    /// rotation-grace-period scenarios.
    fn keypair_from_seed(seed: u8) -> (SigningKey, VerifyingKey) {
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
    fn sign_access_token(sk: &SigningKey, kid: &str, claims: &TestAccessClaims) -> String {
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
    struct TestAccessClaims {
        iss:   String,
        aud:   String,
        sub:   String,
        cid:   String,
        scope: String,
        jti:   String,
        iat:   i64,
        exp:   i64,
    }

    fn make_claims() -> TestAccessClaims {
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
            &store, &[], ISS, AUD, 30,
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
            &store, &[], ISS, AUD, 30,
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
            &store, &keys, ISS, AUD, 30,
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
            &store, &keys, ISS, AUD, 30,
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
            &store, &keys, ISS, AUD, 30,
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
            &store, &keys, ISS, AUD, 30,
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
            &store, &keys, ISS, AUD, 30,
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
}

// =====================================================================
// v0.41.0 — extract_kid helper tests
// =====================================================================

mod extract_kid_tests {
    use crate::jwt::signer::extract_kid;
    use ed25519_dalek::{Signer, SigningKey};

    /// Same compact-JWS construction as the multi_key
    /// tests above: build base64url(header) +
    /// base64url(payload) + base64url(ed25519 signature)
    /// directly so we stay independent of
    /// jsonwebtoken's EncodingKey plumbing (which
    /// requires PKCS#8 DER wrapping rather than raw
    /// 32-byte seed).
    fn sign_with_kid(kid: Option<&str>) -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let header_json = match kid {
            Some(k) => format!(r#"{{"alg":"EdDSA","typ":"JWT","kid":"{k}"}}"#),
            None    => r#"{"alg":"EdDSA","typ":"JWT"}"#.to_owned(),
        };
        let payload_json = "{}";
        let header_b64  = URL_SAFE_NO_PAD.encode(header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = sk.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }

    #[test]
    fn extracts_kid_when_present() {
        let token = sign_with_kid(Some("test-kid-123"));
        assert_eq!(extract_kid(&token).as_deref(), Some("test-kid-123"));
    }

    #[test]
    fn returns_none_when_kid_absent() {
        let token = sign_with_kid(None);
        assert!(extract_kid(&token).is_none(),
            "kid-less JWT must yield None: token={token}");
    }

    #[test]
    fn returns_none_on_garbage_input() {
        assert!(extract_kid("not-a-jwt").is_none());
        assert!(extract_kid("").is_none());
        assert!(extract_kid("a.b.c").is_none(),
            "three-part garbage must yield None");
        assert!(extract_kid("eyJxxx.eyJxxx").is_none(),
            "two-part garbage must yield None");
    }

    #[test]
    fn does_not_verify_signature() {
        // Tamper with signature segment. extract_kid MUST
        // still return the kid because it doesn't touch
        // the signature.
        let mut token = sign_with_kid(Some("untouched"));
        let last_dot = token.rfind('.').unwrap();
        token.truncate(last_dot + 1);
        token.push_str("AAAAAAA");
        assert_eq!(extract_kid(&token).as_deref(), Some("untouched"),
            "extract_kid must not gate on signature validity");
    }
}
