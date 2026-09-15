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
    map: std::sync::Mutex<std::collections::HashMap<crate::types::FamilyId, crate::ports::store::FamilyState>>,
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
            expired:           None,
            auth_time:         init.auth_time,
        });
        Ok(())
    }

    async fn rotate(
        &self, _family_id: &crate::types::FamilyId, _presented_jti: &crate::types::Jti, _new_jti: &crate::types::Jti, _now_unix: i64,
        _lifetime: &crate::ports::store::RefreshLifetime,
    ) -> PortResult<RotateOutcome> {
        unimplemented!("introspect_token must not call rotate")
    }

    async fn peek(&self, family_id: &crate::types::FamilyId) -> PortResult<Option<FamilyState>> {
        let m = self.map.lock().unwrap();
        Ok(m.get(family_id).cloned())
    }

    async fn revoke(&self, family_id: &crate::types::FamilyId, now_unix: i64) -> PortResult<()> {
        let mut m = self.map.lock().unwrap();
        if let Some(f) = m.get_mut(family_id) {
            if f.revoked_at.is_none() {
                f.revoked_at = Some(now_unix);
            }
        }
        Ok(())
    }
}

/// The RFC 139 refresh-token format: `base64url("{family_id}.{jti}")`.
fn encode_token(family_id: &str, jti: &str) -> String {
    let raw = format!("{family_id}.{jti}");
    URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

const FAKE_PUBKEY: [u8; 32] = [0u8; 32];
const ISS: &str = "https://cesauth.example";
const AUD: &str = "client_X";  // RFC 009: AUD must differ from ISS (prod: aud=client.id)

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
        family_id: crate::types::FamilyId::from_storage(family_id),
        user_id: crate::types::UserId::from_storage(user_id),
        client_id: crate::types::ClientId::from_storage(client_id),
        scopes:    scopes.iter().map(|s| s.to_string()).collect(),
        first_jti: crate::types::Jti::from_storage(first_jti),
        now_unix:  100,
        auth_time: 0,
    }).await.unwrap();
}

#[tokio::test]
async fn refresh_token_active_returns_active_response_with_claims() {
    let store = StubFamilyStore::default();
    install_family(&store, "fam1", "user_alice", "client_X",
                   "jti_current", &["openid", "profile"]).await;

    let token = encode_token("fam1", "jti_current");
    let resp = introspect_token(
        &store, &fake_keys(), ISS, 30,
        &IntrospectInput {
            token: &token,
            hint:  Some(TokenTypeHint::RefreshToken),
            now_unix: 200, refresh_lifetime: test_lifetime()
        },
    ).await.unwrap();

    assert!(resp.active, "current refresh token must be active");
    assert_eq!(resp.client_id.as_deref(), Some("client_X"));
    assert_eq!(resp.sub.as_deref(),       Some("user_alice"));
    assert_eq!(resp.jti.as_deref(),       Some("jti_current"));
    assert_eq!(resp.scope.as_deref(),     Some("openid profile"));
    assert_eq!(resp.token_type, None,
        "refresh tokens have no Bearer Authorization-header role");
    // RFC 139 §9.4: exp is the family's earlier deadline under the policy —
    // created and last rotated at 100, so 100 + the 14-day idle window —
    // never a value carried by the token, which no longer has one.
    assert_eq!(resp.exp, Some(100 + crate::ports::store::DEFAULT_REFRESH_IDLE_TIMEOUT_SECS));
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
        m.get_mut(&crate::types::FamilyId::from_storage("fam1")).unwrap().retired_jtis.push(crate::types::Jti::from_storage("old_jti"));
    }

    let token = encode_token("fam1", "old_jti");
    let resp = introspect_token(
        &store, &fake_keys(), ISS, 30,
        &IntrospectInput { token: &token, hint: Some(TokenTypeHint::RefreshToken), now_unix: 200, refresh_lifetime: test_lifetime()  },
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
    store.revoke(&crate::types::FamilyId::from_storage("fam_dead"), 150).await.unwrap();

    let token = encode_token("fam_dead", "j1");
    let resp = introspect_token(
        &store, &fake_keys(), ISS, 30,
        &IntrospectInput { token: &token, hint: Some(TokenTypeHint::RefreshToken), now_unix: 200, refresh_lifetime: test_lifetime()  },
    ).await.unwrap();

    assert!(!resp.active,
        "revoked family must report inactive even though the jti is the family's current");
    assert!(resp.client_id.is_none(),
        "RFC 7662 §2.2 — no other claims on inactive");
}

#[tokio::test]
async fn refresh_token_unknown_family_is_inactive() {
    let store = StubFamilyStore::default();
    let token = encode_token("never_existed", "j1");
    let resp = introspect_token(
        &store, &fake_keys(), ISS, 30,
        &IntrospectInput { token: &token, hint: Some(TokenTypeHint::RefreshToken), now_unix: 200, refresh_lifetime: test_lifetime()  },
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
        &store, &fake_keys(), ISS, 30,
        &IntrospectInput { token: "this is not a valid token", hint: None, now_unix: 200, refresh_lifetime: test_lifetime()  },
    ).await.unwrap();

    assert!(!resp.active);
}

#[tokio::test]
async fn empty_token_is_inactive_not_error() {
    let store = StubFamilyStore::default();
    let resp = introspect_token(
        &store, &fake_keys(), ISS, 30,
        &IntrospectInput { token: "", hint: None, now_unix: 200, refresh_lifetime: test_lifetime()  },
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

    let token = encode_token("fam2", "jti_current");
    let resp = introspect_token(
        &store, &fake_keys(), ISS, 30,
        &IntrospectInput {
            token: &token,
            hint: Some(TokenTypeHint::AccessToken),  // wrong hint
            now_unix: 200, refresh_lifetime: test_lifetime()
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
        Some("rs.example.com".into()),
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


// ─── Nested test groups split into sibling files (v0.76.0) ─────────────
//
// Each module is a logical scope of tests originally nested as
// `mod foo { ... }` in this file. The split brings every file under
// the 500-ELOC dev-guideline threshold and keeps the test groups
// independently editable.
mod multi_key;
mod extract_kid_tests;
mod rate_limit;
mod refresh_ext;
mod audience_gate;
mod rfc009_aud_correctness;

// =====================================================================
// RFC 139 — introspection under the lifetime policy (tests 10–13)
// =====================================================================

/// The shipped defaults: 30 d absolute, 14 d idle. Existing tests' families
/// are created at 100 and introspected by 700, inside both windows.
fn test_lifetime() -> crate::ports::store::RefreshLifetime {
    crate::ports::store::RefreshLifetime::new(2_592_000, crate::ports::store::DEFAULT_REFRESH_IDLE_TIMEOUT_SECS).unwrap()
}

fn rfc139_policy(absolute: i64, idle: i64) -> crate::ports::store::RefreshLifetime {
    crate::ports::store::RefreshLifetime::new(absolute, idle).unwrap()
}

async fn rfc139_introspect(store: &StubFamilyStore, token: &str, now_unix: i64, p: crate::ports::store::RefreshLifetime) -> IntrospectionResponse {
    introspect_token(store, &fake_keys(), ISS, 30, &IntrospectInput {
        token, hint: Some(TokenTypeHint::RefreshToken), now_unix, refresh_lifetime: p,
    }).await.unwrap()
}

/// Test 10 — a live family is active, and `exp` is the earlier deadline.
#[tokio::test]
async fn rfc139_live_family_reports_the_earlier_deadline_as_exp() {
    let store = StubFamilyStore::default();
    install_family(&store, "fam139", "u", "c", "j", &["openid"]).await; // created 100
    let token = encode_token("fam139", "j");

    // absolute 100 + 1_000 = 1_100; idle 100 + 300 = 400 → exp 400
    let resp = rfc139_introspect(&store, &token, 399, rfc139_policy(1_000, 300)).await;
    assert!(resp.active);
    assert_eq!(resp.exp, Some(400));

    // idle disabled → only the absolute term
    let resp = rfc139_introspect(&store, &token, 399, rfc139_policy(1_000, 0)).await;
    assert!(resp.active);
    assert_eq!(resp.exp, Some(1_100));
}

/// Test 11 — a family past a deadline that nothing has rotated is inactive
/// `Expired`, and introspection wrote nothing: `revoked_at` stays `None`.
#[tokio::test]
async fn rfc139_unrotated_family_past_a_deadline_is_expired_and_untouched() {
    use crate::oidc::introspect::FamilyClassification;
    let store = StubFamilyStore::default();
    install_family(&store, "fam139", "u", "c", "j", &["openid"]).await; // created 100
    let token = encode_token("fam139", "j");

    for (now, p) in [(400, rfc139_policy(1_000, 300)), (1_100, rfc139_policy(1_000, 0))] {
        let resp = rfc139_introspect(&store, &token, now, p).await;
        assert!(!resp.active, "past a deadline at {now}");
        assert!(resp.exp.is_none(), "inactive responses carry no claims");
        let ext = resp.x_cesauth.expect("x_cesauth on an expired family");
        assert_eq!(ext.family_state, Some(FamilyClassification::Expired));
        assert_eq!(ext.revoked_at, None, "not revoked: nothing wrote");
        assert_eq!(ext.revoke_reason, None);
    }
    let fam = store.peek(&crate::types::FamilyId::from_storage("fam139")).await.unwrap().unwrap();
    assert_eq!(fam.revoked_at, None, "introspection must not revoke");
    assert_eq!(fam.expired, None, "introspection must not record expiry");
}

/// Test 12 — a family the store already expired is `Expired`, not
/// `Revoked`/`Explicit`, even when the clock alone would call it live.
#[tokio::test]
async fn rfc139_store_expired_family_is_expired_not_explicitly_revoked() {
    use crate::oidc::introspect::FamilyClassification;
    let store = StubFamilyStore::default();
    install_family(&store, "fam139", "u", "c", "j", &["openid"]).await;
    {
        let mut m = store.map.lock().unwrap();
        let f = m.get_mut(&crate::types::FamilyId::from_storage("fam139")).unwrap();
        f.revoked_at = Some(500);
        f.expired    = Some(crate::ports::store::LifetimeExpiry::Absolute);
    }
    let resp = rfc139_introspect(&store, &encode_token("fam139", "j"), 600, test_lifetime()).await;
    assert!(!resp.active);
    let ext = resp.x_cesauth.unwrap();
    assert_eq!(ext.family_state, Some(FamilyClassification::Expired));
    assert_eq!(ext.revoked_at, Some(500), "a stored revoked_at is surfaced");
    assert_eq!(ext.revoke_reason, None, "an expiry is not an explicit revocation");
}

/// Test 13 (introspection decoder) — exactly two parts.
#[test]
fn rfc139_introspection_decoder_accepts_exactly_two_parts() {
    assert!(super::decode_refresh_token(&encode_token("fam", "jti")).is_some());
    assert!(super::decode_refresh_token(&URL_SAFE_NO_PAD.encode("fam.jti.999999")).is_none(), "three parts");
    assert!(super::decode_refresh_token(&URL_SAFE_NO_PAD.encode("fam")).is_none(), "one part");
}
