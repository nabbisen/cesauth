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
        &store, &FAKE_PUBKEY, ISS, AUD, 30,
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
        &store, &FAKE_PUBKEY, ISS, AUD, 30,
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
        &store, &FAKE_PUBKEY, ISS, AUD, 30,
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
        &store, &FAKE_PUBKEY, ISS, AUD, 30,
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
        &store, &FAKE_PUBKEY, ISS, AUD, 30,
        &IntrospectInput { token: "this is not a valid token", hint: None, now_unix: 200 },
    ).await.unwrap();

    assert!(!resp.active);
}

#[tokio::test]
async fn empty_token_is_inactive_not_error() {
    let store = StubFamilyStore::default();
    let resp = introspect_token(
        &store, &FAKE_PUBKEY, ISS, AUD, 30,
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
        &store, &FAKE_PUBKEY, ISS, AUD, 30,
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
