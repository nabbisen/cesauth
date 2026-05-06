//! Unit tests for `service::revoke::revoke_refresh_token`.

use super::*;
use crate::error::CoreError;
use crate::ports::PortResult;
use crate::ports::repo::ClientRepository;
use crate::ports::store::{
    AuthMethod, FamilyInit, FamilyState, RefreshTokenFamilyStore, RotateOutcome,
};
use crate::service::client_auth::sha256_hex;
use crate::types::OidcClient;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::cell::RefCell;
use std::collections::HashMap;

// =====================================================================
// Stubs
// =====================================================================

struct StubFamilyStore {
    families:           RefCell<HashMap<String, FamilyState>>,
    revoke_calls:       RefCell<Vec<String>>,
}

impl Default for StubFamilyStore {
    fn default() -> Self {
        Self {
            families:     RefCell::new(HashMap::new()),
            revoke_calls: RefCell::new(Vec::new()),
        }
    }
}

impl StubFamilyStore {
    fn install(&self, family_id: &str, client_id: &str) {
        self.families.borrow_mut().insert(family_id.to_owned(), FamilyState {
            family_id:       family_id.to_owned(),
            user_id:         "user_demo".into(),
            client_id:       client_id.to_owned(),
            scopes:          vec!["openid".into()],
            current_jti:     "jti_curr".into(),
            retired_jtis:    Vec::new(),
            created_at:      100,
            last_rotated_at: 100,
            revoked_at:      None,
            reused_jti:        None,
            reused_at:         None,
            reuse_was_retired: None,
        });
    }
}

impl RefreshTokenFamilyStore for StubFamilyStore {
    async fn init(&self, _: &FamilyInit) -> PortResult<()> {
        unimplemented!("revoke must not init")
    }
    async fn rotate(&self, _: &str, _: &str, _: &str, _: i64) -> PortResult<RotateOutcome> {
        unimplemented!("revoke must not rotate")
    }
    async fn peek(&self, family_id: &str) -> PortResult<Option<FamilyState>> {
        Ok(self.families.borrow().get(family_id).cloned())
    }
    async fn revoke(&self, family_id: &str, _now: i64) -> PortResult<()> {
        self.revoke_calls.borrow_mut().push(family_id.to_owned());
        if let Some(s) = self.families.borrow_mut().get_mut(family_id) {
            s.revoked_at = Some(200);
        }
        Ok(())
    }
}

struct StubClients {
    map: HashMap<String, Option<String>>,
}

impl ClientRepository for StubClients {
    async fn find(&self, _: &str) -> PortResult<Option<OidcClient>> {
        unimplemented!("revoke must not call find")
    }
    async fn client_secret_hash(&self, client_id: &str) -> PortResult<Option<String>> {
        Ok(self.map.get(client_id).cloned().unwrap_or(None))
    }
    async fn create(&self, _: &OidcClient, _: Option<&str>) -> PortResult<()> {
        unimplemented!()
    }
}

fn clients_with_secret(client_id: &str, secret: &str) -> StubClients {
    let mut map = HashMap::new();
    map.insert(client_id.to_owned(), Some(sha256_hex(secret.as_bytes())));
    StubClients { map }
}

fn clients_public(client_id: &str) -> StubClients {
    let mut map = HashMap::new();
    map.insert(client_id.to_owned(), None);
    StubClients { map }
}

fn encode_token(family_id: &str, jti: &str) -> String {
    let raw = format!("{family_id}.{jti}.unused");
    URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

// =====================================================================
// Public-client paths
// =====================================================================

#[tokio::test]
async fn public_client_revokes_with_just_token_possession() {
    // RFC 7009 §2.1 allows public clients to revoke
    // by token possession without authentication. The
    // existing v0.27.0 behavior is preserved for
    // public clients.
    let store = StubFamilyStore::default();
    store.install("fam_pub", "public_client");
    let clients = clients_public("public_client");

    let token = encode_token("fam_pub", "jti_curr");
    let outcome = revoke_refresh_token(&store, &clients, &RevokeInput {
        token:         &token,
        hint:          None,
        client_id:     None,
        client_secret: None,
        now_unix:      200,
    }).await.unwrap();

    assert_eq!(outcome, RevokeOutcome::Revoked {
        family_id: "fam_pub".into(),
        client_id: "public_client".into(),
        auth_mode: RevokeAuthMode::PublicClient,
    });
    assert_eq!(store.revoke_calls.borrow().as_slice(), &["fam_pub".to_owned()]);
}

#[tokio::test]
async fn public_client_with_no_client_id_revokes_by_token_possession() {
    // Public client; request didn't bother to send
    // client_id. RFC 7009 allows this for public
    // clients. The cid-binding gate trivially holds
    // (no claimed client_id to mismatch), so revoke
    // proceeds.
    let store = StubFamilyStore::default();
    store.install("fam_pub", "public_client");
    let clients = clients_public("public_client");

    let token = encode_token("fam_pub", "jti_curr");
    let outcome = revoke_refresh_token(&store, &clients, &RevokeInput {
        token:         &token,
        hint:          None,
        client_id:     None,
        client_secret: None,
        now_unix:      200,
    }).await.unwrap();

    assert!(matches!(outcome, RevokeOutcome::Revoked { .. }),
        "no-client_id public-client revoke must succeed by token possession");
}

#[tokio::test]
async fn public_client_form_client_id_mismatch_returns_unauthorized() {
    // Public client claiming a different client_id
    // than the token's cid. Even though both are
    // public, the cid binding still applies — a
    // public client must not be able to revoke
    // another client's tokens. Without this gate,
    // any public client could enumerate-and-revoke
    // any other public client's tokens whose
    // family_ids leaked.
    let store = StubFamilyStore::default();
    store.install("fam_pub", "public_client");
    let clients = clients_public("public_client");

    let token = encode_token("fam_pub", "jti_curr");
    let outcome = revoke_refresh_token(&store, &clients, &RevokeInput {
        token:         &token,
        hint:          None,
        client_id:     Some("totally_different_app"),
        client_secret: None,
        now_unix:      200,
    }).await.unwrap();

    assert_eq!(outcome, RevokeOutcome::Unauthorized {
        reason: UnauthorizedReason::ClientIdCidMismatch,
    });
    assert!(store.revoke_calls.borrow().is_empty(),
        "cross-client public revoke must NOT touch the family DO");
}

// =====================================================================
// Confidential-client paths
// =====================================================================

#[tokio::test]
async fn confidential_client_with_correct_creds_revokes() {
    let store = StubFamilyStore::default();
    store.install("fam_conf", "conf_client");
    let clients = clients_with_secret("conf_client", "the_secret");

    let token = encode_token("fam_conf", "jti_curr");
    let outcome = revoke_refresh_token(&store, &clients, &RevokeInput {
        token:         &token,
        hint:          None,
        client_id:     Some("conf_client"),
        client_secret: Some("the_secret"),
        now_unix:      200,
    }).await.unwrap();

    assert_eq!(outcome, RevokeOutcome::Revoked {
        family_id: "fam_conf".into(),
        client_id: "conf_client".into(),
        auth_mode: RevokeAuthMode::ConfidentialClient,
    });
    assert_eq!(store.revoke_calls.borrow().len(), 1);
}

#[tokio::test]
async fn confidential_client_no_creds_returns_unauthorized() {
    // RFC 7009 §2.1 MUST: confidential clients MUST
    // authenticate. Cesauth refuses revocation
    // without credentials — but still 200 silent on
    // the wire (the worker handles wire format).
    let store = StubFamilyStore::default();
    store.install("fam_conf", "conf_client");
    let clients = clients_with_secret("conf_client", "the_secret");

    let token = encode_token("fam_conf", "jti_curr");
    let outcome = revoke_refresh_token(&store, &clients, &RevokeInput {
        token:         &token,
        hint:          None,
        client_id:     None,
        client_secret: None,
        now_unix:      200,
    }).await.unwrap();

    assert_eq!(outcome, RevokeOutcome::Unauthorized {
        reason: UnauthorizedReason::ConfidentialAuthFailed,
    });
    assert!(store.revoke_calls.borrow().is_empty(),
        "Unauthorized must NOT touch the family DO");
}

#[tokio::test]
async fn confidential_client_wrong_secret_returns_unauthorized() {
    let store = StubFamilyStore::default();
    store.install("fam_conf", "conf_client");
    let clients = clients_with_secret("conf_client", "the_secret");

    let token = encode_token("fam_conf", "jti_curr");
    let outcome = revoke_refresh_token(&store, &clients, &RevokeInput {
        token:         &token,
        hint:          None,
        client_id:     Some("conf_client"),
        client_secret: Some("wrong_secret"),
        now_unix:      200,
    }).await.unwrap();

    assert_eq!(outcome, RevokeOutcome::Unauthorized {
        reason: UnauthorizedReason::ConfidentialAuthFailed,
    });
    assert!(store.revoke_calls.borrow().is_empty());
}

#[tokio::test]
async fn confidential_client_cannot_revoke_other_clients_token() {
    // Cross-client cid binding: client_a authenticates
    // and tries to revoke a token belonging to
    // client_b. RFC 7009 §2: "the token was issued to
    // the client making the revocation request" —
    // mismatch fails this gate. Silent 200 to avoid
    // revealing cross-client token ownership.
    let store = StubFamilyStore::default();
    store.install("fam_other", "client_b");

    let mut map = HashMap::new();
    map.insert("client_a".to_owned(), Some(sha256_hex(b"secret_a")));
    map.insert("client_b".to_owned(), Some(sha256_hex(b"secret_b")));
    let clients = StubClients { map };

    let token = encode_token("fam_other", "jti_curr");
    let outcome = revoke_refresh_token(&store, &clients, &RevokeInput {
        token:         &token,
        hint:          None,
        client_id:     Some("client_a"),
        client_secret: Some("secret_a"),
        now_unix:      200,
    }).await.unwrap();

    assert_eq!(outcome, RevokeOutcome::Unauthorized {
        reason: UnauthorizedReason::ClientIdCidMismatch,
    });
    assert!(store.revoke_calls.borrow().is_empty(),
        "cross-client revoke MUST NOT touch the family DO");
}

// =====================================================================
// Boundary cases
// =====================================================================

#[tokio::test]
async fn malformed_token_returns_not_revocable() {
    let store = StubFamilyStore::default();
    let clients = clients_public("public_client");

    let outcome = revoke_refresh_token(&store, &clients, &RevokeInput {
        token:         "not-base64-or-anything",
        hint:          None,
        client_id:     None,
        client_secret: None,
        now_unix:      200,
    }).await.unwrap();

    assert_eq!(outcome, RevokeOutcome::NotRevocable);
}

#[tokio::test]
async fn empty_token_returns_not_revocable() {
    let store = StubFamilyStore::default();
    let clients = clients_public("public_client");

    let outcome = revoke_refresh_token(&store, &clients, &RevokeInput {
        token:         "",
        hint:          None,
        client_id:     None,
        client_secret: None,
        now_unix:      200,
    }).await.unwrap();

    assert_eq!(outcome, RevokeOutcome::NotRevocable);
}

#[tokio::test]
async fn unknown_family_returns_unknown_family() {
    // Token decodes but family doesn't exist (deleted,
    // never existed, or recycled family_id). Idempotent
    // no-op; same wire response as Revoked.
    let store = StubFamilyStore::default();
    // No family installed.
    let clients = clients_public("public_client");

    let token = encode_token("fam_ghost", "jti_curr");
    let outcome = revoke_refresh_token(&store, &clients, &RevokeInput {
        token:         &token,
        hint:          None,
        client_id:     None,
        client_secret: None,
        now_unix:      200,
    }).await.unwrap();

    assert_eq!(outcome, RevokeOutcome::UnknownFamily);
    assert!(store.revoke_calls.borrow().is_empty(),
        "UnknownFamily must NOT call revoke");
}

#[tokio::test]
async fn jwt_access_token_returns_not_revocable() {
    // A JWT (3-part base64 with dots) doesn't decode
    // through best_effort because best_effort
    // base64-decodes the WHOLE input as one blob, not
    // segment-by-segment. JWTs have unencoded `.`
    // separators that base64 doesn't accept. Result:
    // NotRevocable. RFC 7009 §2 allows servers to not
    // support access-token revocation.
    let store = StubFamilyStore::default();
    let clients = clients_public("public_client");

    let outcome = revoke_refresh_token(&store, &clients, &RevokeInput {
        token:         "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1c2VyIn0.signature",
        hint:          Some(TokenTypeHint::AccessToken),
        client_id:     None,
        client_secret: None,
        now_unix:      200,
    }).await.unwrap();

    assert_eq!(outcome, RevokeOutcome::NotRevocable);
}

// =====================================================================
// TokenTypeHint parsing
// =====================================================================

#[test]
fn token_type_hint_parses_recognized_values() {
    assert_eq!(TokenTypeHint::parse("access_token"),  Some(TokenTypeHint::AccessToken));
    assert_eq!(TokenTypeHint::parse("refresh_token"), Some(TokenTypeHint::RefreshToken));
}

#[test]
fn token_type_hint_returns_none_for_unknown() {
    // RFC 7009 §2.1 says the AS MAY ignore hints; we
    // return None so the worker treats it as
    // hint-absent.
    assert_eq!(TokenTypeHint::parse(""),                None);
    assert_eq!(TokenTypeHint::parse("bearer"),          None);
    assert_eq!(TokenTypeHint::parse("ACCESS_TOKEN"),    None,
        "case-sensitive per RFC 7009 §2.1");
}

// =====================================================================
// Idempotence / repeat-revoke
// =====================================================================

#[tokio::test]
async fn already_revoked_family_revokes_again_idempotently() {
    // Revoking an already-revoked family is a no-op
    // semantically but the store accepts the call.
    // The function returns Revoked again — the
    // family DO's revoke call is idempotent, and the
    // outcome of "revocation requested, completed
    // (with no further side effect)" is correctly
    // Revoked.
    let store = StubFamilyStore::default();
    store.install("fam_2x", "public_client");
    let clients = clients_public("public_client");

    let token = encode_token("fam_2x", "jti_curr");
    let _ = revoke_refresh_token(&store, &clients, &RevokeInput {
        token:         &token,
        hint:          None,
        client_id:     None,
        client_secret: None,
        now_unix:      200,
    }).await.unwrap();
    let outcome2 = revoke_refresh_token(&store, &clients, &RevokeInput {
        token:         &token,
        hint:          None,
        client_id:     None,
        client_secret: None,
        now_unix:      300,
    }).await.unwrap();

    assert!(matches!(outcome2, RevokeOutcome::Revoked { .. }),
        "second revoke must succeed idempotently, got {outcome2:?}");
    assert_eq!(store.revoke_calls.borrow().as_slice(),
               &["fam_2x".to_owned(), "fam_2x".to_owned()]);
}
