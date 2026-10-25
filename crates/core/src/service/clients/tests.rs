//! Unit tests for `service::clients`.

use std::cell::RefCell;
use std::collections::HashMap;

use super::*;
use crate::ports::repo::ClientAuthView;
use crate::ports::PortResult;

/// Minimal in-memory stub, same shape as the ones in `service::token`'s
/// and `service::revoke`'s own test modules (`core` cannot depend on
/// `adapter-test` — that crate depends on `core`).
struct StubClients(RefCell<HashMap<String, (OidcClient, Option<String>)>>);

impl StubClients {
    fn new() -> Self { Self(RefCell::new(HashMap::new())) }
}

impl ClientRepository for StubClients {
    async fn find(&self, id: &str) -> PortResult<Option<OidcClient>> {
        Ok(self.0.borrow().get(id).map(|(c, _)| c.clone()))
    }
    async fn client_secret_hash(&self, id: &str) -> PortResult<Option<String>> {
        Ok(self.0.borrow().get(id).and_then(|(_, h)| h.clone()))
    }
    async fn find_auth_view(&self, id: &str) -> PortResult<Option<ClientAuthView>> {
        Ok(self.0.borrow().get(id).map(|(c, h)| ClientAuthView {
            client_id:          c.id.clone(),
            client_type:        c.client_type,
            client_secret_hash: h.clone(),
            audience:           c.audience.clone(),
            token_auth_method:  c.token_auth_method,
        }))
    }
    async fn create(&self, client: &OidcClient, secret_hash: Option<&str>) -> PortResult<()> {
        let mut m = self.0.borrow_mut();
        if m.contains_key(&client.id) {
            return Err(PortError::Conflict);
        }
        m.insert(client.id.clone(), (client.clone(), secret_hash.map(str::to_owned)));
        Ok(())
    }
    async fn list(&self) -> PortResult<Vec<OidcClient>> {
        Ok(self.0.borrow().values().map(|(c, _)| c.clone()).collect())
    }
    async fn update(&self, client: &OidcClient) -> PortResult<()> {
        let mut m = self.0.borrow_mut();
        let Some(entry) = m.get_mut(&client.id) else { return Err(PortError::NotFound); };
        entry.0 = client.clone();
        Ok(())
    }
    async fn set_secret_hash(&self, id: &str, secret_hash: Option<&str>) -> PortResult<()> {
        let mut m = self.0.borrow_mut();
        let Some(entry) = m.get_mut(id) else { return Err(PortError::NotFound); };
        entry.1 = secret_hash.map(str::to_owned);
        Ok(())
    }
    async fn delete(&self, id: &str) -> PortResult<()> {
        if self.0.borrow_mut().remove(id).is_none() {
            return Err(PortError::NotFound);
        }
        Ok(())
    }
}

fn new_public(id: &str) -> NewClient {
    NewClient {
        id:                id.to_owned(),
        name:              "Demo CLI".to_owned(),
        client_type:       ClientType::Public,
        redirect_uris:     vec!["http://localhost:8787/callback".to_owned()],
        allowed_scopes:    vec!["openid".to_owned(), "profile".to_owned()],
        token_auth_method: TokenAuthMethod::None,
        audience:          None,
    }
}

fn new_confidential(id: &str, method: TokenAuthMethod) -> NewClient {
    NewClient {
        id:                id.to_owned(),
        name:              "Backend integration".to_owned(),
        client_type:       ClientType::Confidential,
        redirect_uris:     vec!["https://app.example.com/callback".to_owned()],
        allowed_scopes:    vec!["openid".to_owned(), "email".to_owned()],
        token_auth_method: method,
        audience:          Some("https://api.example.com".to_owned()),
    }
}

// ── validate_registration: every unrepresentable combination (§3.4) ───────

#[test]
fn public_with_none_is_valid() {
    assert!(validate_registration(
        "n", ClientType::Public, &["https://a/cb".to_owned()], &["openid".to_owned()],
        TokenAuthMethod::None, true,
    ).is_ok());
}

#[test]
fn confidential_with_basic_is_valid() {
    assert!(validate_registration(
        "n", ClientType::Confidential, &["https://a/cb".to_owned()], &["openid".to_owned()],
        TokenAuthMethod::ClientSecretBasic, true,
    ).is_ok());
}

#[test]
fn confidential_with_post_is_valid() {
    assert!(validate_registration(
        "n", ClientType::Confidential, &["https://a/cb".to_owned()], &["openid".to_owned()],
        TokenAuthMethod::ClientSecretPost, true,
    ).is_ok());
}

#[test]
fn public_with_basic_is_unrepresentable() {
    let e = validate_registration(
        "n", ClientType::Public, &["https://a/cb".to_owned()], &["openid".to_owned()],
        TokenAuthMethod::ClientSecretBasic, true,
    ).unwrap_err();
    assert!(matches!(e, ClientValidationError::TypeMethodMismatch { .. }));
}

#[test]
fn public_with_post_is_unrepresentable() {
    let e = validate_registration(
        "n", ClientType::Public, &["https://a/cb".to_owned()], &["openid".to_owned()],
        TokenAuthMethod::ClientSecretPost, true,
    ).unwrap_err();
    assert!(matches!(e, ClientValidationError::TypeMethodMismatch { .. }));
}

#[test]
fn confidential_with_none_is_unrepresentable() {
    let e = validate_registration(
        "n", ClientType::Confidential, &["https://a/cb".to_owned()], &["openid".to_owned()],
        TokenAuthMethod::None, true,
    ).unwrap_err();
    assert!(matches!(e, ClientValidationError::TypeMethodMismatch { .. }));
}

#[test]
fn require_pkce_false_is_rejected() {
    let e = validate_registration(
        "n", ClientType::Public, &["https://a/cb".to_owned()], &["openid".to_owned()],
        TokenAuthMethod::None, false,
    ).unwrap_err();
    assert_eq!(e, ClientValidationError::RequirePkceFalse);
}

#[test]
fn empty_name_is_rejected() {
    let e = validate_registration(
        "   ", ClientType::Public, &["https://a/cb".to_owned()], &["openid".to_owned()],
        TokenAuthMethod::None, true,
    ).unwrap_err();
    assert_eq!(e, ClientValidationError::NameEmpty);
}

#[test]
fn no_redirect_uris_is_rejected() {
    let e = validate_registration(
        "n", ClientType::Public, &[], &["openid".to_owned()], TokenAuthMethod::None, true,
    ).unwrap_err();
    assert_eq!(e, ClientValidationError::NoRedirectUris);
}

#[test]
fn malformed_redirect_uri_is_rejected() {
    for bad in ["not-a-uri", "//missing-scheme/cb", "https://#frag", "https://a/cb#frag", "javascript:alert(1)"] {
        let e = validate_registration(
            "n", ClientType::Public, &[bad.to_owned()], &["openid".to_owned()],
            TokenAuthMethod::None, true,
        ).unwrap_err();
        assert!(
            matches!(e, ClientValidationError::RedirectUriNotAbsolute(_)),
            "expected rejection for {bad:?}, got {e:?}",
        );
    }
}

#[test]
fn well_formed_redirect_uris_are_accepted() {
    for ok in ["https://a.example.com/callback", "http://localhost:8787/callback", "myapp://callback"] {
        assert!(
            validate_registration(
                "n", ClientType::Public, &[ok.to_owned()], &["openid".to_owned()],
                TokenAuthMethod::None, true,
            ).is_ok(),
            "expected acceptance for {ok:?}",
        );
    }
}

#[test]
fn no_allowed_scopes_is_rejected() {
    let e = validate_registration(
        "n", ClientType::Public, &["https://a/cb".to_owned()], &[], TokenAuthMethod::None, true,
    ).unwrap_err();
    assert_eq!(e, ClientValidationError::NoAllowedScopes);
}

#[test]
fn unknown_scope_is_rejected() {
    let e = validate_registration(
        "n", ClientType::Public, &["https://a/cb".to_owned()], &["sudo".to_owned()],
        TokenAuthMethod::None, true,
    ).unwrap_err();
    assert_eq!(e, ClientValidationError::UnknownScope("sudo".to_owned()));
}

#[test]
fn every_known_scope_is_accepted() {
    for s in crate::oidc::discovery::KNOWN_SCOPES {
        assert!(
            validate_registration(
                "n", ClientType::Public, &["https://a/cb".to_owned()], &[(*s).to_owned()],
                TokenAuthMethod::None, true,
            ).is_ok(),
            "expected {s:?} to be accepted",
        );
    }
}

// ── register_client / the secret round-trip ───────────────────────────────

#[tokio::test]
async fn public_client_registers_with_no_secret() {
    let repo = StubClients::new();
    let r = register_client(&repo, new_public("demo-cli")).await.unwrap();
    assert!(r.secret.is_none());
    assert_eq!(r.client.token_auth_method, TokenAuthMethod::None);
    assert!(repo.client_secret_hash("demo-cli").await.unwrap().is_none());
}

#[tokio::test]
async fn confidential_client_registers_with_a_minted_secret_whose_hash_is_stored() {
    let repo = StubClients::new();
    let r = register_client(&repo, new_confidential("app-1", TokenAuthMethod::ClientSecretBasic))
        .await.unwrap();
    let secret = r.secret.expect("confidential client must get a secret");

    let stored_hash = repo.client_secret_hash("app-1").await.unwrap().expect("hash on file");
    // The stored value is the hash, never the plaintext.
    assert_ne!(stored_hash, secret.expose());
    assert_eq!(stored_hash, secret.sha256().as_storage_str());
}

#[tokio::test]
async fn minted_secrets_are_not_predictable_repeats() {
    let repo = StubClients::new();
    let a = register_client(&repo, new_confidential("app-a", TokenAuthMethod::ClientSecretBasic))
        .await.unwrap().secret.unwrap();
    let b = register_client(&repo, new_confidential("app-b", TokenAuthMethod::ClientSecretBasic))
        .await.unwrap().secret.unwrap();
    assert_ne!(a.expose(), b.expose());
}

#[tokio::test]
async fn register_rejects_invalid_input_before_touching_the_repo() {
    let repo = StubClients::new();
    let mut bad = new_public("demo-cli");
    bad.redirect_uris.clear();
    let err = register_client(&repo, bad).await.unwrap_err();
    assert!(matches!(err, ClientOpError::Validation(ClientValidationError::NoRedirectUris)));
    assert!(repo.find("demo-cli").await.unwrap().is_none(), "nothing should have been stored");
}

#[tokio::test]
async fn duplicate_id_is_conflict() {
    let repo = StubClients::new();
    register_client(&repo, new_public("demo-cli")).await.unwrap();
    let err = register_client(&repo, new_public("demo-cli")).await.unwrap_err();
    assert!(matches!(err, ClientOpError::Conflict));
}

// ── rotate_secret ───────────────────────────────────────────────────────

#[tokio::test]
async fn rotate_secret_invalidates_the_previous_one() {
    let repo = StubClients::new();
    let first = register_client(&repo, new_confidential("app-1", TokenAuthMethod::ClientSecretBasic))
        .await.unwrap().secret.unwrap();
    let second = rotate_secret(&repo, "app-1").await.unwrap();

    assert_ne!(first.expose(), second.expose());
    let stored_hash = repo.client_secret_hash("app-1").await.unwrap().unwrap();
    assert_eq!(stored_hash, second.sha256().as_storage_str());
    assert_ne!(stored_hash, first.sha256().as_storage_str(), "the old hash must no longer be on file");
}

#[tokio::test]
async fn rotate_secret_on_a_public_client_is_rejected() {
    let repo = StubClients::new();
    register_client(&repo, new_public("demo-cli")).await.unwrap();
    let err = rotate_secret(&repo, "demo-cli").await.unwrap_err();
    assert!(matches!(err, ClientOpError::NotConfidential));
}

#[tokio::test]
async fn rotate_secret_on_an_unknown_client_is_not_found() {
    let repo = StubClients::new();
    let err = rotate_secret(&repo, "no-such-client").await.unwrap_err();
    assert!(matches!(err, ClientOpError::NotFound));
}

// ── update_client ───────────────────────────────────────────────────────

#[tokio::test]
async fn update_replaces_the_mutable_fields_and_preserves_type() {
    let repo = StubClients::new();
    register_client(&repo, new_confidential("app-1", TokenAuthMethod::ClientSecretPost)).await.unwrap();

    let updated = update_client(&repo, "app-1", ClientUpdate {
        name:              "Renamed".to_owned(),
        redirect_uris:     vec!["https://new.example.com/cb".to_owned()],
        allowed_scopes:    vec!["openid".to_owned()],
        token_auth_method: TokenAuthMethod::ClientSecretPost, // unchanged
        audience:          None,
    }).await.unwrap();

    assert_eq!(updated.name, "Renamed");
    assert_eq!(updated.redirect_uris, vec!["https://new.example.com/cb".to_owned()]);
    assert_eq!(updated.audience, None);
    assert_eq!(updated.token_auth_method, TokenAuthMethod::ClientSecretPost);
    // client_type cannot change by this call — there is no field for it.
    assert_eq!(updated.client_type, ClientType::Confidential);
}

// ── RFC 141 C1-141 item 3: token_auth_method is updatable, client_type isn't ──

#[tokio::test]
async fn update_switches_a_confidential_client_from_basic_to_post() {
    let repo = StubClients::new();
    register_client(&repo, new_confidential("app-1", TokenAuthMethod::ClientSecretBasic)).await.unwrap();

    let updated = update_client(&repo, "app-1", ClientUpdate {
        name:              "Backend integration".to_owned(),
        redirect_uris:     vec!["https://app.example.com/callback".to_owned()],
        allowed_scopes:    vec!["openid".to_owned(), "email".to_owned()],
        token_auth_method: TokenAuthMethod::ClientSecretPost,
        audience:          None,
    }).await.unwrap();
    assert_eq!(updated.token_auth_method, TokenAuthMethod::ClientSecretPost);

    // And back again, via the same repo round-trip (`find` sees what
    // `update` stored — exercises the adapter-shaped path, not just the
    // struct returned by this call).
    let back = update_client(&repo, "app-1", ClientUpdate {
        name:              "Backend integration".to_owned(),
        redirect_uris:     vec!["https://app.example.com/callback".to_owned()],
        allowed_scopes:    vec!["openid".to_owned(), "email".to_owned()],
        token_auth_method: TokenAuthMethod::ClientSecretBasic,
        audience:          None,
    }).await.unwrap();
    assert_eq!(back.token_auth_method, TokenAuthMethod::ClientSecretBasic);
    assert_eq!(repo.find("app-1").await.unwrap().unwrap().token_auth_method, TokenAuthMethod::ClientSecretBasic);
}

#[tokio::test]
async fn update_cannot_turn_a_confidential_client_public_shaped() {
    // There is no `client_type` field on `ClientUpdate` — the only way to
    // attempt this is `token_auth_method: None` against an existing
    // `client_type: Confidential`, which §4.3 still rejects, now at
    // update time, exactly as it would have at create time.
    let repo = StubClients::new();
    register_client(&repo, new_confidential("app-1", TokenAuthMethod::ClientSecretBasic)).await.unwrap();

    let err = update_client(&repo, "app-1", ClientUpdate {
        name:              "Backend integration".to_owned(),
        redirect_uris:     vec!["https://app.example.com/callback".to_owned()],
        allowed_scopes:    vec!["openid".to_owned()],
        token_auth_method: TokenAuthMethod::None,
        audience:          None,
    }).await.unwrap_err();
    assert!(matches!(
        err,
        ClientOpError::Validation(ClientValidationError::TypeMethodMismatch {
            client_type: ClientType::Confidential,
            token_auth_method: TokenAuthMethod::None,
        }),
    ));
    // Unchanged: the rejected attempt touched nothing.
    assert_eq!(repo.find("app-1").await.unwrap().unwrap().token_auth_method, TokenAuthMethod::ClientSecretBasic);
}

#[tokio::test]
async fn update_cannot_give_a_public_client_a_confidential_method() {
    let repo = StubClients::new();
    register_client(&repo, new_public("demo-cli")).await.unwrap();

    let err = update_client(&repo, "demo-cli", ClientUpdate {
        name:              "Demo CLI".to_owned(),
        redirect_uris:     vec!["http://localhost:8787/callback".to_owned()],
        allowed_scopes:    vec!["openid".to_owned()],
        token_auth_method: TokenAuthMethod::ClientSecretBasic,
        audience:          None,
    }).await.unwrap_err();
    assert!(matches!(err, ClientOpError::Validation(ClientValidationError::TypeMethodMismatch { .. })));
}

#[tokio::test]
async fn update_runs_the_same_validation_as_create() {
    let repo = StubClients::new();
    register_client(&repo, new_public("demo-cli")).await.unwrap();
    let err = update_client(&repo, "demo-cli", ClientUpdate {
        name:              "Demo CLI".to_owned(),
        redirect_uris:     vec!["not-a-uri".to_owned()],
        allowed_scopes:    vec!["openid".to_owned()],
        token_auth_method: TokenAuthMethod::None,
        audience:          None,
    }).await.unwrap_err();
    assert!(matches!(err, ClientOpError::Validation(ClientValidationError::RedirectUriNotAbsolute(_))));
}

#[tokio::test]
async fn update_on_an_unknown_client_is_not_found() {
    let repo = StubClients::new();
    let err = update_client(&repo, "no-such-client", ClientUpdate {
        name:              "n".to_owned(),
        redirect_uris:     vec!["https://a/cb".to_owned()],
        allowed_scopes:    vec!["openid".to_owned()],
        token_auth_method: TokenAuthMethod::None,
        audience:          None,
    }).await.unwrap_err();
    assert!(matches!(err, ClientOpError::NotFound));
}

// ── list / delete ───────────────────────────────────────────────────────

#[tokio::test]
async fn list_returns_every_registered_client() {
    let repo = StubClients::new();
    register_client(&repo, new_public("demo-cli")).await.unwrap();
    register_client(&repo, new_confidential("app-1", TokenAuthMethod::ClientSecretBasic)).await.unwrap();
    let mut ids: Vec<String> = list_clients(&repo).await.unwrap().into_iter().map(|c| c.id).collect();
    ids.sort();
    assert_eq!(ids, vec!["app-1".to_owned(), "demo-cli".to_owned()]);
}

#[tokio::test]
async fn delete_removes_the_client() {
    let repo = StubClients::new();
    register_client(&repo, new_public("demo-cli")).await.unwrap();
    delete_client(&repo, "demo-cli").await.unwrap();
    assert!(repo.find("demo-cli").await.unwrap().is_none());
}

#[tokio::test]
async fn delete_on_an_unknown_client_is_not_found() {
    let repo = StubClients::new();
    let err = delete_client(&repo, "no-such-client").await.unwrap_err();
    assert!(matches!(err, ClientOpError::NotFound));
}
