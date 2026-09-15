//! Unit tests for `service::client_auth`.

use super::*;
use crate::ports::repo::ClientAuthView;
use crate::ports::PortResult;
use crate::types::OidcClient;

/// Minimal stub ClientRepository for credential-verification
/// testing. We only exercise `client_secret_hash`; the other
/// methods just unimplemented so the test fails loudly if the
/// service ever reaches for them.
struct StubClients {
    map: std::collections::HashMap<String, Option<String>>,
}

impl ClientRepository for StubClients {
    async fn find(&self, _client_id: &str) -> PortResult<Option<OidcClient>> {
        unimplemented!("verify_client_credentials must not call find")
    }

    async fn client_secret_hash(&self, client_id: &str) -> PortResult<Option<String>> {
        Ok(self.map.get(client_id).cloned().unwrap_or(None))
    }

    async fn find_auth_view(&self, client_id: &str) -> PortResult<Option<ClientAuthView>> {
        use crate::types::TokenAuthMethod;
        Ok(self.map.get(client_id).map(|hash| ClientAuthView {
            client_id:          client_id.to_owned(),
            client_type:        crate::types::ClientType::Confidential,
            client_secret_hash: hash.clone(),
            audience:           None,
            token_auth_method:  TokenAuthMethod::ClientSecretBasic,
        }))
    }

    async fn create(&self, _: &OidcClient, _: Option<&str>) -> PortResult<()> {
        unimplemented!()
    }
}

fn stub_with(client_id: &str, secret: &str) -> StubClients {
    let mut map = std::collections::HashMap::new();
    map.insert(client_id.to_owned(), Some(sha256_hex(secret.as_bytes())));
    StubClients { map }
}

/// **v0.42.0** — Stub returning a registered public
/// client (the `client_id` exists but has no
/// `client_secret_hash` on file). Used by the
/// `verify_client_credentials_optional` tests; in
/// production this corresponds to a PKCE-only OIDC
/// client provisioned by an admin who chose not to
/// generate a secret.
fn stub_public(client_id: &str) -> StubClients {
    let mut map = std::collections::HashMap::new();
    map.insert(client_id.to_owned(), None);
    StubClients { map }
}

#[tokio::test]
async fn correct_secret_verifies() {
    let clients = stub_with("rs_demo", "topsecret123");
    let result = verify_client_credentials(&clients, "rs_demo", "topsecret123").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn wrong_secret_returns_invalid_client() {
    let clients = stub_with("rs_demo", "topsecret123");
    let result = verify_client_credentials(&clients, "rs_demo", "wrong").await;
    assert!(matches!(result, Err(CoreError::InvalidClient)));
}

#[tokio::test]
async fn unknown_client_returns_invalid_client() {
    // The variant is the same as wrong-secret — collapsing the
    // two avoids the enumeration side-channel where an attacker
    // could probe which client_ids exist.
    let clients = stub_with("rs_demo", "topsecret123");
    let result = verify_client_credentials(&clients, "no_such_client", "anything").await;
    assert!(matches!(result, Err(CoreError::InvalidClient)));
}

#[tokio::test]
async fn public_client_no_secret_on_file_returns_invalid_client() {
    // A registered client without a stored secret hash is a
    // public client (PKCE-only). It can't authenticate via
    // client_secret_basic/post, so the verification fails.
    let mut map = std::collections::HashMap::new();
    map.insert("rs_demo".to_owned(), None);
    let clients = StubClients { map };
    let result = verify_client_credentials(&clients, "rs_demo", "anything").await;
    assert!(matches!(result, Err(CoreError::InvalidClient)));
}

#[tokio::test]
async fn empty_secret_does_not_authenticate() {
    // The hash of "" is not the same as any real registered
    // secret hash. This is a reflection-of-property test
    // pinning that we don't have a degenerate empty-secret
    // bypass.
    let clients = stub_with("rs_demo", "actual_secret");
    let result = verify_client_credentials(&clients, "rs_demo", "").await;
    assert!(matches!(result, Err(CoreError::InvalidClient)));
}

// =====================================================================
// SHA-256 + constant-time helpers
// =====================================================================

#[test]
fn sha256_hex_known_vectors() {
    // Empty input — the canonical SHA-256 of "".
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    // "abc" — RFC 6234 §8.5 vector.
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
}

#[test]
fn sha256_hex_is_64_chars_lowercase_hex() {
    let h = sha256_hex(b"random input");
    assert_eq!(h.len(), 64);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
}

#[test]
fn constant_time_eq_basic_correctness() {
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(!constant_time_eq(b"abc", b"abcd"),
        "length mismatch must return false");
    assert!(constant_time_eq(b"", b""));
    assert!(!constant_time_eq(b"a", b""));
}

// =====================================================================
// v0.42.0 — verify_client_credentials_optional (RFC 7009 revoke)
// =====================================================================

#[tokio::test]
async fn optional_public_client_returns_public_or_unknown() {
    // No client_secret_hash on file → registered as public.
    let clients = stub_public("public_demo");
    let outcome = verify_client_credentials_optional(
        &clients, "public_demo", None,
    ).await.unwrap();
    assert_eq!(outcome, ClientAuthOutcome::PublicOrUnknown);
}

#[tokio::test]
async fn optional_unknown_client_returns_public_or_unknown() {
    // Client doesn't exist at all → same outcome as public.
    // This conflation is the privacy invariant: the caller
    // can't tell "unknown client" from "public client" by
    // outcome alone.
    let clients = stub_with("known_only", "secret");
    let outcome = verify_client_credentials_optional(
        &clients, "totally_unknown", Some("anything"),
    ).await.unwrap();
    assert_eq!(outcome, ClientAuthOutcome::PublicOrUnknown);
}

#[tokio::test]
async fn optional_confidential_no_creds_returns_auth_failed() {
    // Confidential client, but no Authorization or
    // form-body creds → revoke endpoint must reject.
    let clients = stub_with("conf_demo", "real_secret");
    let outcome = verify_client_credentials_optional(
        &clients, "conf_demo", None,
    ).await.unwrap();
    assert_eq!(outcome, ClientAuthOutcome::AuthenticationFailed);
}

#[tokio::test]
async fn optional_confidential_correct_creds_returns_authenticated() {
    let clients = stub_with("conf_demo", "real_secret");
    let outcome = verify_client_credentials_optional(
        &clients, "conf_demo", Some("real_secret"),
    ).await.unwrap();
    assert_eq!(outcome, ClientAuthOutcome::Authenticated);
}

#[tokio::test]
async fn optional_confidential_wrong_creds_returns_auth_failed() {
    let clients = stub_with("conf_demo", "real_secret");
    let outcome = verify_client_credentials_optional(
        &clients, "conf_demo", Some("wrong_secret"),
    ).await.unwrap();
    assert_eq!(outcome, ClientAuthOutcome::AuthenticationFailed);
}

#[tokio::test]
async fn optional_confidential_empty_secret_returns_auth_failed() {
    // Defensive: an empty Some("") is treated like wrong
    // creds, not like None. The hash of "" doesn't match
    // any reasonable stored secret. We don't want a path
    // where presenting "" to a confidential client somehow
    // gates as PublicOrUnknown.
    let clients = stub_with("conf_demo", "real_secret");
    let outcome = verify_client_credentials_optional(
        &clients, "conf_demo", Some(""),
    ).await.unwrap();
    assert_eq!(outcome, ClientAuthOutcome::AuthenticationFailed);
}

// -----------------------------------------------------------------------
// RFC 026 — check_client_credentials_from_view tests
// -----------------------------------------------------------------------

fn make_view(secret: Option<&str>, audience: Option<&str>) -> ClientAuthView {
    use crate::types::TokenAuthMethod;
    // Build a SHA-256 hex hash of the secret when present.
    let hash = secret.map(|s| {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        format!("{:x}", h.finalize())
    });
    ClientAuthView {
        client_id:          "test-client".to_owned(),
        client_type:        crate::types::ClientType::Confidential,
        client_secret_hash: hash,
        audience:           audience.map(str::to_owned),
        token_auth_method:  TokenAuthMethod::ClientSecretBasic,
    }
}

#[test]
fn from_view_correct_secret_returns_authenticated() {
    let view = make_view(Some("super_secret"), None);
    assert_eq!(
        check_client_credentials_from_view(&view, "super_secret"),
        ClientAuthOutcome::Authenticated
    );
}

#[test]
fn from_view_wrong_secret_returns_auth_failed() {
    let view = make_view(Some("super_secret"), None);
    assert_eq!(
        check_client_credentials_from_view(&view, "wrong"),
        ClientAuthOutcome::AuthenticationFailed
    );
}

#[test]
fn from_view_no_hash_returns_public_or_unknown() {
    let view = make_view(None, None);
    assert_eq!(
        check_client_credentials_from_view(&view, "anything"),
        ClientAuthOutcome::PublicOrUnknown
    );
}

#[test]
fn from_view_audience_field_preserved() {
    let view = make_view(Some("s"), Some("https://api.example.com"));
    assert_eq!(view.audience.as_deref(), Some("https://api.example.com"));
}

#[test]
fn from_view_empty_secret_returns_auth_failed() {
    let view = make_view(Some("real_secret"), None);
    assert_eq!(
        check_client_credentials_from_view(&view, ""),
        ClientAuthOutcome::AuthenticationFailed
    );
}

// -----------------------------------------------------------------------
// RFC 137 — `/token` client-credential precedence
// (`resolve_token_client_credentials`). Pure, so the route's rules are
// testable on the host: `worker::Headers` cannot be constructed off wasm32.
// -----------------------------------------------------------------------

/// Test 11 — a Basic header and a disagreeing form `client_id` is one client
/// presenting two identities in one request (RFC 6749 §2.3).
#[test]
fn token_basic_header_with_disagreeing_form_client_id_is_invalid_client() {
    let r = crate::service::client_auth::resolve_token_client_credentials(
        true, Some(("client-a", "secret-a")), Some("client-b"), None,
    );
    assert!(matches!(r, Err(crate::error::CoreError::InvalidClient)), "got {r:?}");
}

/// §7.2 — a malformed Basic header must not fall through to the form body, or
/// a broken Basic attempt would silently retry itself as `client_secret_post`.
#[test]
fn token_malformed_basic_header_does_not_fall_through_to_the_form() {
    let r = crate::service::client_auth::resolve_token_client_credentials(
        true, None, Some("client-a"), Some("secret-a"),
    );
    assert!(matches!(r, Err(crate::error::CoreError::InvalidClient)), "got {r:?}");
}

/// Basic with an agreeing form `client_id` resolves to the header's credentials.
#[test]
fn token_basic_header_with_agreeing_form_client_id_resolves() {
    let r = crate::service::client_auth::resolve_token_client_credentials(
        true, Some(("client-a", "secret-a")), Some("client-a"), None,
    ).expect("agreeing identities must resolve");
    assert_eq!(r, ("client-a".to_owned(), Some("secret-a".to_owned())));
}

/// No header — the form supplies the client, and an empty secret is absent,
/// matching `extract_from_form`. This is the beginner guide's `demo-cli` path.
#[test]
fn token_form_credentials_treat_an_empty_secret_as_absent() {
    let r = crate::service::client_auth::resolve_token_client_credentials(
        false, None, Some("demo-cli"), Some(""),
    ).expect("a public client with no secret must resolve");
    assert_eq!(r, ("demo-cli".to_owned(), None));
}

// -----------------------------------------------------------------------
// RFC 137 C1-137 — one authentication method per request; Basic identifies
// the client without a body client_id.
// -----------------------------------------------------------------------

/// Basic plus a non-empty form `client_secret` is two methods, even when the
/// identities agree (RFC 6749 §2.3).
#[test]
fn token_basic_header_with_a_form_client_secret_is_invalid_client() {
    let r = crate::service::client_auth::resolve_token_client_credentials(
        true, Some(("client-a", "secret-a")), Some("client-a"), Some("secret-a"),
    );
    assert!(matches!(r, Err(crate::error::CoreError::InvalidClient)), "got {r:?}");
}

/// An empty form `client_secret` is not a second method.
#[test]
fn token_basic_header_with_an_empty_form_client_secret_resolves() {
    let r = crate::service::client_auth::resolve_token_client_credentials(
        true, Some(("client-a", "secret-a")), None, Some(""),
    ).expect("an empty form secret is absent");
    assert_eq!(r, ("client-a".to_owned(), Some("secret-a".to_owned())));
}

/// Basic alone, no body `client_id`: the header supplies the effective client.
#[test]
fn token_basic_header_without_a_form_client_id_resolves_to_the_header_identity() {
    let r = crate::service::client_auth::resolve_token_client_credentials(
        true, Some(("client-a", "secret-a")), None, None,
    ).expect("Basic alone identifies the client");
    assert_eq!(r, ("client-a".to_owned(), Some("secret-a".to_owned())));
}

/// No header and no body `client_id` is still `invalid_request`, unchanged.
#[test]
fn token_no_header_and_no_client_id_is_still_invalid_request() {
    let r = crate::service::client_auth::resolve_token_client_credentials(false, None, None, None);
    assert!(matches!(r, Err(crate::error::CoreError::InvalidRequest(_))), "got {r:?}");
}
