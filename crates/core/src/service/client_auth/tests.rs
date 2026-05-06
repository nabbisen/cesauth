//! Unit tests for `service::client_auth`.

use super::*;
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
