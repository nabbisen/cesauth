//! Transition tests for the RFC 117 pipeline. Each asserts the **exact**
//! `CoreError` (variant and message) the procedural `exchange_code` returned
//! before this module existed, because existing tests pin those to the wire.

use super::*;

use std::cell::RefCell;
use std::collections::HashMap;

use base64::Engine;
use sha2::{Digest, Sha256};

use crate::ports::PortResult;
use crate::ports::store::AuthChallengeStore;
use crate::types::{ClientType, TokenAuthMethod};

const SECRET:   &str = "test-client-secret-0123456789abcdef";
const VERIFIER: &str = "test-verifier-padded-to-exactly-43chars-xxx";

fn s256(verifier: &str) -> String {
    let mut h = Sha256::new();
    h.update(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize())
}

fn handle() -> ChallengeHandle { ChallengeHandle::from_storage("code-1") }

fn view(id: &str, ty: ClientType, hash: Option<String>) -> ClientAuthView {
    ClientAuthView {
        client_id:          id.to_owned(),
        client_type:        ty,
        client_secret_hash: hash,
        audience:           None,
        token_auth_method:  TokenAuthMethod::ClientSecretBasic,
    }
}

fn confidential(id: &str) -> ClientAuthView {
    view(id, ClientType::Confidential, Some(crate::service::client_auth::sha256_hex(SECRET.as_bytes())))
}

fn authed(id: &str) -> AuthenticatedClient {
    AuthenticatedClient::authenticate(&confidential(id), Some(SECRET)).expect("test client authenticates")
}

/// A store that follows the port's contract (RFC 140: expired iff
/// `now_unix >= expires_at`), as `StubCodes` and the in-memory store do. The
/// pipeline adds no expiry rule of its own; this is what it delegates to.
#[derive(Default)]
struct Store(RefCell<HashMap<String, Challenge>>);

impl AuthChallengeStore for Store {
    async fn put(&self, h: &ChallengeHandle, c: &Challenge) -> PortResult<()> {
        self.0.borrow_mut().insert(h.as_str().to_owned(), c.clone());
        Ok(())
    }
    async fn peek(&self, h: &ChallengeHandle, now: i64) -> PortResult<Option<Challenge>> {
        Ok(self.0.borrow().get(h.as_str()).filter(|c| now < c.expires_at()).cloned())
    }
    async fn take(&self, h: &ChallengeHandle, now: i64) -> PortResult<Option<Challenge>> {
        Ok(self.0.borrow_mut().remove(h.as_str()).filter(|c| now < c.expires_at()))
    }
    async fn bump_magic_link_attempts(&self, _: &ChallengeHandle, _: i64) -> PortResult<u32> { Ok(0) }
}

fn auth_code(client: &str, method: &str) -> Challenge {
    Challenge::AuthCode {
        client_id:             client.to_owned(),
        redirect_uri:          "https://app.test/cb".to_owned(),
        user_id:               "user-1".to_owned(),
        scopes:                Scopes(vec!["openid".to_owned(), "email".to_owned()]),
        nonce:                 Some("nonce-1".to_owned()),
        code_challenge:        s256(VERIFIER),
        code_challenge_method: method.to_owned(),
        issued_at:             1_000,
        expires_at:            1_300,
        auth_time:             990,
    }
}

async fn store_with(c: Challenge) -> Store {
    let s = Store::default();
    s.put(&handle(), &c).await.unwrap();
    s
}

async fn consumed(client: &str) -> ConsumedCode {
    ConsumedCode::take(&store_with(auth_code(client, "S256")).await, &handle(), 1_000).await.unwrap()
}

macro_rules! assert_grant {
    ($r:expr, $msg:expr) => {
        match $r { Err(CoreError::InvalidGrant(m)) => assert_eq!(m, $msg),
                   other => panic!("expected InvalidGrant({:?}), got {:?}", $msg, other) }
    };
}

// ── AuthenticatedClient ─────────────────────────────────────────────────────

#[test]
fn authenticate_admits_a_public_client_with_no_secret() {
    let v = view("demo-cli", ClientType::Public, None);
    assert!(AuthenticatedClient::authenticate(&v, None).is_ok());
}

#[test]
fn authenticate_admits_a_confidential_client_with_its_secret() {
    assert!(AuthenticatedClient::authenticate(&confidential("c-a"), Some(SECRET)).is_ok());
}

#[test]
fn authenticate_refuses_a_wrong_missing_or_unhashed_secret_as_invalid_client() {
    assert!(matches!(AuthenticatedClient::authenticate(&confidential("c-a"), Some("nope")), Err(CoreError::InvalidClient)));
    assert!(matches!(AuthenticatedClient::authenticate(&confidential("c-a"), None),         Err(CoreError::InvalidClient)));
    // RFC 137 §12.2: a confidential client with no stored hash is refused.
    let unhashed = view("c-a", ClientType::Confidential, None);
    assert!(matches!(AuthenticatedClient::authenticate(&unhashed, Some(SECRET)), Err(CoreError::InvalidClient)));
}

// ── ConsumedCode::take ──────────────────────────────────────────────────────

#[tokio::test]
async fn take_of_an_absent_handle_is_unknown_or_used() {
    assert_grant!(ConsumedCode::take(&Store::default(), &handle(), 1_000).await,
                  "code is unknown or already used");
}

#[tokio::test]
async fn take_of_a_handle_that_is_not_an_authorization_code_is_refused() {
    let magic = Challenge::MagicLink {
        email_or_user: "a@example.com".to_owned(), code_hash: "h".to_owned(), attempts: 0, expires_at: 1_300,
    };
    assert_grant!(ConsumedCode::take(&store_with(magic).await, &handle(), 1_000).await,
                  "handle is not a code");
}

#[tokio::test]
async fn take_consumes_the_code() {
    let s = store_with(auth_code("c-a", "S256")).await;
    assert!(ConsumedCode::take(&s, &handle(), 1_000).await.is_ok());
    assert_grant!(ConsumedCode::take(&s, &handle(), 1_000).await, "code is unknown or already used");
}

/// Expiry is the store's rule: `take` hands the store its `now_unix` and treats
/// `None` as an unknown code, with the same error. The pipeline compares nothing.
#[tokio::test]
async fn take_delegates_expiry_to_the_store_with_the_same_error() {
    let s = store_with(auth_code("c-a", "S256")).await;
    assert_grant!(ConsumedCode::take(&s, &handle(), 1_300).await, "code is unknown or already used");
}

// ── bind_client ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn bind_client_refuses_a_code_issued_to_another_client() {
    let r = consumed("c-a").await.bind_client(&authed("c-b"));
    assert_grant!(r, "code was issued to a different client");
}

#[tokio::test]
async fn bind_client_admits_the_client_the_code_was_issued_to() {
    assert!(consumed("c-a").await.bind_client(&authed("c-a")).is_ok());
}

/// A wrong-client attempt runs after `take`, so it has consumed the code
/// (RFC 137 T1): the rightful client's retry finds nothing.
#[tokio::test]
async fn a_wrong_client_attempt_has_consumed_the_code() {
    let s = store_with(auth_code("c-a", "S256")).await;
    let taken = ConsumedCode::take(&s, &handle(), 1_000).await.unwrap();
    assert_grant!(taken.bind_client(&authed("c-b")), "code was issued to a different client");
    assert_grant!(ConsumedCode::take(&s, &handle(), 1_000).await, "code is unknown or already used");
}

// ── bind_redirect ───────────────────────────────────────────────────────────

#[tokio::test]
async fn bind_redirect_refuses_a_different_redirect_uri() {
    let bound = consumed("c-a").await.bind_client(&authed("c-a")).unwrap();
    assert_grant!(bound.bind_redirect("https://evil.test/cb"), "redirect_uri mismatch");
}

#[tokio::test]
async fn bind_redirect_admits_the_bound_redirect_uri() {
    let bound = consumed("c-a").await.bind_client(&authed("c-a")).unwrap();
    assert!(bound.bind_redirect("https://app.test/cb").is_ok());
}

// ── verify_pkce ─────────────────────────────────────────────────────────────

async fn redirect_bound(method: &str) -> RedirectBoundCode {
    let taken = ConsumedCode::take(&store_with(auth_code("c-a", method)).await, &handle(), 1_000).await.unwrap();
    taken.bind_client(&authed("c-a")).unwrap().bind_redirect("https://app.test/cb").unwrap()
}

#[tokio::test]
async fn verify_pkce_refuses_a_wrong_verifier() {
    let wrong = "another-verifier-padded-to-exactly-43chars-";
    assert!(matches!(redirect_bound("S256").await.verify_pkce(wrong), Err(CoreError::PkceMismatch)));
}

#[tokio::test]
async fn verify_pkce_refuses_a_too_short_verifier_as_a_mismatch() {
    assert!(matches!(redirect_bound("S256").await.verify_pkce("short"), Err(CoreError::PkceMismatch)));
}

#[tokio::test]
async fn verify_pkce_refuses_a_stored_method_other_than_s256_as_invalid_request() {
    assert!(matches!(redirect_bound("plain").await.verify_pkce(VERIFIER),
        Err(CoreError::InvalidRequest("code_challenge_method: plain is not supported"))));
    assert!(matches!(redirect_bound("S512").await.verify_pkce(VERIFIER),
        Err(CoreError::InvalidRequest("code_challenge_method: unknown value"))));
}

// ── the whole chain ─────────────────────────────────────────────────────────

/// Happy path: the mint input carries exactly the code's contents.
#[tokio::test]
async fn the_full_chain_yields_the_codes_contents() {
    let mint = consumed("c-a").await
        .bind_client(&authed("c-a")).unwrap()
        .bind_redirect("https://app.test/cb").unwrap()
        .verify_pkce(VERIFIER).unwrap()
        .into_mint_input();
    assert_eq!(mint.client_id(), "c-a");
    assert_eq!(mint.user_id(), "user-1");
    assert_eq!(mint.scopes(), &Scopes(vec!["openid".to_owned(), "email".to_owned()]));
    assert_eq!(mint.nonce(), Some("nonce-1"));
    assert_eq!(mint.auth_time(), 990);
}

/// The checks run in the order RFC 117 §1 states. With a wrong client, a wrong
/// redirect URI and a wrong verifier all at once, each step reports only its own
/// error, so a reordering would change which error surfaces.
#[tokio::test]
async fn the_checks_run_client_then_redirect_then_pkce() {
    let (bad_uri, bad_verifier) = ("https://evil.test/cb", "x");

    let r = consumed("c-a").await.bind_client(&authed("c-b"));
    assert_grant!(r, "code was issued to a different client");

    let r = consumed("c-a").await.bind_client(&authed("c-a")).unwrap().bind_redirect(bad_uri);
    assert_grant!(r, "redirect_uri mismatch");

    let r = consumed("c-a").await.bind_client(&authed("c-a")).unwrap()
        .bind_redirect("https://app.test/cb").unwrap().verify_pkce(bad_verifier);
    assert!(matches!(r, Err(CoreError::PkceMismatch)));
}

/// A derived `Debug` would print the user id and PKCE challenge into a log line.
#[tokio::test]
async fn debug_output_reveals_nothing_about_a_states_contents() {
    let c = consumed("c-a").await;
    let dbg = format!("{c:?}");
    for secret in ["user-1", "c-a", "nonce-1", &s256(VERIFIER)] {
        assert!(!dbg.contains(secret), "Debug leaked {secret:?}: {dbg}");
    }
    let mint = c.bind_client(&authed("c-a")).unwrap().bind_redirect("https://app.test/cb").unwrap()
        .verify_pkce(VERIFIER).unwrap().into_mint_input();
    let dbg = format!("{mint:?}");
    assert!(!dbg.contains("user-1") && !dbg.contains("nonce-1"), "MintInput Debug leaked: {dbg}");
}
