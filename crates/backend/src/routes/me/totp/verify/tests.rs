//! Tests for the verify handler.
//!
//! `attempts_exhausted` boundary tests are preserved verbatim
//! from v0.31.0; the v0.31.1 P1-B additions are the
//! `decide_verify_get` integration tests using in-memory
//! adapters.

use super::*;

use cesauth_adapter_test::store::InMemoryAuthChallengeStore;
use cesauth_core::ports::store::{AuthMethod, Challenge};

const TOTP_HANDLE: &str = "handle_test";

fn parked_pending_totp() -> Challenge {
    Challenge::PendingTotp {
        user_id:                 "usr_a".to_owned(),
        auth_method:             AuthMethod::MagicLink,
        ar_client_id:            None,
        ar_redirect_uri:         None,
        ar_scope:                None,
        ar_state:                None,
        ar_nonce:                None,
        ar_code_challenge:       None,
        ar_code_challenge_method:None,
        attempts:                0,
        expires_at:              i64::MAX,
    }
}

// =====================================================================
// attempts_exhausted boundary — v0.31.0 (preserved verbatim)
// =====================================================================
//
// Pin the lockout threshold. The handler increments before
// calling this; first wrong code → 1, fifth → 5. At >= 5 the
// gate clears and the user is bounced to /login.

#[test]
fn attempts_under_threshold_does_not_lock() {
    assert!(!attempts_exhausted(0));
    assert!(!attempts_exhausted(1));
    assert!(!attempts_exhausted(4));
}

#[test]
fn attempts_at_max_locks() {
    assert!(attempts_exhausted(MAX_ATTEMPTS));
}

#[test]
fn attempts_above_max_locks() {
    // Defensive: a corrupt PendingTotp claiming attempts=999
    // should still trigger lockout, not roll under.
    assert!(attempts_exhausted(MAX_ATTEMPTS + 1));
    assert!(attempts_exhausted(u32::MAX));
}

#[test]
fn max_attempts_is_in_reasonable_range() {
    // Pin the band: too low (1-2) is friction-heavy on
    // legitimate users with bad inputs; too high (50+)
    // weakens the rate-limit story per ADR-009.
    assert!(MAX_ATTEMPTS >= 3 && MAX_ATTEMPTS <= 10,
        "MAX_ATTEMPTS = {MAX_ATTEMPTS} should sit in 3-10 band");
}

// =====================================================================
// decide_verify_get — v0.31.1 P1-B
// =====================================================================

#[tokio::test]
async fn verify_get_with_live_pending_totp_renders() {
    let store = InMemoryAuthChallengeStore::default();
    store.put(TOTP_HANDLE, &parked_pending_totp()).await.unwrap();

    let decision = decide_verify_get(TOTP_HANDLE, &store).await;
    assert_eq!(decision, VerifyGetDecision::RenderPage);

    // Critical: peek (not take). The challenge MUST still be
    // there after the GET so the POST that follows can take it.
    assert!(store.peek(TOTP_HANDLE).await.unwrap().is_some(),
        "GET must not consume the challenge");
}

#[tokio::test]
async fn verify_get_with_unknown_handle_is_stale_gate() {
    let store = InMemoryAuthChallengeStore::default();
    let decision = decide_verify_get("never-parked", &store).await;
    assert_eq!(decision, VerifyGetDecision::StaleGate);
}

#[tokio::test]
async fn verify_get_with_wrong_challenge_kind_is_stale_gate() {
    // Park a non-PendingTotp under the handle.
    let store = InMemoryAuthChallengeStore::default();
    let other = Challenge::PendingAuthorize {
        client_id:             "c".to_owned(),
        redirect_uri:          "http://x".to_owned(),
        scope:                 None,
        state:                 None,
        nonce:                 None,
        code_challenge:        "z".to_owned(),
        code_challenge_method: "S256".to_owned(),
        expires_at:            i64::MAX,
    };
    store.put(TOTP_HANDLE, &other).await.unwrap();

    let decision = decide_verify_get(TOTP_HANDLE, &store).await;
    assert_eq!(decision, VerifyGetDecision::StaleGate);
}

#[tokio::test]
async fn verify_get_after_take_is_stale_gate() {
    // Simulate the case where the POST has already consumed the
    // challenge and the user reloads the GET. They should land
    // on /login, not on a verify page with a non-existent
    // challenge.
    let store = InMemoryAuthChallengeStore::default();
    store.put(TOTP_HANDLE, &parked_pending_totp()).await.unwrap();
    store.take(TOTP_HANDLE).await.unwrap(); // consume

    let decision = decide_verify_get(TOTP_HANDLE, &store).await;
    assert_eq!(decision, VerifyGetDecision::StaleGate);
}

// =====================================================================
// decide_verify_post — v0.31.1 P1-B / v0.32.1
// =====================================================================
//
// The most complex handler in the TOTP suite. Tests cover the
// full branch table:
//
// - CSRF success vs failure
// - Wrong / missing / consumed challenge
// - Soft-success when the user has no authenticator
// - Decryption failure
// - Happy path (verifies + persists last_used_step)
// - Wrong-code re-park with bumped attempts
// - Lockout at MAX_ATTEMPTS

use cesauth_adapter_test::repo::InMemoryTotpAuthenticatorRepository;
use cesauth_core::ports::PortError;
use cesauth_core::totp::{
    aad_for_id as aad, compute_code, encrypt_secret, step_for_unix, Secret,
    storage::{TotpAuthenticator, TotpAuthenticatorRepository as _},
};

const USER_ID:    &str = "usr_test_alice";
const AUTH_ID:    &str = "auth_test_xyz";
const KEY_ID:     &str = "totp-key-v1";

/// 32-byte encryption key for tests. Deterministic so re-runs see
/// the same ciphertext + chain hashes; not used in production.
fn fixed_key() -> Vec<u8> {
    (0u8..32).collect()
}

/// Build a confirmed authenticator with a known secret encrypted
/// under `fixed_key`. Returns the (Secret, persisted row) pair so
/// the test can compute valid TOTP codes against the same secret.
fn fresh_authenticator(now_unix: i64) -> (Secret, TotpAuthenticator) {
    let secret = Secret::from_bytes(vec![0xAB; cesauth_core::totp::SECRET_BYTES]).unwrap();
    let aad = aad(AUTH_ID);
    let (ciphertext, nonce_bytes) = encrypt_secret(&secret, &fixed_key(), &aad).unwrap();
    let row = TotpAuthenticator {
        id:                AUTH_ID.to_owned(),
        user_id:           USER_ID.to_owned(),
        secret_ciphertext: ciphertext,
        secret_nonce:      nonce_bytes.to_vec(),
        secret_key_id:     KEY_ID.to_owned(),
        last_used_step:    0,
        name:              None,
        created_at:        now_unix - 1000,
        last_used_at:      None,
        confirmed_at:      Some(now_unix - 1000),
    };
    (secret, row)
}

async fn fixture_totp_pending(
    attempts: u32,
) -> (InMemoryAuthChallengeStore, InMemoryTotpAuthenticatorRepository, Secret, i64) {
    let store = InMemoryAuthChallengeStore::default();
    let now_unix = 1_700_000_000_i64;
    store.put(TOTP_HANDLE, &Challenge::PendingTotp {
        user_id:                 USER_ID.to_owned(),
        auth_method:             AuthMethod::MagicLink,
        ar_client_id:            None,
        ar_redirect_uri:         None,
        ar_scope:                None,
        ar_state:                None,
        ar_nonce:                None,
        ar_code_challenge:       None,
        ar_code_challenge_method:None,
        attempts,
        expires_at:              now_unix + 600,
    }).await.unwrap();

    let totp_repo = InMemoryTotpAuthenticatorRepository::default();
    let (secret, row) = fresh_authenticator(now_unix);
    totp_repo.create(&row).await.unwrap();

    (store, totp_repo, secret, now_unix)
}

fn matched_csrf_v() -> (String, String) {
    let token = csrf::mint();
    (token.clone(), token)
}

// ----- happy path -----

#[tokio::test]
async fn verify_post_correct_code_returns_success_and_persists_last_used_step() {
    let (store, totp_repo, secret, now) = fixture_totp_pending(0).await;
    let step = step_for_unix(now);
    let code = format!("{:06}", compute_code(&secret, step));
    let (form, cookie) = matched_csrf_v();

    let decision = decide_verify_post(
        &form, &cookie, &code, TOTP_HANDLE,
        &store, &totp_repo, &fixed_key(), now,
    ).await;

    match decision {
        VerifyPostDecision::Success { user_id, auth_method, ar_fields } => {
            assert_eq!(user_id, USER_ID);
            assert_eq!(auth_method, AuthMethod::MagicLink);
            assert!(ar_fields.is_none());
        }
        other => panic!("expected Success, got {other:?}"),
    }

    // last_used_step persisted (replay protection).
    let stored = totp_repo.find_by_id(AUTH_ID).await.unwrap().unwrap();
    assert!(stored.last_used_step >= step,
        "last_used_step must advance past the verified step");
    assert!(stored.last_used_at.is_some());

    // Challenge consumed.
    assert!(store.peek(TOTP_HANDLE).await.unwrap().is_none());
}

// ----- CSRF -----

#[tokio::test]
async fn verify_post_csrf_failure_does_not_take_challenge_or_touch_state() {
    let (store, totp_repo, _, now) = fixture_totp_pending(0).await;

    let decision = decide_verify_post(
        "wrong", "right", "123456", TOTP_HANDLE,
        &store, &totp_repo, &fixed_key(), now,
    ).await;
    assert!(matches!(decision, VerifyPostDecision::CsrfFailure));

    // Challenge preserved.
    assert!(store.peek(TOTP_HANDLE).await.unwrap().is_some());
    // last_used_step untouched.
    let stored = totp_repo.find_by_id(AUTH_ID).await.unwrap().unwrap();
    assert_eq!(stored.last_used_step, 0);
}

// ----- no challenge / wrong handle -----

#[tokio::test]
async fn verify_post_unknown_handle_returns_no_challenge() {
    let (store, totp_repo, _, now) = fixture_totp_pending(0).await;
    let (form, cookie) = matched_csrf_v();

    let decision = decide_verify_post(
        &form, &cookie, "000000", "wrong-handle",
        &store, &totp_repo, &fixed_key(), now,
    ).await;
    assert!(matches!(decision, VerifyPostDecision::NoChallenge));
}

// ----- find_active_for_user None: soft success -----

#[tokio::test]
async fn verify_post_no_user_authenticator_yields_soft_success_passthrough() {
    let (store, _, _, now) = fixture_totp_pending(0).await;
    // Empty totp_repo — user has no authenticator (e.g., admin
    // disabled it between gate-park and now).
    let totp_repo = InMemoryTotpAuthenticatorRepository::default();
    let (form, cookie) = matched_csrf_v();

    let decision = decide_verify_post(
        &form, &cookie, "000000", TOTP_HANDLE,
        &store, &totp_repo, &fixed_key(), now,
    ).await;

    match decision {
        VerifyPostDecision::NoUserAuthenticator { user_id, auth_method, ar_fields } => {
            assert_eq!(user_id, USER_ID);
            assert_eq!(auth_method, AuthMethod::MagicLink);
            assert!(ar_fields.is_none());
        }
        other => panic!("expected NoUserAuthenticator, got {other:?}"),
    }
}

// ----- decryption failure -----

#[tokio::test]
async fn verify_post_wrong_encryption_key_returns_decrypt_failed() {
    let (store, totp_repo, _, now) = fixture_totp_pending(0).await;
    let wrong_key: Vec<u8> = (0u8..32).map(|b| b ^ 0xFF).collect();
    let (form, cookie) = matched_csrf_v();

    let decision = decide_verify_post(
        &form, &cookie, "000000", TOTP_HANDLE,
        &store, &totp_repo, &wrong_key, now,
    ).await;
    assert!(matches!(decision, VerifyPostDecision::DecryptFailed));
    // Challenge consumed (we passed the take step).
    assert!(store.peek(TOTP_HANDLE).await.unwrap().is_none());
}

// ----- wrong code under threshold: re-park with BadCode -----

#[tokio::test]
async fn verify_post_wrong_code_under_threshold_returns_bad_code_and_reparks() {
    // Start with attempts=2; one wrong code → 3 → still under
    // MAX_ATTEMPTS (5).
    let (store, totp_repo, _, now) = fixture_totp_pending(2).await;
    let (form, cookie) = matched_csrf_v();

    let decision = decide_verify_post(
        &form, &cookie, "000000", TOTP_HANDLE,
        &store, &totp_repo, &fixed_key(), now,
    ).await;
    assert!(matches!(decision, VerifyPostDecision::BadCode));

    // Challenge re-parked with attempts incremented.
    let parked = store.peek(TOTP_HANDLE).await.unwrap().expect("re-parked");
    match parked {
        Challenge::PendingTotp { attempts, .. } => assert_eq!(attempts, 3),
        other => panic!("expected PendingTotp, got {other:?}"),
    }

    // last_used_step NOT advanced.
    let stored = totp_repo.find_by_id(AUTH_ID).await.unwrap().unwrap();
    assert_eq!(stored.last_used_step, 0);
}

// ----- wrong code AT threshold: Lockout, gate cleared -----

#[tokio::test]
async fn verify_post_wrong_code_at_threshold_returns_lockout_no_repark() {
    // attempts=4; one wrong → 5 → MAX_ATTEMPTS → Lockout.
    let (store, totp_repo, _, now) = fixture_totp_pending(MAX_ATTEMPTS - 1).await;
    let (form, cookie) = matched_csrf_v();

    let decision = decide_verify_post(
        &form, &cookie, "000000", TOTP_HANDLE,
        &store, &totp_repo, &fixed_key(), now,
    ).await;
    assert!(matches!(decision, VerifyPostDecision::Lockout));

    // Challenge consumed (taken at step 2) and NOT re-parked
    // (lockout branch returns before put). The user must restart
    // from /login.
    assert!(store.peek(TOTP_HANDLE).await.unwrap().is_none(),
        "lockout must not re-park the challenge");
}

// ----- malformed code parses as parse-error → BadCode (not lockout) -----

#[tokio::test]
async fn verify_post_malformed_code_treated_as_bad_code() {
    // A non-digit code should fail parse_code, count as wrong,
    // and re-park (NOT 400). Generic message doesn't leak whether
    // parse or verify failed.
    let (store, totp_repo, _, now) = fixture_totp_pending(0).await;
    let (form, cookie) = matched_csrf_v();

    let decision = decide_verify_post(
        &form, &cookie, "abcdef", TOTP_HANDLE,
        &store, &totp_repo, &fixed_key(), now,
    ).await;
    assert!(matches!(decision, VerifyPostDecision::BadCode));

    let parked = store.peek(TOTP_HANDLE).await.unwrap().expect("re-parked");
    match parked {
        Challenge::PendingTotp { attempts, .. } => assert_eq!(attempts, 1),
        _ => panic!(),
    }
}

// ----- find_active_for_user storage error -----

#[tokio::test]
async fn verify_post_find_active_storage_error_returns_storage_error() {
    /// Authenticator repo wrapper that errors on
    /// find_active_for_user but otherwise delegates to inner.
    struct FailingFindRepo {
        inner: InMemoryTotpAuthenticatorRepository,
    }
    impl cesauth_core::totp::storage::TotpAuthenticatorRepository for FailingFindRepo {
        async fn create(&self, row: &TotpAuthenticator) -> cesauth_core::ports::PortResult<()> {
            self.inner.create(row).await
        }
        async fn find_by_id(&self, id: &str) -> cesauth_core::ports::PortResult<Option<TotpAuthenticator>> {
            self.inner.find_by_id(id).await
        }
        async fn find_active_for_user(&self, _user_id: &str) -> cesauth_core::ports::PortResult<Option<TotpAuthenticator>> {
            Err(PortError::Unavailable)
        }
        async fn confirm(&self, _: &str, _: u64, _: i64) -> cesauth_core::ports::PortResult<()> { unimplemented!() }
        async fn update_last_used_step(&self, _: &str, _: u64, _: i64) -> cesauth_core::ports::PortResult<()> { unimplemented!() }
        async fn delete(&self, _: &str) -> cesauth_core::ports::PortResult<()> { unimplemented!() }
        async fn delete_all_for_user(&self, _: &str) -> cesauth_core::ports::PortResult<()> { unimplemented!() }
        async fn list_unconfirmed_older_than(&self, _: i64) -> cesauth_core::ports::PortResult<Vec<String>> { unimplemented!() }
    }

    let (store, inner_repo, _, now) = fixture_totp_pending(0).await;
    let totp_repo = FailingFindRepo { inner: inner_repo };
    let (form, cookie) = matched_csrf_v();

    let decision = decide_verify_post(
        &form, &cookie, "000000", TOTP_HANDLE,
        &store, &totp_repo, &fixed_key(), now,
    ).await;
    assert!(matches!(decision, VerifyPostDecision::StorageError),
        "find_active_for_user error must be StorageError, distinct from NoUserAuthenticator");
}
