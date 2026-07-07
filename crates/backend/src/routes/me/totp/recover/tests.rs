//! Tests for the recover handler — exercises
//! [`decide_recover_post`] across its branch table using
//! in-memory adapters.
//!
//! See `disable/tests.rs` for the broader rationale on
//! decision-extraction testing under v0.31.1 P1-B.

use super::*;

use cesauth_adapter_test::repo::InMemoryTotpRecoveryCodeRepository;
use cesauth_adapter_test::store::InMemoryAuthChallengeStore;
use cesauth_core::ports::store::{AuthMethod, Challenge};
use cesauth_core::totp::{hash_recovery_code, storage::TotpRecoveryCodeRow};

const USER_ID:     &str = "usr_test_alice";
const TOTP_HANDLE: &str = "handle_test_xyz";

/// Build the in-memory test fixtures: a challenge store with a
/// PendingTotp parked under TOTP_HANDLE for USER_ID, and a
/// recovery repo with one unredeemed code whose plaintext is
/// known.
async fn fixture_with_pending_totp_and_codes(
    plaintext_codes: &[&str],
) -> (InMemoryAuthChallengeStore, InMemoryTotpRecoveryCodeRepository) {
    let store = InMemoryAuthChallengeStore::default();
    let challenge = Challenge::PendingTotp {
        user_id:                 USER_ID.to_owned(),
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
    };
    store.put(TOTP_HANDLE, &challenge).await.expect("park challenge");

    let recovery_repo = InMemoryTotpRecoveryCodeRepository::default();
    let rows: Vec<TotpRecoveryCodeRow> = plaintext_codes.iter()
        .enumerate()
        .map(|(i, plaintext)| TotpRecoveryCodeRow {
            id:           format!("rec_{i}"),
            user_id:      USER_ID.to_owned(),
            code_hash:    hash_recovery_code(plaintext),
            redeemed_at:  None,
            created_at:   100,
        })
        .collect();
    recovery_repo.bulk_create(&rows).await.expect("seed codes");
    (store, recovery_repo)
}

fn matched_csrf() -> (String, String) {
    let token = csrf::mint();
    (token.clone(), token)
}

// =====================================================================
// Happy path
// =====================================================================

#[tokio::test]
async fn recover_normal_path_returns_success_and_consumes_code_and_challenge() {
    let plaintext = "ALPHA-BRAVO";
    let (store, recovery_repo) = fixture_with_pending_totp_and_codes(&[plaintext, "OTHER-CODE"]).await;
    let (form, cookie) = matched_csrf();

    let decision = decide_recover_post(
        &form, &cookie, plaintext, TOTP_HANDLE,
        &store, &recovery_repo, 200,
    ).await;

    match decision {
        RecoverDecision::Success { user_id, auth_method, ar_fields } => {
            assert_eq!(user_id, USER_ID);
            assert_eq!(auth_method, AuthMethod::MagicLink);
            assert!(ar_fields.is_none(),
                "no AR was parked; ar_fields should be None");
        }
        other => panic!("expected Success, got {other:?}"),
    }

    // Challenge consumed.
    assert!(store.peek(TOTP_HANDLE).await.unwrap().is_none(),
        "challenge must be taken on success");

    // The redeemed code is gone from the unredeemed set; the other
    // one remains.
    let remaining = recovery_repo.find_unredeemed_by_hash(USER_ID, &hash_recovery_code(plaintext))
        .await.unwrap();
    assert!(remaining.is_none(), "redeemed code must not be returnable");
    let other = recovery_repo.find_unredeemed_by_hash(USER_ID, &hash_recovery_code("OTHER-CODE"))
        .await.unwrap();
    assert!(other.is_some(), "other unredeemed codes must remain");
}

// =====================================================================
// CSRF gate
// =====================================================================

#[tokio::test]
async fn recover_csrf_mismatch_returns_csrf_failure_and_does_not_consume_challenge() {
    let plaintext = "ALPHA-BRAVO";
    let (store, recovery_repo) = fixture_with_pending_totp_and_codes(&[plaintext]).await;

    let decision = decide_recover_post(
        "wrong", "right", plaintext, TOTP_HANDLE,
        &store, &recovery_repo, 200,
    ).await;

    assert!(matches!(decision, RecoverDecision::CsrfFailure));

    // Challenge must NOT be consumed — user can retry with a fresh form.
    assert!(store.peek(TOTP_HANDLE).await.unwrap().is_some(),
        "CSRF failure must not destroy the challenge");

    // Recovery code must NOT be redeemed.
    let still_there = recovery_repo.find_unredeemed_by_hash(USER_ID, &hash_recovery_code(plaintext))
        .await.unwrap();
    assert!(still_there.is_some(), "CSRF failure must not redeem the code");
}

#[tokio::test]
async fn recover_empty_csrf_strings_rejected_as_csrf_failure() {
    let (store, recovery_repo) = fixture_with_pending_totp_and_codes(&["X"]).await;
    let decision = decide_recover_post("", "", "X", TOTP_HANDLE, &store, &recovery_repo, 0).await;
    assert!(matches!(decision, RecoverDecision::CsrfFailure));
    // Preserved.
    assert!(store.peek(TOTP_HANDLE).await.unwrap().is_some());
}

// =====================================================================
// Empty code
// =====================================================================

#[tokio::test]
async fn recover_empty_code_returns_empty_code() {
    let (store, recovery_repo) = fixture_with_pending_totp_and_codes(&["ALPHA"]).await;
    let (form, cookie) = matched_csrf();
    let decision = decide_recover_post(&form, &cookie, "", TOTP_HANDLE, &store, &recovery_repo, 0).await;
    assert!(matches!(decision, RecoverDecision::EmptyCode));
    // Challenge preserved.
    assert!(store.peek(TOTP_HANDLE).await.unwrap().is_some());
}

// =====================================================================
// No challenge / wrong handle
// =====================================================================

#[tokio::test]
async fn recover_unknown_handle_returns_no_challenge() {
    let (store, recovery_repo) = fixture_with_pending_totp_and_codes(&["X"]).await;
    let (form, cookie) = matched_csrf();
    let decision = decide_recover_post(
        &form, &cookie, "X", "wrong-handle",
        &store, &recovery_repo, 0,
    ).await;
    assert!(matches!(decision, RecoverDecision::NoChallenge));
}

#[tokio::test]
async fn recover_wrong_challenge_kind_returns_no_challenge() {
    // Park a non-PendingTotp challenge under the handle.
    let store = InMemoryAuthChallengeStore::default();
    let challenge = Challenge::PendingAuthorize {
        client_id:             "c".to_owned(),
        redirect_uri:          "http://x".to_owned(),
        scope:                 None,
        state:                 None,
        nonce:                 None,
        code_challenge:        "z".to_owned(),
        code_challenge_method: "S256".to_owned(),
        expires_at:            i64::MAX,
    };
    store.put(TOTP_HANDLE, &challenge).await.unwrap();
    let recovery_repo = InMemoryTotpRecoveryCodeRepository::default();
    let (form, cookie) = matched_csrf();

    let decision = decide_recover_post(
        &form, &cookie, "X", TOTP_HANDLE,
        &store, &recovery_repo, 0,
    ).await;
    assert!(matches!(decision, RecoverDecision::NoChallenge));
}

// =====================================================================
// No matching code
// =====================================================================

#[tokio::test]
async fn recover_unknown_code_returns_no_matching_code_and_consumes_challenge() {
    let plaintext = "ALPHA-BRAVO";
    let (store, recovery_repo) = fixture_with_pending_totp_and_codes(&[plaintext]).await;
    let (form, cookie) = matched_csrf();

    // Submit a code that doesn't hash to any stored row.
    let decision = decide_recover_post(
        &form, &cookie, "WRONG-CODE", TOTP_HANDLE,
        &store, &recovery_repo, 0,
    ).await;

    assert!(matches!(decision, RecoverDecision::NoMatchingCode));
    // Challenge consumed (we passed the take step before lookup).
    // The handler clears the gate and bounces; the user starts
    // over from /login.
    assert!(store.peek(TOTP_HANDLE).await.unwrap().is_none(),
        "challenge consumption is irreversible past the take step");
    // Real code remains unredeemed.
    let still_there = recovery_repo.find_unredeemed_by_hash(USER_ID, &hash_recovery_code(plaintext))
        .await.unwrap();
    assert!(still_there.is_some());
}

// =====================================================================
// Storage error vs no-match — make sure they don't collapse
// =====================================================================

#[tokio::test]
async fn recover_recovery_lookup_storage_error_returns_storage_error() {
    /// Recovery repo wrapper that errors on lookup.
    struct FailingLookupRepo;
    impl cesauth_core::totp::storage::TotpRecoveryCodeRepository for FailingLookupRepo {
        async fn bulk_create(&self, _: &[TotpRecoveryCodeRow]) -> cesauth_core::ports::PortResult<()> { unimplemented!() }
        async fn find_unredeemed_by_hash(&self, _: &str, _: &str) -> cesauth_core::ports::PortResult<Option<TotpRecoveryCodeRow>> {
            Err(cesauth_core::ports::PortError::Unavailable)
        }
        async fn mark_redeemed(&self, _: &str, _: i64) -> cesauth_core::ports::PortResult<()> { unimplemented!() }
        async fn count_remaining(&self, _: &str) -> cesauth_core::ports::PortResult<u32> { unimplemented!() }
        async fn delete_all_for_user(&self, _: &str) -> cesauth_core::ports::PortResult<()> { unimplemented!() }
    }

    let (store, _) = fixture_with_pending_totp_and_codes(&["X"]).await;
    let recovery_repo = FailingLookupRepo;
    let (form, cookie) = matched_csrf();

    let decision = decide_recover_post(
        &form, &cookie, "X", TOTP_HANDLE,
        &store, &recovery_repo, 0,
    ).await;
    assert!(matches!(decision, RecoverDecision::StorageError),
        "lookup error must be StorageError, NOT NoMatchingCode");
}

// =====================================================================
// mark_redeemed race
// =====================================================================

#[tokio::test]
async fn recover_mark_redeemed_failure_returns_mark_redeemed_failed() {
    /// Repo that finds the row but fails to mark it redeemed.
    struct RaceLossRepo {
        inner: InMemoryTotpRecoveryCodeRepository,
    }
    impl cesauth_core::totp::storage::TotpRecoveryCodeRepository for RaceLossRepo {
        async fn bulk_create(&self, rows: &[TotpRecoveryCodeRow]) -> cesauth_core::ports::PortResult<()> {
            self.inner.bulk_create(rows).await
        }
        async fn find_unredeemed_by_hash(&self, user_id: &str, code_hash: &str) -> cesauth_core::ports::PortResult<Option<TotpRecoveryCodeRow>> {
            self.inner.find_unredeemed_by_hash(user_id, code_hash).await
        }
        async fn mark_redeemed(&self, _id: &str, _now: i64) -> cesauth_core::ports::PortResult<()> {
            Err(cesauth_core::ports::PortError::Unavailable)
        }
        async fn count_remaining(&self, _: &str) -> cesauth_core::ports::PortResult<u32> { unimplemented!() }
        async fn delete_all_for_user(&self, _: &str) -> cesauth_core::ports::PortResult<()> { unimplemented!() }
    }

    let plaintext = "ALPHA-BRAVO";
    let (store, inner_repo) = fixture_with_pending_totp_and_codes(&[plaintext]).await;
    let recovery_repo = RaceLossRepo { inner: inner_repo };
    let (form, cookie) = matched_csrf();

    let decision = decide_recover_post(
        &form, &cookie, plaintext, TOTP_HANDLE,
        &store, &recovery_repo, 0,
    ).await;

    assert!(matches!(decision, RecoverDecision::MarkRedeemedFailed));
    // Challenge already consumed by the take step.
    assert!(store.peek(TOTP_HANDLE).await.unwrap().is_none());
}

// =====================================================================
// Code canonicalization works through the decision
// =====================================================================

#[tokio::test]
async fn recover_canonicalizes_submitted_code() {
    // Pin that the decision uses `hash_recovery_code` (which
    // strips whitespace + dashes + uppercases). A user pasting
    // "alpha bravo" or "ALPHABRAVO" or "alpha-bravo" should all
    // redeem the same stored row.
    //
    // The pin is important because if a future refactor swapped
    // `hash_recovery_code` for raw `sha256`, this test breaks
    // and the user-paste-friendliness regresses.
    let stored = "ALPHA-BRAVO";
    let (store, recovery_repo) = fixture_with_pending_totp_and_codes(&[stored]).await;
    let (form, cookie) = matched_csrf();

    // Submit lowercase + with spaces.
    let decision = decide_recover_post(
        &form, &cookie, "alpha bravo", TOTP_HANDLE,
        &store, &recovery_repo, 200,
    ).await;
    assert!(matches!(decision, RecoverDecision::Success { .. }),
        "lowercased + whitespaced input should canonicalize to the stored hash");
}
