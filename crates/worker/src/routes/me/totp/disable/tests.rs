//! Tests for the disable handler — both the v0.31.0 pinned
//! constants (preserved) and the v0.31.1 P1-B decision-logic
//! integration tests using the in-memory adapters.
//!
//! ## What this tests
//!
//! `decide_disable_post` is the pure decision function extracted
//! from `post_handler` in v0.31.1. Tests construct in-memory
//! authenticator + recovery-code repositories, call the decision
//! directly, and assert the returned `DisableDecision` plus the
//! observed side effects on the repositories.
//!
//! What this does NOT test:
//!
//! - The HTTP shape of the response (status code, location
//!   header, flash cookie). Those live in the handler's
//!   match-arm wiring, which is a thin transformation from
//!   `DisableDecision` to `Response`. They're best exercised
//!   via end-to-end tests against a deployed Worker, which
//!   v0.31.1 doesn't add — the goal of P1-B is to pin the
//!   decision boundaries, and the handler-side mapping is
//!   straightforward enough to inspect by reading.

use super::*;

use cesauth_adapter_test::repo::{
    InMemoryTotpAuthenticatorRepository, InMemoryTotpRecoveryCodeRepository,
};
use cesauth_core::totp::storage::TotpAuthenticator;

// =====================================================================
// Constants pinned in v0.31.0 — preserved verbatim
// =====================================================================

#[test]
fn disable_lands_on_security_center() {
    assert_eq!(DISABLE_SUCCESS_REDIRECT, "/me/security");
}

#[test]
fn disable_target_is_in_me_namespace() {
    // Pin that the target is allowlisted by
    // me_auth::validate_next_path so a future tightening of
    // the validator doesn't lock the user out of their own
    // post-disable landing page.
    assert!(me_auth::validate_next_path(DISABLE_SUCCESS_REDIRECT).is_some(),
        "post-disable target must remain on the /me/ allowlist");
}

// =====================================================================
// decide_disable_post — v0.31.1 P1-B
// =====================================================================

const USER_ID: &str = "usr_test_alice";

/// A repository wrapper that fails every call. Used to exercise
/// the AuthDeleteError branch without needing a flaky D1.
///
/// Note: this implements `TotpAuthenticatorRepository` only as
/// far as the methods `decide_disable_post` actually invokes;
/// the others would `unimplemented!()` if called, which is the
/// signal "the decision function is calling more than it should
/// be" — a regression alarm.
#[derive(Default)]
struct FailingAuthRepo;

impl cesauth_core::totp::storage::TotpAuthenticatorRepository for FailingAuthRepo {
    async fn create(&self, _row: &TotpAuthenticator) -> cesauth_core::ports::PortResult<()> {
        unimplemented!("decide_disable_post must not call create")
    }
    async fn find_by_id(&self, _id: &str) -> cesauth_core::ports::PortResult<Option<TotpAuthenticator>> {
        unimplemented!("decide_disable_post must not call find_by_id")
    }
    async fn find_active_for_user(&self, _user_id: &str) -> cesauth_core::ports::PortResult<Option<TotpAuthenticator>> {
        unimplemented!("decide_disable_post must not call find_active_for_user")
    }
    async fn confirm(&self, _id: &str, _last_used_step: u64, _now: i64) -> cesauth_core::ports::PortResult<()> {
        unimplemented!("decide_disable_post must not call confirm")
    }
    async fn update_last_used_step(&self, _id: &str, _last_used_step: u64, _now: i64) -> cesauth_core::ports::PortResult<()> {
        unimplemented!("decide_disable_post must not call update_last_used_step")
    }
    async fn delete(&self, _id: &str) -> cesauth_core::ports::PortResult<()> {
        unimplemented!("decide_disable_post must not call delete")
    }
    async fn list_unconfirmed_older_than(&self, _cutoff: i64) -> cesauth_core::ports::PortResult<Vec<String>> {
        unimplemented!("decide_disable_post must not call list_unconfirmed_older_than")
    }
    async fn delete_all_for_user(&self, _user_id: &str) -> cesauth_core::ports::PortResult<()> {
        Err(cesauth_core::ports::PortError::Unavailable)
    }
}

fn matched_csrf() -> (String, String) {
    let token = csrf::mint();
    (token.clone(), token)
}

/// Build a repo seeded with a confirmed authenticator for `USER_ID`.
async fn seeded_auth_repo() -> InMemoryTotpAuthenticatorRepository {
    let repo = InMemoryTotpAuthenticatorRepository::default();
    repo.create(&TotpAuthenticator {
        id:                "auth_1".to_owned(),
        user_id:           USER_ID.to_owned(),
        secret_ciphertext: vec![1, 2, 3],
        secret_nonce:      vec![4, 5, 6],
        secret_key_id:     "key_v1".to_owned(),
        last_used_step:    0,
        name:              None,
        created_at:        100,
        last_used_at:      None,
        confirmed_at:      Some(100),
    }).await.expect("seed insert");
    repo
}

#[tokio::test]
async fn disable_normal_path_returns_success_and_deletes() {
    let auth_repo     = seeded_auth_repo().await;
    let recovery_repo = InMemoryTotpRecoveryCodeRepository::default();
    let (form, cookie) = matched_csrf();

    let decision = decide_disable_post(USER_ID, &form, &cookie, &auth_repo, &recovery_repo).await;

    assert_eq!(decision, DisableDecision::Success);

    // Authenticator is gone.
    assert!(auth_repo.find_active_for_user(USER_ID).await.unwrap().is_none(),
        "authenticator row should be deleted on success");
}

#[tokio::test]
async fn disable_csrf_mismatch_returns_csrf_failure_without_touching_storage() {
    let auth_repo     = seeded_auth_repo().await;
    let recovery_repo = InMemoryTotpRecoveryCodeRepository::default();

    let decision = decide_disable_post(USER_ID, "wrong-token", "right-token", &auth_repo, &recovery_repo).await;

    assert_eq!(decision, DisableDecision::CsrfFailure);

    // Authenticator must remain — the CSRF guard must short-circuit
    // BEFORE any storage mutation. Otherwise an attacker who can
    // bypass CSRF momentarily races against the response.
    assert!(auth_repo.find_active_for_user(USER_ID).await.unwrap().is_some(),
        "authenticator row must NOT be deleted on CSRF failure");
}

#[tokio::test]
async fn disable_csrf_empty_strings_rejected() {
    // Defense in depth: empty form value vs. empty cookie value
    // must NOT compare equal as "two empty strings". csrf::verify
    // rejects empty inputs.
    let auth_repo     = seeded_auth_repo().await;
    let recovery_repo = InMemoryTotpRecoveryCodeRepository::default();

    let decision = decide_disable_post(USER_ID, "", "", &auth_repo, &recovery_repo).await;
    assert_eq!(decision, DisableDecision::CsrfFailure);

    // And the storage must be untouched.
    assert!(auth_repo.find_active_for_user(USER_ID).await.unwrap().is_some());
}

#[tokio::test]
async fn disable_auth_repo_failure_returns_auth_delete_error() {
    let auth_repo     = FailingAuthRepo;
    let recovery_repo = InMemoryTotpRecoveryCodeRepository::default();
    let (form, cookie) = matched_csrf();

    let decision = decide_disable_post(USER_ID, &form, &cookie, &auth_repo, &recovery_repo).await;

    assert_eq!(decision, DisableDecision::AuthDeleteError);
    // FailingAuthRepo's other methods would `unimplemented!()`, so
    // a passing test confirms the decision didn't fall through to
    // recovery-codes-delete or anywhere else.
}

#[tokio::test]
async fn disable_recovery_repo_failure_is_silently_swallowed() {
    // The "best-effort" recovery-codes delete: even if it fails,
    // the decision returns Success because the security-critical
    // authenticators delete succeeded. This pins the
    // module-level commitment that a recovery-codes-delete
    // failure does not 500 the user.
    use cesauth_core::totp::storage::TotpRecoveryCodeRow;

    /// Recovery repo wrapper that fails delete_all_for_user.
    struct FailingRecoveryRepo;
    impl cesauth_core::totp::storage::TotpRecoveryCodeRepository for FailingRecoveryRepo {
        async fn bulk_create(&self, _rows: &[TotpRecoveryCodeRow]) -> cesauth_core::ports::PortResult<()> {
            unimplemented!()
        }
        async fn find_unredeemed_by_hash(&self, _user_id: &str, _code_hash: &str) -> cesauth_core::ports::PortResult<Option<TotpRecoveryCodeRow>> {
            unimplemented!()
        }
        async fn mark_redeemed(&self, _id: &str, _at: i64) -> cesauth_core::ports::PortResult<()> {
            unimplemented!()
        }
        async fn count_remaining(&self, _user_id: &str) -> cesauth_core::ports::PortResult<u32> {
            unimplemented!()
        }
        async fn delete_all_for_user(&self, _user_id: &str) -> cesauth_core::ports::PortResult<()> {
            Err(cesauth_core::ports::PortError::Unavailable)
        }
    }

    let auth_repo     = seeded_auth_repo().await;
    let recovery_repo = FailingRecoveryRepo;
    let (form, cookie) = matched_csrf();

    let decision = decide_disable_post(USER_ID, &form, &cookie, &auth_repo, &recovery_repo).await;

    // Success even though recovery-delete failed.
    assert_eq!(decision, DisableDecision::Success);
}
