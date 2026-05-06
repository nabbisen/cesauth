//! Tests for the enroll handlers (v0.31.1 P1-B).
//!
//! `decide_enroll_get` is the pure-ish decision function for the
//! GET enrollment start. Tests construct in-memory authenticator
//! repositories, build a deterministic Secret + row_id, exercise
//! the decision, and assert the persisted row + the returned
//! page-render data.

use super::*;

use cesauth_adapter_test::repo::InMemoryTotpAuthenticatorRepository;
use cesauth_core::ports::PortError;
use cesauth_core::totp::Secret;
use cesauth_core::totp::storage::TotpAuthenticatorRepository as _;

const USER_ID:    &str = "usr_test_alice";
const USER_EMAIL: &str = "alice@example.com";
const ROW_ID:     &str = "auth_test_xyz";
const KEY_ID:     &str = "totp-key-v1";

fn fixed_secret() -> Secret {
    Secret::from_bytes(vec![0xCD; cesauth_core::totp::SECRET_BYTES]).unwrap()
}

fn fixed_key() -> Vec<u8> { (0u8..32).collect() }

// =====================================================================
// decide_enroll_get — happy path
// =====================================================================

#[tokio::test]
async fn enroll_get_success_inserts_unconfirmed_row_and_returns_render_data() {
    let totp_repo = InMemoryTotpAuthenticatorRepository::default();
    let secret    = fixed_secret();

    let decision = decide_enroll_get(
        USER_ID, USER_EMAIL,
        &secret, ROW_ID,
        &fixed_key(), KEY_ID,
        &totp_repo, 1_700_000_000,
    ).await;

    let (b32, qr) = match decision {
        EnrollGetDecision::Success { secret_b32, qr_svg } => (secret_b32, qr_svg),
        other => panic!("expected Success, got {other:?}"),
    };

    // The base32 form mirrors the Secret's view (verifies the
    // decision didn't substitute a different secret somewhere).
    assert_eq!(b32, secret.to_base32());

    // QR is non-empty SVG content (with XML preamble).
    assert!(qr.contains("<svg"),
        "qr_svg must contain <svg ...>; got prefix {:?}", &qr.chars().take(40).collect::<String>());

    // Row inserted, unconfirmed (confirmed_at: None), bound to user.
    let row = totp_repo.find_by_id(ROW_ID).await.unwrap()
        .expect("row inserted");
    assert_eq!(row.user_id, USER_ID);
    assert_eq!(row.secret_key_id, KEY_ID);
    assert!(row.confirmed_at.is_none(),
        "freshly-enrolled row must be unconfirmed");
    assert_eq!(row.last_used_step, 0);

    // Verify the encrypted blob is round-trippable with the
    // same key + AAD.
    let aad = cesauth_core::totp::aad_for_id(ROW_ID);
    let plaintext = cesauth_core::totp::decrypt_secret(
        &row.secret_ciphertext, &row.secret_nonce,
        &fixed_key(), &aad,
    ).unwrap();
    assert_eq!(plaintext.to_base32(), secret.to_base32(),
        "encrypted secret must decrypt back to the original");
}

// =====================================================================
// EncryptError — wrong key length
// =====================================================================

#[tokio::test]
async fn enroll_get_wrong_key_length_returns_encrypt_error() {
    let totp_repo = InMemoryTotpAuthenticatorRepository::default();
    let secret    = fixed_secret();
    let bad_key   = vec![0u8; 16];   // valid AES-GCM key sizes are 16/24/32; 16 is wrong here per ENCRYPTION_KEY_LEN=32

    let decision = decide_enroll_get(
        USER_ID, USER_EMAIL,
        &secret, ROW_ID,
        &bad_key, KEY_ID,
        &totp_repo, 1_700_000_000,
    ).await;
    assert!(matches!(decision, EnrollGetDecision::EncryptError),
        "wrong-length key must map to EncryptError before any storage write");

    // Row must NOT have been inserted.
    assert!(totp_repo.find_by_id(ROW_ID).await.unwrap().is_none(),
        "EncryptError must short-circuit BEFORE the create() call");
}

// =====================================================================
// StoreError — repository create fails
// =====================================================================

#[tokio::test]
async fn enroll_get_repo_create_failure_returns_store_error() {
    /// Repo wrapper that fails create. This pins the EncryptError-vs-
    /// StoreError distinction: an encryption failure must NOT
    /// silently degrade to "row inserted but encrypted with garbage";
    /// a storage failure must NOT pretend success.
    struct FailingCreateRepo;
    impl cesauth_core::totp::storage::TotpAuthenticatorRepository for FailingCreateRepo {
        async fn create(&self, _row: &TotpAuthenticator) -> cesauth_core::ports::PortResult<()> {
            Err(PortError::Unavailable)
        }
        async fn find_by_id(&self, _: &str) -> cesauth_core::ports::PortResult<Option<TotpAuthenticator>> { unimplemented!() }
        async fn find_active_for_user(&self, _: &str) -> cesauth_core::ports::PortResult<Option<TotpAuthenticator>> { unimplemented!() }
        async fn confirm(&self, _: &str, _: u64, _: i64) -> cesauth_core::ports::PortResult<()> { unimplemented!() }
        async fn update_last_used_step(&self, _: &str, _: u64, _: i64) -> cesauth_core::ports::PortResult<()> { unimplemented!() }
        async fn delete(&self, _: &str) -> cesauth_core::ports::PortResult<()> { unimplemented!() }
        async fn delete_all_for_user(&self, _: &str) -> cesauth_core::ports::PortResult<()> { unimplemented!() }
        async fn list_unconfirmed_older_than(&self, _: i64) -> cesauth_core::ports::PortResult<Vec<String>> { unimplemented!() }
    }

    let secret = fixed_secret();
    let decision = decide_enroll_get(
        USER_ID, USER_EMAIL, &secret, ROW_ID,
        &fixed_key(), KEY_ID, &FailingCreateRepo, 1_700_000_000,
    ).await;
    assert!(matches!(decision, EnrollGetDecision::StoreError),
        "create() failure must surface as StoreError, NOT silently succeed");
}

// =====================================================================
// AAD binding — pin that the row_id is part of the encryption AAD
// =====================================================================

// =====================================================================
// AAD binding — pin that the row_id is part of the encryption AAD
// =====================================================================

#[tokio::test]
async fn enroll_get_decryption_with_wrong_row_id_aad_fails() {
    // Pin that decrypt_secret must be called with the SAME row_id
    // that was used during encrypt — a row_id swap (e.g., a future
    // refactor that splits encryption from row creation and uses
    // a different id) breaks the AAD binding and decryption fails.
    let totp_repo = InMemoryTotpAuthenticatorRepository::default();
    let secret    = fixed_secret();
    let _ = decide_enroll_get(
        USER_ID, USER_EMAIL, &secret, ROW_ID,
        &fixed_key(), KEY_ID, &totp_repo, 1_700_000_000,
    ).await;

    let row = totp_repo.find_by_id(ROW_ID).await.unwrap().unwrap();

    // Decrypt with a wrong AAD ("totp:" + WRONG id) must fail.
    let bad_aad = cesauth_core::totp::aad_for_id("different_id");
    let result = cesauth_core::totp::decrypt_secret(
        &row.secret_ciphertext, &row.secret_nonce,
        &fixed_key(), &bad_aad,
    );
    assert!(result.is_err(),
        "AAD binding to row_id must reject decryption with wrong id");
}

// =====================================================================
// decide_enroll_confirm_post — v0.31.1 P1-B / v0.32.1
// =====================================================================
//
// Branch table:
// - CSRF mismatch → CsrfFailure
// - Unknown enroll_id / user mismatch → UnknownEnrollment
// - Already confirmed → AlreadyConfirmed
// - Decrypt fail → DecryptFailed
// - Wrong code → WrongCode { secret_b32 }
// - Right code, first enrollment → SuccessFirstEnrollment with codes
// - Right code, additional auth → SuccessAdditionalAuthenticator
// - confirm() race lost → ConfirmRaceLost

use cesauth_adapter_test::repo::InMemoryTotpRecoveryCodeRepository;
use cesauth_core::totp::{
    aad_for_id, compute_code, encrypt_secret, step_for_unix,
    storage::{TotpRecoveryCodeRepository as _, TotpRecoveryCodeRow},
};

const NOW_UNIX: i64 = 1_700_000_000;

fn matched_csrf_e() -> (String, String) {
    let token = csrf::mint();
    (token.clone(), token)
}

/// Build an in-memory totp_repo containing an unconfirmed row
/// with a known secret encrypted under fixed_key. Returns the
/// (Secret, totp_repo) pair so the test can compute valid codes.
async fn fixture_unconfirmed_row(user_id: &str, row_id: &str) -> (Secret, InMemoryTotpAuthenticatorRepository) {
    let totp_repo = InMemoryTotpAuthenticatorRepository::default();
    let secret = fixed_secret();
    let aad = aad_for_id(row_id);
    let (ciphertext, nonce) = encrypt_secret(&secret, &fixed_key(), &aad).unwrap();
    let row = TotpAuthenticator {
        id:                row_id.to_owned(),
        user_id:           user_id.to_owned(),
        secret_ciphertext: ciphertext,
        secret_nonce:      nonce.to_vec(),
        secret_key_id:     KEY_ID.to_owned(),
        last_used_step:    0,
        name:              None,
        created_at:        NOW_UNIX - 60,
        last_used_at:      None,
        confirmed_at:      None,
    };
    totp_repo.create(&row).await.unwrap();
    (secret, totp_repo)
}

// ----- happy path: first enrollment mints recovery codes -----

#[tokio::test]
async fn enroll_confirm_first_enrollment_mints_recovery_codes_and_confirms() {
    let (secret, totp_repo) = fixture_unconfirmed_row(USER_ID, ROW_ID).await;
    let recovery_repo = InMemoryTotpRecoveryCodeRepository::default();
    let code = format!("{:06}", compute_code(&secret, step_for_unix(NOW_UNIX)));
    let (form, cookie) = matched_csrf_e();

    let decision = decide_enroll_confirm_post(
        USER_ID, ROW_ID,
        &form, &cookie, &code,
        &fixed_key(),
        &totp_repo, &recovery_repo, NOW_UNIX,
    ).await;

    let codes = match decision {
        EnrollConfirmDecision::SuccessFirstEnrollment { plaintext_codes } => plaintext_codes,
        other => panic!("expected SuccessFirstEnrollment, got {other:?}"),
    };
    assert_eq!(codes.len(), 10, "first enrollment must mint 10 recovery codes per ADR-009");
    // Codes are non-empty and distinct.
    let unique: std::collections::HashSet<&String> = codes.iter().collect();
    assert_eq!(unique.len(), 10, "minted recovery codes must be distinct");

    // Row was confirmed.
    let row = totp_repo.find_by_id(ROW_ID).await.unwrap().unwrap();
    assert!(row.confirmed_at.is_some(), "confirm() must have flipped confirmed_at");

    // Recovery codes persisted (10 unredeemed entries).
    assert_eq!(recovery_repo.count_remaining(USER_ID).await.unwrap(), 10);
}

// ----- happy path: additional authenticator skips recovery codes -----

#[tokio::test]
async fn enroll_confirm_additional_authenticator_skips_recovery_codes() {
    let (secret, totp_repo) = fixture_unconfirmed_row(USER_ID, ROW_ID).await;
    let recovery_repo = InMemoryTotpRecoveryCodeRepository::default();
    // Pre-seed an existing recovery code (= user enrolled before).
    recovery_repo.bulk_create(&[TotpRecoveryCodeRow {
        id:           "rec_pre".to_owned(),
        user_id:      USER_ID.to_owned(),
        code_hash:    "deadbeef".to_owned(),
        redeemed_at:  None,
        created_at:   NOW_UNIX - 1000,
    }]).await.unwrap();

    let code = format!("{:06}", compute_code(&secret, step_for_unix(NOW_UNIX)));
    let (form, cookie) = matched_csrf_e();

    let decision = decide_enroll_confirm_post(
        USER_ID, ROW_ID,
        &form, &cookie, &code,
        &fixed_key(),
        &totp_repo, &recovery_repo, NOW_UNIX,
    ).await;
    assert!(matches!(decision, EnrollConfirmDecision::SuccessAdditionalAuthenticator),
        "second authenticator must NOT mint fresh recovery codes (ADR-009 §Q6)");

    // Row confirmed.
    let row = totp_repo.find_by_id(ROW_ID).await.unwrap().unwrap();
    assert!(row.confirmed_at.is_some());

    // Recovery codes count unchanged.
    assert_eq!(recovery_repo.count_remaining(USER_ID).await.unwrap(), 1,
        "existing recovery codes must not be re-minted");
}

// ----- CSRF -----

#[tokio::test]
async fn enroll_confirm_csrf_failure_does_not_touch_state() {
    let (_, totp_repo) = fixture_unconfirmed_row(USER_ID, ROW_ID).await;
    let recovery_repo = InMemoryTotpRecoveryCodeRepository::default();

    let decision = decide_enroll_confirm_post(
        USER_ID, ROW_ID,
        "wrong", "right", "000000",
        &fixed_key(),
        &totp_repo, &recovery_repo, NOW_UNIX,
    ).await;
    assert!(matches!(decision, EnrollConfirmDecision::CsrfFailure));

    // Row unchanged (still unconfirmed).
    let row = totp_repo.find_by_id(ROW_ID).await.unwrap().unwrap();
    assert!(row.confirmed_at.is_none());
}

// ----- ownership check -----

#[tokio::test]
async fn enroll_confirm_user_mismatch_returns_unknown_enrollment() {
    let (secret, totp_repo) = fixture_unconfirmed_row(USER_ID, ROW_ID).await;
    let recovery_repo = InMemoryTotpRecoveryCodeRepository::default();
    let code = format!("{:06}", compute_code(&secret, step_for_unix(NOW_UNIX)));
    let (form, cookie) = matched_csrf_e();

    let decision = decide_enroll_confirm_post(
        "different-user-id", ROW_ID,    // different user than the row
        &form, &cookie, &code,
        &fixed_key(),
        &totp_repo, &recovery_repo, NOW_UNIX,
    ).await;
    assert!(matches!(decision, EnrollConfirmDecision::UnknownEnrollment),
        "row owned by another user must be rejected as UnknownEnrollment");
    // Row remains untouched.
    let row = totp_repo.find_by_id(ROW_ID).await.unwrap().unwrap();
    assert!(row.confirmed_at.is_none());
}

#[tokio::test]
async fn enroll_confirm_unknown_enroll_id_returns_unknown_enrollment() {
    let (_, totp_repo) = fixture_unconfirmed_row(USER_ID, ROW_ID).await;
    let recovery_repo = InMemoryTotpRecoveryCodeRepository::default();
    let (form, cookie) = matched_csrf_e();

    let decision = decide_enroll_confirm_post(
        USER_ID, "unknown-id",
        &form, &cookie, "000000",
        &fixed_key(),
        &totp_repo, &recovery_repo, NOW_UNIX,
    ).await;
    assert!(matches!(decision, EnrollConfirmDecision::UnknownEnrollment));
}

// ----- already confirmed -----

#[tokio::test]
async fn enroll_confirm_already_confirmed_returns_already_confirmed() {
    let (secret, totp_repo) = fixture_unconfirmed_row(USER_ID, ROW_ID).await;
    // Confirm it once.
    totp_repo.confirm(ROW_ID, step_for_unix(NOW_UNIX), NOW_UNIX).await.unwrap();
    let recovery_repo = InMemoryTotpRecoveryCodeRepository::default();
    let code = format!("{:06}", compute_code(&secret, step_for_unix(NOW_UNIX)));
    let (form, cookie) = matched_csrf_e();

    let decision = decide_enroll_confirm_post(
        USER_ID, ROW_ID,
        &form, &cookie, &code,
        &fixed_key(),
        &totp_repo, &recovery_repo, NOW_UNIX,
    ).await;
    assert!(matches!(decision, EnrollConfirmDecision::AlreadyConfirmed),
        "second confirm of same row must short-circuit, not mint extra recovery codes");

    // No recovery codes minted on the second submit.
    assert_eq!(recovery_repo.count_remaining(USER_ID).await.unwrap(), 0,
        "double-submit confirm must not mint recovery codes a second time");
}

// ----- wrong code carries secret_b32 for re-render -----

#[tokio::test]
async fn enroll_confirm_wrong_code_returns_wrong_code_with_secret_for_rerender() {
    let (secret, totp_repo) = fixture_unconfirmed_row(USER_ID, ROW_ID).await;
    let recovery_repo = InMemoryTotpRecoveryCodeRepository::default();
    let (form, cookie) = matched_csrf_e();

    let decision = decide_enroll_confirm_post(
        USER_ID, ROW_ID,
        &form, &cookie, "000000",
        &fixed_key(),
        &totp_repo, &recovery_repo, NOW_UNIX,
    ).await;
    let secret_b32 = match decision {
        EnrollConfirmDecision::WrongCode { secret_b32 } => secret_b32,
        other => panic!("expected WrongCode, got {other:?}"),
    };
    // The carried base32 matches the underlying secret — this is
    // what lets the handler re-render the QR without decrypting
    // again.
    assert_eq!(secret_b32, secret.to_base32());

    // Row NOT confirmed.
    let row = totp_repo.find_by_id(ROW_ID).await.unwrap().unwrap();
    assert!(row.confirmed_at.is_none());
}

// ----- decrypt fails on wrong key -----

#[tokio::test]
async fn enroll_confirm_decrypt_failure_returns_decrypt_failed() {
    let (_, totp_repo) = fixture_unconfirmed_row(USER_ID, ROW_ID).await;
    let recovery_repo = InMemoryTotpRecoveryCodeRepository::default();
    let wrong_key: Vec<u8> = (0u8..32).map(|b| b ^ 0xFF).collect();
    let (form, cookie) = matched_csrf_e();

    let decision = decide_enroll_confirm_post(
        USER_ID, ROW_ID,
        &form, &cookie, "000000",
        &wrong_key,
        &totp_repo, &recovery_repo, NOW_UNIX,
    ).await;
    assert!(matches!(decision, EnrollConfirmDecision::DecryptFailed));
}
