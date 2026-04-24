//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;

#[test]
fn round_trip() {
    let issued = issue(1_000_000, 600).unwrap();
    assert_eq!(issued.code_plaintext.len(), OTP_LEN);
    assert!(verify(&issued.code_plaintext, &issued.code_hash, 1_000_001, issued.expires_at).is_ok());
}

#[test]
fn verify_tolerates_lowercase_and_whitespace() {
    let issued = issue(1_000_000, 600).unwrap();
    let mangled = format!(" {} ", issued.code_plaintext.to_lowercase());
    assert!(verify(&mangled, &issued.code_hash, 1_000_001, issued.expires_at).is_ok());
}

#[test]
fn verify_rejects_expired() {
    let issued = issue(1_000_000, 60).unwrap();
    let later  = 1_000_000 + 61;
    assert!(matches!(
        verify(&issued.code_plaintext, &issued.code_hash, later, issued.expires_at),
        Err(CoreError::MagicLinkExpired),
    ));
}

#[test]
fn verify_rejects_wrong_code() {
    let issued = issue(1_000_000, 600).unwrap();
    // Flip one char - pick a value we know is in the alphabet.
    let mut bad = issued.code_plaintext.clone();
    bad.replace_range(0..1, "A");
    if bad == issued.code_plaintext {
        bad.replace_range(0..1, "B");
    }
    assert!(matches!(
        verify(&bad, &issued.code_hash, 1_000_001, issued.expires_at),
        Err(CoreError::MagicLinkMismatch),
    ));
}
