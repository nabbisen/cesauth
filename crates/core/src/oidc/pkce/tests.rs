//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;

// Known-answer test vector from RFC 7636 Appendix B.
const RFC_VERIFIER:  &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

#[test]
fn verify_accepts_rfc_vector() {
    assert!(verify(RFC_VERIFIER, RFC_CHALLENGE, ChallengeMethod::S256).is_ok());
}

#[test]
fn verify_rejects_flipped_bit() {
    // Replace the final character to produce a mismatching challenge.
    let mut bad = RFC_CHALLENGE.to_string();
    bad.pop();
    bad.push('A');
    assert!(verify(RFC_VERIFIER, &bad, ChallengeMethod::S256).is_err());
}

#[test]
fn verify_rejects_short_verifier() {
    // Anything under 43 chars is a protocol error, not a mismatch.
    assert!(verify("tooshort", RFC_CHALLENGE, ChallengeMethod::S256).is_err());
}

#[test]
fn challenge_method_rejects_plain() {
    assert!(ChallengeMethod::parse("plain").is_err());
}

// ── RFC 054 additional tests ───────────────────────────────────────────────

#[test]
fn verify_accepts_exact_43_char_verifier() {
    // RFC 7636 §4.1: minimum allowed length is 43.
    let verifier = "a".repeat(43);
    let challenge = {
        use sha2::{Digest, Sha256};
        use base64::Engine;
        let mut h = Sha256::new();
        h.update(verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize())
    };
    assert!(verify(&verifier, &challenge, ChallengeMethod::S256).is_ok(),
        "43-char verifier (minimum) must be accepted");
}

#[test]
fn verify_accepts_exact_128_char_verifier() {
    // RFC 7636 §4.1: maximum allowed length is 128.
    let verifier = "b".repeat(128);
    let challenge = {
        use sha2::{Digest, Sha256};
        use base64::Engine;
        let mut h = Sha256::new();
        h.update(verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize())
    };
    assert!(verify(&verifier, &challenge, ChallengeMethod::S256).is_ok(),
        "128-char verifier (maximum) must be accepted");
}

#[test]
fn verify_rejects_129_char_verifier() {
    // One over the maximum must fail.
    let verifier = "c".repeat(129);
    assert!(verify(&verifier, RFC_CHALLENGE, ChallengeMethod::S256).is_err(),
        "129-char verifier (over maximum) must be rejected");
}

#[test]
fn verify_rejects_empty_verifier() {
    assert!(verify("", RFC_CHALLENGE, ChallengeMethod::S256).is_err());
}

#[test]
fn verify_rejects_empty_challenge() {
    // Mismatched challenge (empty) must fail.
    assert!(verify(RFC_VERIFIER, "", ChallengeMethod::S256).is_err());
}

#[test]
fn challenge_method_parse_accepts_s256() {
    assert!(ChallengeMethod::parse("S256").is_ok());
}

#[test]
fn challenge_method_parse_rejects_unknown() {
    assert!(ChallengeMethod::parse("RS256").is_err());
    assert!(ChallengeMethod::parse("").is_err());
    assert!(ChallengeMethod::parse("PLAIN").is_err());  // case-sensitive
}

#[test]
fn constant_time_eq_handles_different_lengths() {
    // Different-length slices must return false immediately (no index panic).
    assert!(!crate::util::constant_time_eq_bytes(b"abc", b"ab"));
    assert!(!crate::util::constant_time_eq_bytes(b"ab", b"abc"));
    assert!(!crate::util::constant_time_eq_bytes(b"", b"a"));
    assert!(crate::util::constant_time_eq_bytes(b"", b""));
}

#[test]
fn verify_wrong_verifier_gives_pkcemismatch() {
    // A plausible-length wrong verifier must fail with PkceMismatch.
    let wrong_verifier = "wrongverifier-padding-to-meet-43chars-xxxxxxxxx";
    assert!(wrong_verifier.len() >= 43);
    let result = verify(wrong_verifier, RFC_CHALLENGE, ChallengeMethod::S256);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), crate::error::CoreError::PkceMismatch));
}
