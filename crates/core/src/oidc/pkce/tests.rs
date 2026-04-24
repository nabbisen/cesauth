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
