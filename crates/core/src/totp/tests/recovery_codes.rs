//! Originally part of `crates/core/src/totp/tests.rs`.
//! Split into a sibling file in v0.78.0.

use super::super::*;

// Recovery codes
// =====================================================================

#[test]
fn generate_recovery_codes_returns_correct_count() {
    let codes = generate_recovery_codes().unwrap();
    assert_eq!(codes.len(), RECOVERY_CODES_PER_USER);
}

#[test]
fn recovery_codes_are_unique_within_batch() {
    // Probability of collision among 10 randomly-drawn 50-bit
    // strings is (10 choose 2) * 2^-50 ≈ 4 * 10^-14. Effectively
    // zero. If this test ever fails, the CSPRNG is broken.
    let codes = generate_recovery_codes().unwrap();
    let mut seen = std::collections::HashSet::new();
    for c in &codes {
        assert!(seen.insert(c.as_str().to_owned()),
            "duplicate recovery code in fresh batch");
    }
}

#[test]
fn recovery_code_format_is_xxxxx_xxxxx() {
    let codes = generate_recovery_codes().unwrap();
    for c in &codes {
        let s = c.as_str();
        assert_eq!(s.len(), 11);          // 5 + 1 + 5
        assert_eq!(&s[5..6], "-");
        // Both halves are base32 alphabet uppercase.
        for byte in s[0..5].bytes().chain(s[6..11].bytes()) {
            let ok = matches!(byte, b'A'..=b'Z' | b'2'..=b'7');
            assert!(ok, "non-base32 char in recovery code: {s}");
        }
    }
}

#[test]
fn recovery_code_debug_redacts_value() {
    let codes = generate_recovery_codes().unwrap();
    let c = &codes[0];
    let dbg = format!("{:?}", c);
    assert!(!dbg.contains(c.as_str()),
        "Debug must not leak the recovery code value");
}

#[test]
fn recovery_code_display_renders_value() {
    // Display IS allowed to render — that's the "show once at
    // enrollment" path's mechanism.
    let codes = generate_recovery_codes().unwrap();
    let c = &codes[0];
    let s = format!("{}", c);
    assert_eq!(s, c.as_str());
}

#[test]
fn hash_recovery_code_is_deterministic() {
    let h1 = hash_recovery_code("ABCDE-FGHIJ");
    let h2 = hash_recovery_code("ABCDE-FGHIJ");
    assert_eq!(h1, h2);
}

#[test]
fn hash_recovery_code_canonicalizes_input() {
    // Same canonical form → same hash. Lowercase, dashes,
    // whitespace are all stripped/normalized.
    let canonical = hash_recovery_code("ABCDEFGHIJ");
    assert_eq!(hash_recovery_code("abcde-fghij"),  canonical);
    assert_eq!(hash_recovery_code("ABCDE-FGHIJ"),  canonical);
    assert_eq!(hash_recovery_code(" abcde fghij "),canonical);
    assert_eq!(hash_recovery_code("ABCDE FGHIJ"),  canonical);
    assert_eq!(hash_recovery_code("ABCDE--FGHIJ"), canonical);
}

#[test]
fn hash_recovery_code_distinguishes_different_codes() {
    let a = hash_recovery_code("AAAAA-AAAAA");
    let b = hash_recovery_code("AAAAA-AAAAB");
    assert_ne!(a, b);
}

#[test]
fn hash_recovery_code_output_is_hex() {
    let h = hash_recovery_code("ABCDE-FGHIJ");
    assert_eq!(h.len(), 64); // SHA-256 → 32 bytes → 64 hex chars
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(h.chars().all(|c| !c.is_ascii_uppercase()),
        "hex output should be lowercase");
}

// =====================================================================
