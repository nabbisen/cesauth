//! Originally part of `crates/core/src/totp/tests.rs`.
//! Split into a sibling file in v0.78.0.

use super::super::*;

// Secret round-trip and validation
// =====================================================================

#[test]
fn secret_generate_returns_correct_length() {
    let s = Secret::generate().unwrap();
    assert_eq!(s.as_bytes().len(), SECRET_BYTES);
}

#[test]
fn secret_generate_is_random() {
    // Two consecutive generates must differ. Probability of
    // collision is ~ 2^-160 per call; if this test ever fails,
    // the CSPRNG is broken.
    let a = Secret::generate().unwrap();
    let b = Secret::generate().unwrap();
    assert_ne!(a.as_bytes(), b.as_bytes());
}

#[test]
fn secret_base32_round_trip() {
    let original = Secret::generate().unwrap();
    let b32 = original.to_base32();
    let decoded = Secret::from_base32(&b32).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn secret_from_base32_tolerates_whitespace_and_lowercase() {
    let original = Secret::generate().unwrap();
    let b32 = original.to_base32();

    // Insert spaces every 4 chars (a common formatting users
    // produce when typing from paper) and lowercase everything.
    let formatted: String = b32
        .chars()
        .enumerate()
        .flat_map(|(i, c)| {
            let lc = c.to_ascii_lowercase();
            if i > 0 && i % 4 == 0 {
                vec![' ', lc]
            } else {
                vec![lc]
            }
        })
        .collect();

    let decoded = Secret::from_base32(&formatted).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn secret_from_base32_tolerates_padding() {
    // Some QR-code apps emit padded base32. We strip padding
    // before decoding. Use a real 20-byte secret to round-trip.
    let original = Secret::generate().unwrap();
    let b32 = original.to_base32();
    // Append spurious padding (BASE32_NOPAD wouldn't emit any,
    // but a malformed input with `=` chars should still decode).
    let with_padding = format!("{b32}====");
    let decoded = Secret::from_base32(&with_padding).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn secret_from_base32_rejects_garbage() {
    assert!(Secret::from_base32("not_valid_base32!").is_err());
    assert!(Secret::from_base32("").is_err());          // empty
    assert!(Secret::from_base32("AB").is_err());        // 1 byte
}

#[test]
fn secret_from_bytes_validates_length() {
    assert!(Secret::from_bytes(vec![0; SECRET_BYTES]).is_ok());
    assert!(Secret::from_bytes(vec![0; SECRET_BYTES - 1]).is_err());
    assert!(Secret::from_bytes(vec![0; SECRET_BYTES + 1]).is_err());
    assert!(Secret::from_bytes(vec![]).is_err());
}

#[test]
fn secret_debug_does_not_leak_value() {
    let s = Secret::generate().unwrap();
    let dbg = format!("{:?}", s);
    assert!(!dbg.contains(&s.to_base32()),
        "Secret Debug must not include the base32-encoded value");
    assert!(dbg.contains("20"), "should mention byte length");
}

// =====================================================================
