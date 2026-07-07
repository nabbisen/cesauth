//! Originally part of `crates/core/src/totp/tests.rs`.
//! Split into a sibling file in v0.78.0.

use super::super::*;

// format_code / parse_code
// =====================================================================

#[test]
fn format_code_pads_with_leading_zeros() {
    assert_eq!(format_code(0),      "000000");
    assert_eq!(format_code(1),      "000001");
    assert_eq!(format_code(81804),  "081804");
    assert_eq!(format_code(999999), "999999");
}

#[test]
fn parse_code_accepts_zero_padded() {
    assert_eq!(parse_code("000000").unwrap(),    0);
    assert_eq!(parse_code("000001").unwrap(),    1);
    assert_eq!(parse_code("081804").unwrap(), 81804);
}

#[test]
fn parse_code_accepts_non_padded() {
    // User typed without leading zeros — common in apps that
    // strip them for display. Accept; the integer comparison
    // matches.
    assert_eq!(parse_code("1").unwrap(), 1);
    assert_eq!(parse_code("81804").unwrap(), 81804);
}

#[test]
fn parse_code_rejects_non_digits() {
    assert!(parse_code("12345A").is_err());
    assert!(parse_code("").is_err());          // empty
    assert!(parse_code(" 12345").is_err());    // leading space
    assert!(parse_code("12 345").is_err());    // embedded space
}

#[test]
fn parse_code_rejects_too_long() {
    assert!(parse_code("1234567").is_err());
}

// =====================================================================
