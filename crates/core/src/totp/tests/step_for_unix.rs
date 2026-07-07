//! Originally part of `crates/core/src/totp/tests.rs`.
//! Split into a sibling file in v0.78.0.

use super::super::*;

// step_for_unix
// =====================================================================

#[test]
fn step_zero_at_epoch() {
    assert_eq!(step_for_unix(0), 0);
}

#[test]
fn step_clamps_negative_to_zero() {
    // Negative timestamps can't happen in practice (no real
    // verify happens before 1970) but pin the saturating
    // behavior so a clock-skewed Worker doesn't panic.
    assert_eq!(step_for_unix(-1), 0);
    assert_eq!(step_for_unix(i64::MIN), 0);
}

#[test]
fn step_advances_every_30_seconds() {
    assert_eq!(step_for_unix(29), 0);
    assert_eq!(step_for_unix(30), 1);
    assert_eq!(step_for_unix(59), 1);
    assert_eq!(step_for_unix(60), 2);
}

// =====================================================================
