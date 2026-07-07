//! Originally part of `crates/core/src/totp/tests.rs`.
//! Split into a sibling file in v0.78.0.

use super::super::*;

// RFC 6238 Appendix B test vectors
// =====================================================================
//
// The published test vectors use a 20-byte ASCII secret
// "12345678901234567890" and the SHA-1 variant. cesauth locks to
// SHA-1 so all RFC vectors apply directly.
//
// Sample table (selected):
//   Time (sec)     Step (hex)       SHA-1 TOTP
//   59             0000000000000001 94287082
//   1111111109     00000000023523EC 07081804
//   1111111111     00000000023523ED 14050471
//   1234567890     000000000273EF07 89005924
//   2000000000     0000000003F940AA 69279037
//
// The RFC's reference codes are 8-digit; cesauth uses 6 digits. To
// derive the 6-digit values we apply `% 10^6` to the RFC's
// 8-digit values:
//   94287082 % 1000000 = 287082
//   07081804 % 1000000 =  81804  -> formatted "081804"
//   14050471 % 1000000 =  50471  -> formatted "050471"
//   89005924 % 1000000 =   5924  -> formatted "005924"
//   69279037 % 1000000 = 279037

const RFC6238_SECRET_ASCII: &[u8] = b"12345678901234567890";

pub(super) fn rfc_secret() -> Secret {
    Secret::from_bytes(RFC6238_SECRET_ASCII.to_vec()).unwrap()
}

#[test]
fn rfc6238_vector_t_59() {
    let s = rfc_secret();
    let step = step_for_unix(59);
    assert_eq!(step, 1);
    assert_eq!(compute_code(&s, step), 287082);
}

#[test]
fn rfc6238_vector_t_1111111109() {
    let s = rfc_secret();
    let step = step_for_unix(1111111109);
    assert_eq!(compute_code(&s, step), 81804);
}

#[test]
fn rfc6238_vector_t_1111111111() {
    let s = rfc_secret();
    let step = step_for_unix(1111111111);
    assert_eq!(compute_code(&s, step), 50471);
}

#[test]
fn rfc6238_vector_t_1234567890() {
    let s = rfc_secret();
    let step = step_for_unix(1234567890);
    assert_eq!(compute_code(&s, step), 5924);
}

#[test]
fn rfc6238_vector_t_2000000000() {
    let s = rfc_secret();
    let step = step_for_unix(2000000000);
    assert_eq!(compute_code(&s, step), 279037);
}

// =====================================================================
