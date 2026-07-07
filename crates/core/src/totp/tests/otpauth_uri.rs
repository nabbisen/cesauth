//! Originally part of `crates/core/src/totp/tests.rs`.
//! Split into a sibling file in v0.78.0.

use super::super::*;
use super::rfc6238_vectors::rfc_secret;

// otpauth_uri
// =====================================================================

#[test]
fn otpauth_uri_includes_required_params() {
    let s = rfc_secret();
    let uri = otpauth_uri("cesauth", "alice@example.com", &s);

    assert!(uri.starts_with("otpauth://totp/cesauth:alice%40example.com?"));
    assert!(uri.contains("secret="));
    assert!(uri.contains("issuer=cesauth"));
    assert!(uri.contains("algorithm=SHA1"));
    assert!(uri.contains("digits=6"));
    assert!(uri.contains("period=30"));
}

#[test]
fn otpauth_uri_url_encodes_account() {
    // `@` and ` ` must be percent-encoded.
    let s = rfc_secret();
    let uri = otpauth_uri("cesauth", "alice smith@example.com", &s);
    assert!(uri.contains("alice%20smith%40example.com"),
        "spaces and @ must be percent-encoded: {uri}");
}

#[test]
fn otpauth_uri_url_encodes_issuer() {
    let s = rfc_secret();
    let uri = otpauth_uri("Acme Inc", "alice@example.com", &s);
    assert!(uri.contains("Acme%20Inc:"), "issuer label encoded: {uri}");
    assert!(uri.contains("issuer=Acme%20Inc"), "issuer param encoded: {uri}");
}

#[test]
fn otpauth_uri_secret_is_base32_no_padding() {
    let s = rfc_secret();
    let uri = otpauth_uri("c", "u", &s);
    assert!(uri.contains(&format!("secret={}", s.to_base32())));
    // The secret value (after `secret=`, before `&`) must not
    // contain base32 `=` padding. We use `BASE32_NOPAD` which
    // never emits padding for output, but pin the property so
    // a future migration to a different base32 encoder doesn't
    // silently start emitting padding.
    let secret_value = uri
        .split('?').nth(1).unwrap()
        .split('&')
        .find_map(|kv| kv.strip_prefix("secret="))
        .unwrap();
    assert!(!secret_value.contains('='),
        "secret value must be NOPAD base32: {secret_value}");
}

// =====================================================================
