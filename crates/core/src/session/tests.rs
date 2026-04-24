//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;

fn key() -> [u8; 32] {
    [0xA5; 32]
}

fn sample() -> SessionCookie {
    SessionCookie {
        session_id:  "sess-1".into(),
        user_id:     "user-1".into(),
        auth_method: AuthMethod::MagicLink,
        issued_at:   1_000,
        expires_at:  2_000,
    }
}

#[test]
fn round_trip() {
    let c = sample();
    let wire = c.sign(&key()).unwrap();
    let back = SessionCookie::verify(&wire, &key(), 1_500).unwrap();
    assert_eq!(c, back);
}

#[test]
fn tampered_payload_is_rejected() {
    let c = sample();
    let wire = c.sign(&key()).unwrap();
    // Flip a single character in the payload segment. The MAC no
    // longer matches; verify must refuse.
    let (p, t) = wire.split_once('.').unwrap();
    let mut bad_p = p.to_owned();
    bad_p.replace_range(0..1, "Z");
    let tampered = format!("{bad_p}.{t}");
    assert!(SessionCookie::verify(&tampered, &key(), 1_500).is_err());
}

#[test]
fn different_key_is_rejected() {
    let c = sample();
    let wire = c.sign(&key()).unwrap();
    let other = [0x00u8; 32];
    assert!(SessionCookie::verify(&wire, &other, 1_500).is_err());
}

#[test]
fn expired_cookie_is_rejected() {
    let c = sample();
    let wire = c.sign(&key()).unwrap();
    // Exactly at expires_at is expired.
    assert!(SessionCookie::verify(&wire, &key(), 2_000).is_err());
    assert!(SessionCookie::verify(&wire, &key(), 2_001).is_err());
}

#[test]
fn rejects_trivially_short_key() {
    let c = sample();
    assert!(c.sign(&[0u8; 4]).is_err());
}

#[test]
fn set_cookie_header_has_required_flags() {
    let h = set_cookie_header("x.y", 600);
    assert!(h.starts_with(&format!("{COOKIE_NAME}=x.y")));
    assert!(h.contains("HttpOnly"));
    assert!(h.contains("Secure"));
    assert!(h.contains("SameSite=Lax"));
    assert!(h.contains("Path=/"));
    assert!(h.contains("Max-Age=600"));
}

#[test]
fn clear_cookie_header_zeroes_max_age() {
    let h = clear_cookie_header();
    assert!(h.contains("Max-Age=0"));
}

#[test]
fn extract_from_cookie_header_finds_value() {
    let h = format!("foo=bar; {COOKIE_NAME}=abc.def; other=baz");
    assert_eq!(extract_from_cookie_header(&h), Some("abc.def"));
}

#[test]
fn extract_from_cookie_header_missing() {
    assert_eq!(extract_from_cookie_header("foo=bar"), None);
}
