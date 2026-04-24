//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;

#[test]
fn cookie_header_shape() {
    let h = set_cookie_header("abc");
    assert!(h.starts_with(&format!("{CSRF_COOKIE_NAME}=abc")));
    assert!(h.contains("HttpOnly"));
    assert!(h.contains("Secure"));
    assert!(h.contains("SameSite=Strict"));
}

#[test]
fn extract_present() {
    let h = format!("other=1; {CSRF_COOKIE_NAME}=tok; more=2");
    assert_eq!(extract_from_cookie_header(&h), Some("tok"));
}

#[test]
fn extract_missing() {
    assert_eq!(extract_from_cookie_header("other=1; more=2"), None);
}

#[test]
fn extract_does_not_match_prefix_collision() {
    // A different cookie whose name happens to start the same way
    // must not match. The `strip_prefix` + `=` check guards this.
    let h = format!("{CSRF_COOKIE_NAME}x=bad; other=1");
    assert_eq!(extract_from_cookie_header(&h), None);
}

#[test]
fn constant_time_eq_correctness() {
    assert!(constant_time_eq("abc", "abc"));
    assert!(!constant_time_eq("abc", "abd"));
    assert!(!constant_time_eq("abc", "ab"));
    assert!(!constant_time_eq("",    "a"));
    assert!(constant_time_eq("",     ""));
}

#[test]
fn verify_rejects_empty() {
    assert!(!verify("",    "cookie-val"));
    assert!(!verify("sub", ""));
    assert!(!verify("",    ""));
}

#[test]
fn verify_passes_when_equal() {
    assert!(verify("tok", "tok"));
}

#[test]
fn mint_produces_unique_nonempty_tokens() {
    let a = mint();
    let b = mint();
    assert!(!a.is_empty());
    assert_ne!(a, b);
}
