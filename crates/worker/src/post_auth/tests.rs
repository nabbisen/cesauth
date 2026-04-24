//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;

#[test]
fn pending_cookie_header_shape() {
    let h = set_pending_cookie_header("abc-123", 600);
    assert!(h.starts_with(&format!("{PENDING_COOKIE_NAME}=abc-123")));
    assert!(h.contains("HttpOnly"));
    assert!(h.contains("Secure"));
}

#[test]
fn extract_pending_handle_present() {
    let h = format!("other=1; {PENDING_COOKIE_NAME}=my-handle; more=2");
    assert_eq!(extract_pending_handle(&h), Some("my-handle"));
}

#[test]
fn url_encode_component_encodes_reserved() {
    assert_eq!(url_encode_component("a b"), "a%20b");
    assert_eq!(url_encode_component("a&b"), "a%26b");
    assert_eq!(url_encode_component("ABCxyz-._~0"), "ABCxyz-._~0");
}
