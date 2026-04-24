//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;

#[test]
fn login_page_contains_aria_live_region() {
    let html = login_page("t", None, None);
    assert!(html.contains("aria-live=\"assertive\""));
}

#[test]
fn login_page_escapes_csrf_token() {
    let html = login_page("a\"b", None, None);
    assert!(html.contains(r#"value="a&quot;b""#));
    assert!(!html.contains(r#"value="a"b""#));
}

#[test]
fn error_page_escapes_detail() {
    let html = error_page("oops", "<script>");
    assert!(html.contains("&lt;script&gt;"));
    assert!(!html.contains("<script>"));
}
