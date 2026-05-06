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

// -----------------------------------------------------------------
// magic_link_sent_page — added in v0.25.0 alongside the UX-bug fix
// (template was previously missing the handle and csrf hidden
// inputs, which made the form-flow path unusable in browsers).
// -----------------------------------------------------------------

#[test]
fn sent_page_includes_handle_hidden_input() {
    let html = magic_link_sent_page("h-abc", "tok-xyz");
    assert!(html.contains(r#"<input type="hidden" name="handle" value="h-abc">"#),
        "handle hidden input must be rendered for the verify form to work: {html}");
}

#[test]
fn sent_page_includes_csrf_hidden_input() {
    let html = magic_link_sent_page("h-abc", "tok-xyz");
    assert!(html.contains(r#"<input type="hidden" name="csrf"   value="tok-xyz">"#),
        "csrf hidden input must be rendered for the v0.24.0 CSRF gate to pass: {html}");
}

#[test]
fn sent_page_escapes_handle() {
    // Handle is server-issued (UUID), shouldn't contain HTML-active
    // characters in practice. But pin the escape behavior anyway —
    // a future maintainer who changes handle format shouldn't open
    // an XSS hole.
    let html = magic_link_sent_page("h\"a&b", "tok");
    assert!(html.contains("h&quot;a&amp;b"),
        "handle must be HTML-escaped: {html}");
    assert!(!html.contains(r#"value="h"a&b""#));
}

#[test]
fn sent_page_escapes_csrf_token() {
    // CSRF tokens are base64url and can't contain HTML-active
    // characters either, but defense-in-depth.
    let html = magic_link_sent_page("h", "t<>k");
    assert!(html.contains("t&lt;&gt;k"));
    assert!(!html.contains("t<>k\""));
}

#[test]
fn sent_page_form_posts_to_verify_endpoint() {
    let html = magic_link_sent_page("h", "t");
    assert!(html.contains(r#"action="/magic-link/verify""#));
    assert!(html.contains(r#"method="POST""#));
}

#[test]
fn sent_page_does_not_leak_email() {
    // Account-enumeration mitigation: the response is the same
    // whether the email exists or not, so the page shouldn't
    // surface the email anywhere.
    let html = magic_link_sent_page("h", "t");
    assert!(!html.contains("@"),
        "no `@` character should appear (would imply the email is being echoed): {html}");
}
