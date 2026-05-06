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

// =====================================================================
// TOTP enrollment templates (v0.28.0)
// =====================================================================

#[test]
fn enroll_page_includes_csrf_token() {
    let html = totp_enroll_page("<svg/>", "JBSWY3DPEHPK3PXP", "tok-abc");
    assert!(html.contains(r#"<input type="hidden" name="csrf" value="tok-abc">"#),
        "csrf hidden input must be present for the POST guard");
}

#[test]
fn enroll_page_renders_qr_svg_unescaped() {
    // The SVG comes from server-side generation, NOT from user
    // input. Inlining it (rather than escaping) is the intended
    // behavior — escape would break rendering.
    let html = totp_enroll_page("<svg viewBox=\"0 0 1 1\"></svg>", "X", "t");
    assert!(html.contains("<svg viewBox=\"0 0 1 1\">"),
        "QR SVG must be rendered as markup, not escaped: {html}");
}

#[test]
fn enroll_page_escapes_secret() {
    // The base32 alphabet has no HTML-active chars in practice,
    // but pin the escape behavior so a future maintainer who
    // changes the secret format can't open an XSS hole.
    let html = totp_enroll_page("<svg/>", "A<>B", "t");
    assert!(html.contains("A&lt;&gt;B"));
}

#[test]
fn enroll_page_escapes_csrf_token() {
    let html = totp_enroll_page("<svg/>", "X", "t<>k");
    assert!(html.contains("t&lt;&gt;k"));
}

#[test]
fn enroll_page_form_posts_to_confirm_endpoint() {
    let html = totp_enroll_page("<svg/>", "X", "t");
    assert!(html.contains(r#"action="/me/security/totp/enroll/confirm""#));
    assert!(html.contains(r#"method="POST""#));
}

#[test]
fn enroll_page_input_pattern_constrains_to_six_digits() {
    let html = totp_enroll_page("<svg/>", "X", "t");
    assert!(html.contains(r#"pattern="[0-9]{6}""#),
        "client-side pattern enforces 6 digits before round-trip: {html}");
}

// =====================================================================
// TOTP recovery codes display
// =====================================================================

#[test]
fn recovery_codes_page_renders_each_code() {
    let codes = vec![
        "AAAAA-BBBBB".to_owned(),
        "CCCCC-DDDDD".to_owned(),
        "EEEEE-FFFFF".to_owned(),
    ];
    let html = totp_recovery_codes_page(&codes);
    for c in &codes {
        assert!(html.contains(&format!("<code>{c}</code>")),
            "each recovery code must appear as a <code> element: {c}");
    }
}

#[test]
fn recovery_codes_page_includes_irreversibility_warning() {
    let codes = vec!["AAAAA-BBBBB".to_owned()];
    let html = totp_recovery_codes_page(&codes);
    assert!(html.contains("only time"),
        "page must warn the codes won't be shown again: {html}");
}

#[test]
fn recovery_codes_page_escapes_codes() {
    // Codes are server-issued from a fixed alphabet, but defense
    // in depth.
    let codes = vec!["A<>B".to_owned()];
    let html = totp_recovery_codes_page(&codes);
    assert!(html.contains("A&lt;&gt;B"));
    assert!(!html.contains("<code>A<>B</code>"));
}

// =====================================================================
// TOTP verify page (post-MagicLink gate)
// =====================================================================

#[test]
fn verify_page_includes_csrf_token() {
    let html = totp_verify_page("tok-xyz", None);
    // Both forms (code entry + recovery) carry the CSRF token.
    let count = html.matches(r#"name="csrf" value="tok-xyz""#).count();
    assert_eq!(count, 2,
        "csrf token must appear in both the verify and recover forms: {html}");
}

#[test]
fn verify_page_renders_no_error_block_when_none() {
    let html = totp_verify_page("t", None);
    assert!(!html.contains(r#"class="error""#),
        "no error block on initial render: {html}");
}

#[test]
fn verify_page_renders_error_block_when_some() {
    let html = totp_verify_page("t", Some("Code didn't match"));
    assert!(html.contains(r#"class="error""#));
    assert!(html.contains("Code didn&#x27;t match") || html.contains("Code didn't match"),
        "error message text must be rendered: {html}");
}

#[test]
fn verify_page_includes_recovery_alternative() {
    let html = totp_verify_page("t", None);
    assert!(html.contains(r#"action="/me/security/totp/recover""#),
        "verify page offers recovery as an alternative: {html}");
}

#[test]
fn verify_page_recovery_form_does_not_appear_inline() {
    // The recovery form is inside a <details> so it's collapsed
    // by default; users only see it if they click "Lost your
    // authenticator?". Pin so a future refactor doesn't expose
    // the recovery code field by default (more visible than
    // intended → user habituation to typing recovery codes).
    let html = totp_verify_page("t", None);
    let details_idx = html.find("<details").expect("recovery is in <details>");
    let recover_idx = html.find(r#"action="/me/security/totp/recover""#).expect("has recover action");
    assert!(recover_idx > details_idx,
        "recovery form must be inside <details>: {html}");
}

#[test]
fn verify_page_escapes_csrf() {
    let html = totp_verify_page("t<>k", None);
    assert!(html.contains("t&lt;&gt;k"));
    assert!(!html.contains(r#"value="t<>k""#));
}

#[test]
fn verify_page_escapes_error_message() {
    let html = totp_verify_page("t", Some("<script>alert(1)</script>"));
    assert!(html.contains("&lt;script&gt;"));
    assert!(!html.contains("<script>alert"),
        "error message must not be rendered as live HTML: {html}");
}

#[test]
fn verify_page_input_constrains_to_six_digits() {
    let html = totp_verify_page("t", None);
    assert!(html.contains(r#"pattern="[0-9]{6}""#));
}

#[test]
fn verify_page_does_not_leak_user_id() {
    // Per ADR-009 §Q7 the post-Magic-Link verify gate
    // intentionally avoids surfacing user identity. The
    // PendingTotp challenge identifies who they are; the page
    // doesn't need to echo it back. Pin so a UX iteration
    // doesn't accidentally surface "Welcome, alice@..." which
    // would leak target email through the verify-page rendering
    // even before the user submits.
    let html = totp_verify_page("t", None);
    assert!(!html.contains("@"),
        "no `@` character should appear (would imply email is being echoed): {html}");
}

// =====================================================================
// TOTP disable confirmation page (v0.30.0)
// =====================================================================

#[test]
fn disable_page_includes_csrf_token() {
    let html = totp_disable_confirm_page("tok-abc");
    assert!(html.contains(r#"<input type="hidden" name="csrf" value="tok-abc">"#));
}

#[test]
fn disable_page_form_posts_to_disable_endpoint() {
    let html = totp_disable_confirm_page("t");
    assert!(html.contains(r#"action="/me/security/totp/disable""#));
    assert!(html.contains(r#"method="POST""#));
}

#[test]
fn disable_page_warns_about_recovery_code_loss() {
    // The disable flow wipes recovery codes too. Pin so a future
    // UX iteration that softens the warning doesn't accidentally
    // hide the consequence.
    let html = totp_disable_confirm_page("t");
    assert!(html.contains("recovery codes"),
        "disable page must mention recovery codes are wiped: {html}");
}

#[test]
fn disable_page_offers_cancel_link() {
    let html = totp_disable_confirm_page("t");
    assert!(html.contains(r#"<a href="/">Cancel"#),
        "destructive flow must offer a no-op exit: {html}");
}

#[test]
fn disable_page_escapes_csrf() {
    let html = totp_disable_confirm_page("t<>k");
    assert!(html.contains("t&lt;&gt;k"));
    assert!(!html.contains(r#"value="t<>k""#));
}
