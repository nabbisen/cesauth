//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;

/// Strip the inline `<style>...</style>` block from a rendered
/// page. Used by leak-detection tests that want to inspect the
/// visible body content without false positives from CSS
/// declarations (e.g., `@media`, `@font-face`).
///
/// This is intentionally a string-search rather than an HTML
/// parser — the templates emit a single `<style>` block in the
/// `<head>`, and missing the closing tag would itself be a
/// rendering bug worth catching elsewhere.
fn strip_inline_style(html: &str) -> String {
    if let (Some(start), Some(end_rel)) = (html.find("<style>"), html.find("</style>")) {
        let end = end_rel + "</style>".len();
        if end > start {
            let mut out = String::with_capacity(html.len());
            out.push_str(&html[..start]);
            out.push_str(&html[end..]);
            return out;
        }
    }
    html.to_owned()
}

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
    //
    // We strip the inline `<style>` block before checking — the
    // base CSS now contains `@media (prefers-color-scheme: dark)`
    // (v0.31.0 design tokens), and an at-rule is not an email
    // leak. The intent of this test is to detect echoing the
    // user-supplied address in the visible content.
    let html = magic_link_sent_page("h", "t");
    let body_only = strip_inline_style(&html);
    assert!(!body_only.contains("@"),
        "no `@` character should appear in body (would imply the email is being echoed): {body_only}");
}

// =====================================================================
// TOTP enrollment templates (v0.28.0)
// =====================================================================

#[test]
fn enroll_page_includes_csrf_token() {
    let html = totp_enroll_page("<svg/>", "JBSWY3DPEHPK3PXP", "tok-abc", None);
    assert!(html.contains(r#"<input type="hidden" name="csrf" value="tok-abc">"#),
        "csrf hidden input must be present for the POST guard");
}

#[test]
fn enroll_page_renders_qr_svg_unescaped() {
    // The SVG comes from server-side generation, NOT from user
    // input. Inlining it (rather than escaping) is the intended
    // behavior — escape would break rendering.
    let html = totp_enroll_page("<svg viewBox=\"0 0 1 1\"></svg>", "X", "t", None);
    assert!(html.contains("<svg viewBox=\"0 0 1 1\">"),
        "QR SVG must be rendered as markup, not escaped: {html}");
}

#[test]
fn enroll_page_escapes_secret() {
    // The base32 alphabet has no HTML-active chars in practice,
    // but pin the escape behavior so a future maintainer who
    // changes the secret format can't open an XSS hole.
    let html = totp_enroll_page("<svg/>", "A<>B", "t", None);
    assert!(html.contains("A&lt;&gt;B"));
}

#[test]
fn enroll_page_escapes_csrf_token() {
    let html = totp_enroll_page("<svg/>", "X", "t<>k", None);
    assert!(html.contains("t&lt;&gt;k"));
}

#[test]
fn enroll_page_form_posts_to_confirm_endpoint() {
    let html = totp_enroll_page("<svg/>", "X", "t", None);
    assert!(html.contains(r#"action="/me/security/totp/enroll/confirm""#));
    assert!(html.contains(r#"method="POST""#));
}

#[test]
fn enroll_page_input_pattern_constrains_to_six_digits() {
    let html = totp_enroll_page("<svg/>", "X", "t", None);
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
    //
    // (v0.31.0): we strip the inline <style> block before the
    // check because the base CSS now contains `@media`
    // declarations, and at-rules are not user-id leaks.
    let html = totp_verify_page("t", None);
    let body_only = strip_inline_style(&html);
    assert!(!body_only.contains("@"),
        "no `@` character should appear in body (would imply email is being echoed): {body_only}");
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

// =====================================================================
// Design tokens — v0.31.0 P0-D
// =====================================================================
//
// These tests pin the CSS token contract. The :root variables are
// referenced by .flash--*, .badge--*, button.danger, button.warning,
// and (in v0.31.0) by future code that wants to color state without
// re-deriving the values. A silent regression here would propagate
// through every page.

#[test]
fn base_css_defines_state_tokens() {
    // Pin all 8 v0.31.0 state tokens. If a future CSS rewrite
    // renames or drops one of these, every page that uses it
    // breaks silently — the browser falls back to inherit/initial
    // and the message becomes uncolored. Pin so the test fails
    // loudly instead.
    let html = error_page("t", "d");
    for token in [
        "--success:",   "--success-bg:",
        "--warning:",   "--warning-bg:",
        "--danger:",    "--danger-bg:",
        "--info:",      "--info-bg:",
    ] {
        assert!(html.contains(token),
            "BASE_CSS must define {token}: missing");
    }
}

#[test]
fn base_css_preserves_legacy_tokens() {
    // The v0.31.0 token expansion did NOT remove the legacy
    // tokens (--accent, --err, --muted, --bg, --fg). Pin so a
    // future cleanup doesn't break old templates that still
    // reference them.
    let html = error_page("t", "d");
    for token in ["--accent:", "--err:", "--muted:", "--bg:", "--fg:"] {
        assert!(html.contains(token),
            "BASE_CSS must preserve legacy {token}: missing");
    }
}

#[test]
fn base_css_includes_dark_mode_overrides() {
    // The dark-mode @media block adjusts state tokens to remain
    // legible against a dark canvas. Without this, light-bg
    // values like #e8f5e9 wash out completely. Pin the
    // @media query's presence and at least one expected dark
    // override.
    let html = error_page("t", "d");
    assert!(html.contains("@media (prefers-color-scheme: dark)"),
        "BASE_CSS must include dark-mode @media block");
    // Dark variant for --success-bg is a deep green (#14532d)
    // per the v0.31.0 plan. Pin one value to detect drift.
    assert!(html.contains("#14532d"),
        "BASE_CSS dark mode must override --success-bg to #14532d");
}

#[test]
fn base_css_defines_state_button_classes() {
    // Pin button.danger / button.warning rule definitions.
    // Used by totp_disable_confirm_page (button class="danger")
    // and reserved for future destructive flows.
    let html = error_page("t", "d");
    assert!(html.contains("button.danger"),
        "BASE_CSS must define button.danger");
    assert!(html.contains("button.warning"),
        "BASE_CSS must define button.warning");
}

#[test]
fn base_css_defines_flash_modifier_classes() {
    // Flash banners use level-specific modifier classes set
    // by templates::flash_block (lands in PR-3). Pin all four
    // so the templates can rely on them existing.
    let html = error_page("t", "d");
    for modifier in ["flash--success", "flash--warning", "flash--danger", "flash--info"] {
        assert!(html.contains(modifier),
            "BASE_CSS must define .{modifier}: missing");
    }
}

#[test]
fn base_css_defines_badge_modifier_classes() {
    // Badges in the Security Center page use these modifiers.
    let html = error_page("t", "d");
    for modifier in ["badge--success", "badge--warning", "badge--danger", "badge--info"] {
        assert!(html.contains(modifier),
            "BASE_CSS must define .{modifier}: missing");
    }
}

#[test]
fn base_css_defines_visually_hidden_utility() {
    // The verify-page recovery form uses class="visually-hidden"
    // for a screen-reader heading. Before v0.31.0 the class was
    // referenced in templates but the rule was missing from CSS
    // — fixed in this release. Pin the rule so it doesn't
    // disappear again.
    let html = error_page("t", "d");
    assert!(html.contains(".visually-hidden"),
        "BASE_CSS must define .visually-hidden utility class");
    // Sanity: the rule should clip to a 1px box (standard SR-only
    // technique). Don't pin every property, but the clip is the
    // most fragile bit.
    assert!(html.contains("clip: rect(0, 0, 0, 0)"),
        "visually-hidden must clip to zero rect");
}

#[test]
fn base_css_focus_ring_present_on_inputs_and_buttons() {
    // Accessibility floor: inputs and buttons must have a visible
    // focus ring. Pin the outline rule so a future styling
    // change doesn't remove keyboard-only focus indicators.
    let html = error_page("t", "d");
    assert!(html.contains("input:focus"),
        "BASE_CSS must keep an input:focus rule for keyboard users");
    assert!(html.contains("button:focus"),
        "BASE_CSS must keep a button:focus rule for keyboard users");
    assert!(html.contains("outline-offset"),
        "focus rule must use outline-offset for visibility");
}

// =====================================================================
// flash_block — v0.31.0 P0-B
// =====================================================================

fn make_view(level: &'static str, modifier: &'static str, icon: &'static str, text: &'static str) -> FlashView {
    FlashView {
        aria_live:    level,
        css_modifier: modifier,
        icon,
        text,
    }
}

#[test]
fn flash_block_returns_empty_for_none() {
    assert_eq!(flash_block(None), "");
}

#[test]
fn flash_block_emits_modifier_class() {
    let html = flash_block(Some(make_view("polite", "flash--success", "✓", "saved")));
    assert!(html.contains(r#"class="flash flash--success""#),
        "class must include both root and modifier: {html}");
}

#[test]
fn flash_block_emits_aria_live_polite_for_polite() {
    let html = flash_block(Some(make_view("polite", "flash--info", "i", "fyi")));
    assert!(html.contains(r#"aria-live="polite""#));
    assert!(html.contains(r#"role="status""#),
        "polite flash should pair aria-live=polite with role=status: {html}");
}

#[test]
fn flash_block_emits_aria_live_assertive_for_assertive() {
    let html = flash_block(Some(make_view("assertive", "flash--danger", "x", "broken")));
    assert!(html.contains(r#"aria-live="assertive""#));
    assert!(html.contains(r#"role="alert""#),
        "assertive flash should pair aria-live=assertive with role=alert: {html}");
}

#[test]
fn flash_block_marks_icon_as_decorative() {
    // Icon is purely visual; the text is the source of truth
    // for assistive tech. Pin aria-hidden="true" so a future
    // refactor doesn't accidentally announce the icon glyph
    // in addition to the text (double-announce annoyance).
    let html = flash_block(Some(make_view("polite", "flash--info", "ℹ", "fyi")));
    assert!(html.contains(r#"<span class="flash__icon" aria-hidden="true">ℹ</span>"#),
        "icon span must be aria-hidden: {html}");
}

#[test]
fn flash_block_includes_text() {
    let html = flash_block(Some(make_view("polite", "flash--success", "✓", "ログアウトしました。")));
    assert!(html.contains("ログアウトしました。"),
        "rendered html must include the text content: {html}");
    assert!(html.contains(r#"<span class="flash__text">ログアウトしました。</span>"#));
}

#[test]
fn flash_block_does_not_escape_text() {
    // Text comes from a closed token table in the worker, not
    // from user input. Pin that the renderer does NOT escape it
    // — that contract lets the table use UTF-8 fixed strings
    // freely without round-tripping through escape(). If a future
    // change makes `text` user-controlled, this contract MUST be
    // revisited.
    let html = flash_block(Some(make_view("polite", "flash--info", "i", "<b>fixed</b>")));
    assert!(html.contains("<b>fixed</b>"),
        "text is from a closed table and rendered raw: {html}");
}

#[test]
fn frame_with_flash_inserts_block_inside_main() {
    // Verify the splice point: flash sits between <main> and the
    // body, so it appears at the top of the readable content.
    //
    // Caveat: `flash--info` also appears in the CSS rule
    // declarations inside <style>. Use a body-only marker
    // (`<div class="flash`) for the position check.
    let flash_html = flash_block(Some(make_view("polite", "flash--info", "i", "hi")));
    let html = frame_with_flash("t", &flash_html, "<p>body</p>");
    let main_idx  = html.find("<main>").expect("must contain <main>");
    let flash_idx = html.find(r#"<div class="flash "#).expect("must contain flash div");
    let body_idx  = html.find("<p>body</p>").expect("must contain body");
    assert!(main_idx < flash_idx, "flash must come after <main>: {html}");
    assert!(flash_idx < body_idx, "flash must come before body content: {html}");
}

#[test]
fn frame_with_empty_flash_renders_clean() {
    // The default `frame()` calls `frame_with_flash(... "", body)`.
    // Pin that this produces no stray flash markup — empty string
    // → no `<div class="flash` substring.
    let html = frame("t", "<p>body</p>");
    assert!(!html.contains("class=\"flash"),
        "empty flash slot should produce no flash div: {html}");
    assert!(html.contains("<p>body</p>"));
}

// =====================================================================
// totp_enroll_page error slot — v0.31.0 P0-C
// =====================================================================
//
// Pin the error: Option<&str> contract added in v0.31.0. Before
// this release the page had no error slot and the wrong-code
// branch silently re-rendered, leaving the user wondering why
// nothing changed. Tests pin: (a) None renders no error div,
// (b) Some renders an aria-live=assertive alert, (c) the message
// is HTML-escaped (no XSS via crafted error text — currently the
// caller passes a static string but the contract should hold),
// (d) the code input keeps autofocus regardless of error state.

#[test]
fn enroll_page_with_no_error_renders_no_error_div() {
    let html = totp_enroll_page("<svg/>", "JBSWY3DPEHPK3PXP", "t", None);
    assert!(!html.contains(r#"role="alert""#),
        "no error → no role=alert div: {html}");
}

#[test]
fn enroll_page_with_error_emits_alert_role() {
    let html = totp_enroll_page(
        "<svg/>",
        "JBSWY3DPEHPK3PXP",
        "t",
        Some("入力されたコードが一致しませんでした。"),
    );
    assert!(html.contains(r#"role="alert""#),
        "Some(error) must emit role=alert: {html}");
    assert!(html.contains(r#"aria-live="assertive""#),
        "Some(error) must emit aria-live=assertive: {html}");
    assert!(html.contains("入力されたコードが一致しませんでした。"),
        "error text must appear in body: {html}");
}

#[test]
fn enroll_page_escapes_error_message() {
    // Caller currently passes a static string but pin the
    // escape contract — a future call site must not become
    // an XSS vector.
    let html = totp_enroll_page("<svg/>", "X", "t", Some("<script>alert(1)</script>"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "error message must be HTML-escaped: {html}");
    assert!(!html.contains("<script>alert(1)</script>"),
        "raw script tag must not appear: {html}");
}

#[test]
fn enroll_page_code_input_has_autofocus() {
    // The code input should land focus regardless of error state
    // — UX for both initial render (user is here to enroll) and
    // wrong-code re-render (they have the app open, ready to
    // type the next code).
    let html_no_err   = totp_enroll_page("<svg/>", "X", "t", None);
    let html_with_err = totp_enroll_page("<svg/>", "X", "t", Some("err"));
    assert!(html_no_err.contains("autofocus"),
        "initial render must autofocus the code input: {html_no_err}");
    assert!(html_with_err.contains("autofocus"),
        "error re-render must autofocus the code input: {html_with_err}");
}

#[test]
fn enroll_page_error_appears_above_form() {
    // The error block sits between the manual-entry <details>
    // and the confirm form, so it's visible when the user's
    // attention is on the form.
    let html = totp_enroll_page("<svg/>", "X", "t", Some("oops"));
    let err_idx  = html.find(r#"role="alert""#).expect("must contain alert role");
    let form_idx = html.find(r#"method="POST""#).expect("must contain form");
    assert!(err_idx < form_idx,
        "error block must appear before the form: {html}");
}

// =====================================================================
// security_center_page — v0.31.0 P0-A
// =====================================================================
//
// The Security Center is the index page for /me/security. Pin
// the four recovery-code threshold tiers (10 / 2-9 / 1 / 0), the
// branching on totp_enabled, the anonymous suppression, and the
// single-task-per-page rule (no enroll/disable form on this page,
// only links to the dedicated forms).

fn make_state(method: PrimaryAuthMethod, enabled: bool, n: u32) -> SecurityCenterState {
    SecurityCenterState {
        primary_method:           method,
        totp_enabled:             enabled,
        recovery_codes_remaining: n,
    }
}

#[test]
fn security_center_shows_primary_method_label() {
    let html_passkey = security_center_page(&make_state(PrimaryAuthMethod::Passkey, false, 0));
    assert!(html_passkey.contains("パスキー"),
        "Passkey label must appear: {html_passkey}");

    let html_magic = security_center_page(&make_state(PrimaryAuthMethod::MagicLink, false, 0));
    assert!(html_magic.contains("メールリンク"),
        "MagicLink label must appear: {html_magic}");

    let html_anon = security_center_page(&make_state(PrimaryAuthMethod::Anonymous, false, 0));
    assert!(html_anon.contains("匿名トライアル"),
        "Anonymous label must appear: {html_anon}");
}

#[test]
fn security_center_with_totp_disabled_shows_enroll_link_not_disable() {
    let html = security_center_page(&make_state(PrimaryAuthMethod::MagicLink, false, 0));
    let body = strip_inline_style(&html);
    assert!(body.contains("/me/security/totp/enroll"),
        "disabled state must link to enroll: {body}");
    assert!(!body.contains("/me/security/totp/disable"),
        "disabled state must NOT show disable link: {body}");
    assert!(body.contains("badge--info"),
        "disabled state should use info badge (not danger): {body}");
}

#[test]
fn security_center_with_totp_enabled_shows_disable_link_not_enroll() {
    let html = security_center_page(&make_state(PrimaryAuthMethod::MagicLink, true, 10));
    let body = strip_inline_style(&html);
    assert!(body.contains("/me/security/totp/disable"),
        "enabled state must link to disable: {body}");
    assert!(!body.contains("/me/security/totp/enroll"),
        "enabled state must NOT show enroll link: {body}");
    assert!(body.contains("badge--success"),
        "enabled state must use success badge: {body}");
}

// --- Recovery code threshold boundaries ---

#[test]
fn recovery_threshold_n10_shows_info_badge_no_warning() {
    // strip_inline_style: `flash--warning` and `flash--danger`
    // appear in the CSS class definitions inside <style>, so a
    // raw .contains() would always match. Strip the style block
    // first so the assertions reflect the body only.
    let html = security_center_page(&make_state(PrimaryAuthMethod::MagicLink, true, 10));
    let body = strip_inline_style(&html);
    assert!(body.contains("badge--info"),
        "N=10 must use info badge: {body}");
    assert!(body.contains("10 個有効"),
        "N=10 must show count: {body}");
    assert!(!body.contains("flash--warning"),
        "N=10 must not emit warning flash: {body}");
    assert!(!body.contains("flash--danger"),
        "N=10 must not emit danger flash: {body}");
}

#[test]
fn recovery_threshold_n5_shows_info_badge_with_count() {
    let html = security_center_page(&make_state(PrimaryAuthMethod::MagicLink, true, 5));
    let body = strip_inline_style(&html);
    assert!(body.contains("badge--info"),
        "N=5 must use info badge: {body}");
    assert!(body.contains("5 個有効"),
        "N=5 must show count: {body}");
    assert!(!body.contains("flash--warning"),
        "N=5 must not emit warning flash: {body}");
}

#[test]
fn recovery_threshold_n1_shows_warning_with_reenroll_hint() {
    let html = security_center_page(&make_state(PrimaryAuthMethod::MagicLink, true, 1));
    let body = strip_inline_style(&html);
    assert!(body.contains("flash--warning"),
        "N=1 must emit warning flash: {body}");
    assert!(body.contains("残り 1 個"),
        "N=1 must label as 'remaining 1': {body}");
    assert!(body.contains("再 enroll"),
        "N=1 must mention re-enrollment as the recovery path: {body}");
    assert!(!body.contains("flash--danger"),
        "N=1 is warning, not danger: {body}");
}

#[test]
fn recovery_threshold_n0_shows_danger_with_admin_message() {
    let html = security_center_page(&make_state(PrimaryAuthMethod::MagicLink, true, 0));
    let body = strip_inline_style(&html);
    assert!(body.contains("flash--danger"),
        "N=0 must emit danger flash: {body}");
    assert!(body.contains("リカバリーコード残なし"),
        "N=0 must label as 'no recovery codes left': {body}");
    assert!(body.contains("管理者連絡"),
        "N=0 must mention admin contact path: {body}");
}

#[test]
fn anonymous_user_sees_no_totp_controls() {
    // Anonymous principals can't enroll TOTP. Per plan §3.1 P0-A
    // the page renders without enroll/disable controls and shows
    // an explanatory note.
    let html = security_center_page(&make_state(PrimaryAuthMethod::Anonymous, false, 0));
    assert!(!html.contains("/me/security/totp/enroll"),
        "anonymous must not see enroll link: {html}");
    assert!(!html.contains("/me/security/totp/disable"),
        "anonymous must not see disable link: {html}");
    assert!(html.contains("匿名トライアルでは TOTP を有効化できません"),
        "anonymous must see explanatory note: {html}");
}

#[test]
fn security_center_uses_icon_plus_text_not_color_alone() {
    // WCAG 1.4.1 — every state badge must include both an icon
    // and a text label. Pin so a future restyle can't drop one.
    let html = security_center_page(&make_state(PrimaryAuthMethod::MagicLink, true, 0));
    // The N=0 case is the most state-heavy: TOTP enabled badge,
    // recovery danger flash. Both must include aria-hidden icons
    // alongside readable text.
    assert!(html.contains(r#"aria-hidden="true""#),
        "decorative icons must be aria-hidden: {html}");
}

#[test]
fn security_center_does_not_inline_destructive_form() {
    // Single-task-per-page rule: this index has links, not
    // POST forms. A `<form method="POST"` here would mean
    // we leaked the disable confirmation onto the index, which
    // weakens the danger UX.
    let html = security_center_page(&make_state(PrimaryAuthMethod::MagicLink, true, 5));
    assert!(!html.contains(r#"method="POST""#),
        "Security Center index must contain no POST form: {html}");
}

#[test]
fn security_center_renders_in_japanese_without_panic_on_all_states() {
    // Smoke: every (method × enabled × N) combo we'd render in
    // production produces a non-empty page without panic.
    for method in [
        PrimaryAuthMethod::Passkey,
        PrimaryAuthMethod::MagicLink,
        PrimaryAuthMethod::Anonymous,
    ] {
        for enabled in [false, true] {
            for n in [0_u32, 1, 5, 10] {
                let s = make_state(method, enabled, n);
                let html = security_center_page(&s);
                assert!(!html.is_empty());
                assert!(html.contains("セキュリティ"),
                    "page heading must appear: method={method:?} enabled={enabled} n={n}");
            }
        }
    }
}
