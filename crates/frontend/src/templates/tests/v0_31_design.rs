//! v0.31.0 — design tokens, flash_block, totp_enroll error slot, security_center base.
//!
//! Split out from `templates/tests.rs` in v0.75.0 (test-file
//! modularization per the dev guidelines' 500-ELOC strongly-recommended
//! split threshold).

use super::super::*;
use super::super::chrome::frame;
#[allow(unused_imports)]
use cesauth_core::i18n::Locale;
#[allow(unused_imports)]
use super::common::{strip_inline_style, make_state};

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
        text:         std::borrow::Cow::Borrowed(text),
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
    let html = frame_with_flash("t", &flash_html, "<p>body</p>", cesauth_core::i18n::Locale::Ja);
    let main_idx  = html.find("<main id=\"main\">").expect("must contain <main id=main>");
    let flash_idx = html.find(r#"<div class="flash "#).expect("must contain flash div");
    let body_idx  = html.find("<p>body</p>").expect("must contain body");
    assert!(main_idx < flash_idx, "flash must come after <main id=main>: {html}");
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

// =====================================================================
