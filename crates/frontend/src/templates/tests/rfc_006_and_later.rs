//! RFC 006 nonce + RFC 027 flash a11y + html-lang + recovery confirm + skip-link.
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

// RFC 006 (v0.52.0) — nonce injection tests
// =====================================================================

#[test]
fn login_page_for_emits_nonce_attribute_on_inline_style() {
    crate::set_render_nonce("test_nonce_abc");
    let html = login_page_for("csrf", None, None, true, cesauth_core::i18n::Locale::default());
    assert!(html.contains(r#"nonce="test_nonce_abc""#),
        "inline <style> must carry the per-request nonce attribute: {html}");
}

#[test]
fn login_page_for_emits_nonce_attribute_on_inline_script() {
    crate::set_render_nonce("test_nonce_abc");
    let html = login_page_for("csrf", None, None, true, cesauth_core::i18n::Locale::default());
    assert!(html.contains(r#"<script defer nonce="test_nonce_abc""#),
        "inline <script> must carry the per-request nonce attribute: {html}");
}

#[test]
fn login_page_for_does_not_emit_inline_event_handler() {
    crate::set_render_nonce("test_nonce_xyz");
    let html = login_page_for("csrf", None, None, true, cesauth_core::i18n::Locale::default());
    assert!(!html.contains("onclick="),
        "login page must not use inline event handlers (CSP audit): {html}");
    assert!(!html.contains("onload="),
        "login page must not use inline event handlers (CSP audit): {html}");
}

#[test]
fn frame_with_flash_emits_nonce_in_style_tag() {
    crate::set_render_nonce("nonce_frame_test");
    // Call any function that goes through frame_with_flash
    let html = error_page("oops", "detail");
    assert!(html.contains(r#"nonce="nonce_frame_test""#),
        "frame_with_flash must embed nonce in <style>: {html}");
}

#[test]
fn different_render_calls_use_their_own_nonce() {
    // Nonce set to A → render → nonce should be A
    crate::set_render_nonce("nonce_AAA");
    let html_a = error_page("a", "d");
    assert!(html_a.contains(r#"nonce="nonce_AAA""#),
        "first render must use nonce AAA");

    // Nonce set to B → render → nonce should be B
    crate::set_render_nonce("nonce_BBB");
    let html_b = error_page("b", "d");
    assert!(html_b.contains(r#"nonce="nonce_BBB""#),
        "second render must use nonce BBB");
    assert!(!html_b.contains("nonce_AAA"),
        "second render must not leak first nonce");
}

// =====================================================================
// RFC 027 — Accessibility: every flash level renders icon + text + class
// =====================================================================

/// Canonical FlashLevel data from the worker crate, inlined here so
/// cesauth-frontend stays independent of the worker crate.  These values must
/// match `cesauth_worker::flash::FlashLevel`.  A drift detector test in
/// the worker crate will catch any mismatch.
struct FlashLevelSpec {
    css_modifier: &'static str,
    aria_live:    &'static str,
    icon:         &'static str,
}

const FLASH_LEVELS: &[FlashLevelSpec] = &[
    FlashLevelSpec { css_modifier: "flash--info",    aria_live: "polite",    icon: "\u{2139}" }, // ℹ
    FlashLevelSpec { css_modifier: "flash--success", aria_live: "polite",    icon: "\u{2713}" }, // ✓
    FlashLevelSpec { css_modifier: "flash--warning", aria_live: "assertive", icon: "\u{26A0}" }, // ⚠
    FlashLevelSpec { css_modifier: "flash--danger",  aria_live: "assertive", icon: "\u{26D4}" }, // ⛔
];

#[test]
fn every_flash_level_pairs_css_class_icon_and_text() {
    // WCAG 1.4.1 Use of Color: color must not be the sole visual means
    // of conveying information.  Each flash level must carry all three:
    //   1. CSS class  (visual color styling)
    //   2. Icon glyph (shape signal, color-blind safe)
    //   3. Text label (rendered in the flash__text span)
    for spec in FLASH_LEVELS {
        let view = FlashView {
            aria_live:    spec.aria_live,
            css_modifier: spec.css_modifier,
            icon:         spec.icon,
            text:         std::borrow::Cow::Borrowed("test message"),
        };
        let html = flash_block(Some(view));

        // 1. CSS class
        assert!(
            html.contains(spec.css_modifier),
            "flash level '{}' missing css modifier class: {html}",
            spec.css_modifier
        );

        // 2. Icon — inside an aria-hidden span
        assert!(
            html.contains(r#"class="flash__icon" aria-hidden="true""#),
            "flash level '{}' missing aria-hidden icon span: {html}",
            spec.css_modifier
        );
        assert!(
            html.contains(spec.icon),
            "flash level '{}' icon character '{}' not present in output: {html}",
            spec.css_modifier,
            spec.icon
        );

        // 3. Text — inside a flash__text span
        assert!(
            html.contains(r#"class="flash__text""#),
            "flash level '{}' missing flash__text span: {html}",
            spec.css_modifier
        );
        assert!(
            html.contains("test message"),
            "flash level '{}' text not rendered: {html}",
            spec.css_modifier
        );
    }
}

#[test]
fn flash_block_icon_is_aria_hidden_not_in_text_span() {
    // Screen readers must not announce the icon glyph in addition to
    // the text — that would produce "tick TOTP enrolled" instead of
    // "TOTP enrolled".  Pin the separation: icon is in aria-hidden
    // span, text is in flash__text span with the icon absent.
    let html = flash_block(Some(FlashView {
        aria_live:    "polite",
        css_modifier: "flash--success",
        icon:         "\u{2713}",
        text:         std::borrow::Cow::Borrowed("TOTP enrolled"),
    }));

    // icon must appear before </span> with aria-hidden="true"
    assert!(
        html.contains(r#"<span class="flash__icon" aria-hidden="true">✓</span>"#),
        "icon must be in aria-hidden span: {html}"
    );

    // flash__text span must contain the text but NOT the icon
    let text_span_start = html.find(r#"class="flash__text""#).expect("flash__text span missing");
    let text_content = &html[text_span_start..];
    assert!(
        !text_content.contains("\u{2713}"),
        "icon character must not appear inside flash__text span: {html}"
    );
}

#[test]
fn flash_block_polite_uses_role_status_assertive_uses_role_alert() {
    // WAI-ARIA best practice: polite → role=status, assertive → role=alert.
    // Pinned separately from the existing tests so regression surfaces
    // at the right semantic level.
    let polite_html = flash_block(Some(FlashView {
        aria_live: "polite", css_modifier: "flash--info",
        icon: "ℹ", text: std::borrow::Cow::Borrowed("fyi"),
    }));
    assert!(polite_html.contains(r#"role="status""#) && polite_html.contains(r#"aria-live="polite""#),
        "polite flash must pair role=status with aria-live=polite: {polite_html}");

    let assertive_html = flash_block(Some(FlashView {
        aria_live: "assertive", css_modifier: "flash--danger",
        icon: "⛔", text: std::borrow::Cow::Borrowed("error"),
    }));
    assert!(assertive_html.contains(r#"role="alert""#) && assertive_html.contains(r#"aria-live="assertive""#),
        "assertive flash must pair role=alert with aria-live=assertive: {assertive_html}");
}

// ── RFC 072 — html lang attribute ─────────────────────────────────────────

#[test]
fn login_page_ja_uses_lang_ja() {
    let html = super::super::login_page_for("csrf", None, None, true, Locale::Ja);
    assert!(html.contains(r#"<html lang="ja""#),
        "JA locale must produce <html lang=\"ja\">");
}

#[test]
fn login_page_en_uses_lang_en() {
    let html = super::super::login_page_for("csrf", None, None, true, Locale::En);
    assert!(html.contains(r#"<html lang="en""#),
        "EN locale must produce <html lang=\"en\">");
}

#[test]
fn security_center_ja_uses_lang_ja() {
    use super::super::{security_center_page_for, SecurityCenterState, PrimaryAuthMethod};
    let state = SecurityCenterState {
        primary_method: PrimaryAuthMethod::Passkey,
        totp_enabled: false,
        recovery_codes_remaining: 10,
        active_sessions_count: None,
    };
    let html = security_center_page_for(&state, "", Locale::Ja);
    assert!(html.contains(r#"<html lang="ja""#));
}

#[test]
fn security_center_en_uses_lang_en() {
    use super::super::{security_center_page_for, SecurityCenterState, PrimaryAuthMethod};
    let state = SecurityCenterState {
        primary_method: PrimaryAuthMethod::Passkey,
        totp_enabled: false,
        recovery_codes_remaining: 10,
        active_sessions_count: None,
    };
    let html = security_center_page_for(&state, "", Locale::En);
    assert!(html.contains(r#"<html lang="en""#));
}

#[test]
fn admin_frame_uses_lang_ja() {
    // tokens::list_page is simple and goes through admin_frame
    use crate::admin::tokens::list_page;
    use cesauth_core::admin::types::{AdminPrincipal, Role};
    let p = AdminPrincipal { id: "x".into(), name: None, role: Role::ReadOnly, user_id: None };
    let html = list_page(&p, &[]);
    assert!(html.contains(r#"<html lang="ja""#),
        "admin frame must always use lang=\"ja\" (JA-only policy)");
}

// ── RFC 075 — Security Center summary card ────────────────────────────────

#[test]
fn security_summary_has_four_badge_slots() {
    let state = make_state(PrimaryAuthMethod::Passkey, true, 8);
    let html = security_center_page_for(&state, "", Locale::Ja);
    assert!(html.contains("security-summary__badges"),
        "must render summary badges section");
    // Passkey, TOTP, Recovery (totp enabled), sessions (None → hidden)
    assert!(html.contains("パスキー設定済み"), "passkey badge must appear in JA");
    assert!(html.contains("TOTP 有効"),        "totp badge must appear in JA");
    assert!(html.contains("リカバリーコード 8 残"), "recovery badge must appear in JA");
}

#[test]
fn security_summary_en_locale() {
    let state = make_state(PrimaryAuthMethod::Passkey, true, 5);
    let html = security_center_page_for(&state, "", Locale::En);
    assert!(html.contains("Passkey OK"),   "EN passkey badge");
    assert!(html.contains("TOTP enabled"), "EN TOTP badge");
    assert!(html.contains("Recovery: 5"), "EN recovery badge");
}

#[test]
fn security_summary_recovery_zero_uses_danger_badge() {
    let state = make_state(PrimaryAuthMethod::Passkey, true, 0);
    let html = security_center_page_for(&state, "", Locale::Ja);
    assert!(html.contains("badge--danger"), "0 recovery codes must use danger badge");
    assert!(html.contains("リカバリーコード 0 残"));
}

#[test]
fn security_summary_sessions_count_shown_when_some() {
    let mut state = make_state(PrimaryAuthMethod::Passkey, false, 0);
    state.active_sessions_count = Some(3);
    let html = security_center_page_for(&state, "", Locale::Ja);
    assert!(html.contains("セッション 3"), "session count must appear when Some");
}

#[test]
fn security_summary_sessions_hidden_when_none() {
    let state = make_state(PrimaryAuthMethod::Passkey, false, 0);
    // active_sessions_count is None by default in make_state
    let html = security_center_page_for(&state, "", Locale::Ja);
    assert!(!html.contains("セッション "), "session badge must be absent when count is None");
}

#[test]
fn security_summary_badges_have_icon_and_text() {
    let state = make_state(PrimaryAuthMethod::Passkey, true, 6);
    let html = security_center_page_for(&state, "", Locale::Ja);
    // Each badge must have both icon span and text span
    assert!(html.contains("badge__icon"), "badges must have icon span (WCAG 1.4.1)");
    assert!(html.contains("badge__text"), "badges must have text span");
}

// ── RFC 076 — Recovery code save-confirmation gate ────────────────────────

#[test]
fn recovery_codes_page_button_starts_disabled() {
    let html = totp_recovery_codes_page_for(
        &["ABCD-1234".to_string()],
        "csrf-x",
        Locale::Ja,
    );
    assert!(html.contains(r#"id="proceed-btn""#),
        "must have proceed button");
    assert!(html.contains(r#"disabled"#),
        "proceed button must start disabled (RFC 076)");
}

#[test]
fn recovery_codes_page_has_saved_confirm_checkbox_with_required() {
    let html = totp_recovery_codes_page_for(
        &["ABCD-1234".to_string()],
        "csrf-x",
        Locale::Ja,
    );
    assert!(html.contains(r#"name="saved_confirm""#),
        "must have saved_confirm checkbox");
    assert!(html.contains(r#"required"#),
        "checkbox must be required (RFC 076 — fallback for no-JS browsers)");
}

#[test]
fn recovery_codes_page_form_targets_confirm_route() {
    let html = totp_recovery_codes_page_for(
        &["ABCD-1234".to_string()],
        "csrf-x",
        Locale::Ja,
    );
    assert!(html.contains(r#"action="/me/security/totp/recover/confirm""#),
        "form must POST to the confirm route");
}

#[test]
fn recovery_codes_page_csrf_token_in_form() {
    let html = totp_recovery_codes_page_for(
        &["ABCD-1234".to_string()],
        "tok-abc",
        Locale::Ja,
    );
    assert!(html.contains(r#"value="tok-abc""#),
        "CSRF token must appear in the hidden input");
}

#[test]
fn recovery_codes_page_ja_confirm_label() {
    let html = totp_recovery_codes_page_for(
        &["ABCD-1234".to_string()],
        "csrf-x",
        Locale::Ja,
    );
    assert!(html.contains("リカバリーコードを安全に保管しました"),
        "JA confirm label must appear");
}

#[test]
fn recovery_codes_page_en_confirm_label() {
    let html = totp_recovery_codes_page_for(
        &["ABCD-1234".to_string()],
        "csrf-x",
        Locale::En,
    );
    assert!(html.contains("I have saved my recovery codes"),
        "EN confirm label must appear");
}

// ── RFC 077 — skip-to-content link (WCAG 2.4.1) ──────────────────────────

#[test]
fn end_user_frame_has_skip_link_ja() {
    let html = login_page_for("csrf", None, None, true, Locale::Ja);
    assert!(html.contains("href=\"#main\" class=\"skip-link\""),
        "JA login page must have skip-link");
    assert!(html.contains("メインコンテンツへスキップ"),
        "JA skip-link text must appear");
}

#[test]
fn end_user_frame_has_skip_link_en() {
    let html = login_page_for("csrf", None, None, true, Locale::En);
    assert!(html.contains("href=\"#main\" class=\"skip-link\""),
        "EN login page must have skip-link");
    assert!(html.contains("Skip to main content"),
        "EN skip-link text must appear");
}

#[test]
fn end_user_frame_main_has_id_main() {
    let html = login_page_for("csrf", None, None, true, Locale::Ja);
    assert!(html.contains("<main id=\"main\""),
        "main element must have id=main for skip-link target");
}

// ── RFC 079 — Magic Link not configured notice ────────────────────────────

#[test]
fn login_page_magic_link_available_renders_form() {
    let html = login_page_for("csrf", None, None, true, Locale::Ja);
    assert!(html.contains(r#"action="/magic-link/request""#),
        "when available=true, magic link form must be present");
}

#[test]
fn login_page_magic_link_unavailable_shows_notice_ja() {
    let html = login_page_for("csrf", None, None, false, Locale::Ja);
    assert!(!html.contains(r#"action="/magic-link/request""#),
        "when unavailable, magic link form must be absent");
    assert!(html.contains("メールリンクは現在ご利用いただけません"),
        "JA unavailable notice must appear");
}

#[test]
fn login_page_magic_link_unavailable_shows_notice_en() {
    let html = login_page_for("csrf", None, None, false, Locale::En);
    assert!(!html.contains(r#"action="/magic-link/request""#),
        "when unavailable, form absent");
    assert!(html.contains("Magic Link is currently unavailable"),
        "EN unavailable notice must appear");
}

#[test]
fn login_page_magic_link_unavailable_no_provider_details() {
    let html = login_page_for("csrf", None, None, false, Locale::Ja);
    // Must not leak provider name, API key presence, or error code
    assert!(!html.contains("SendGrid"),   "must not leak provider name");
    assert!(!html.contains("NotConfigured"), "must not leak error type");
    assert!(!html.contains("api_key"),    "must not leak config field");
}
