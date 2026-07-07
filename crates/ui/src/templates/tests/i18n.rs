//! v0.39.0 + v0.47.0 — i18n cross-template tests.
//!
//! Split out from `templates/tests.rs` in v0.75.0 (test-file
//! modularization per the dev guidelines' 500-ELOC strongly-recommended
//! split threshold).

use super::super::*;
use super::super::chrome::frame;
#[allow(unused_imports)]
use cesauth_core::i18n::Locale;
#[allow(unused_imports)]
use super::common::strip_inline_style;

// v0.39.0 i18n: login + TOTP enroll/verify + Security Center
// rendering pins. The migrated `_for(.., locale)` variants
// must render the locale-appropriate strings; the plain
// shorthand defaults to Ja per the v0.36.0 backward-compat
// pattern.
// =====================================================================

#[test]
fn login_page_for_en_renders_english_chrome() {
    let html = login_page_for("csrf", None, None, true, Locale::En);
    assert!(html.contains("Sign in"),                  "missing EN title: {html}");
    assert!(html.contains("Sign in with a passkey"),    "missing EN passkey button");
    assert!(html.contains("Or email me a code"),        "missing EN email heading");
    assert!(html.contains("Email me a code"),           "missing EN email button");
    // No JA leaking through.
    assert!(!html.contains("サインインする"));
    assert!(!html.contains("パスキーでサインイン"));
}

#[test]
fn login_page_for_ja_renders_japanese_chrome() {
    let html = login_page_for("csrf", None, None, true, Locale::Ja);
    assert!(html.contains("サインインする"),                "missing JA title");
    assert!(html.contains("パスキーでサインイン"),          "missing JA passkey button");
    assert!(html.contains("メールアドレス"),                 "missing JA email label");
    // No EN leaking through.
    assert!(!html.contains("Sign in with a passkey"));
    assert!(!html.contains("Or email me a code"));
}

#[test]
fn login_page_default_shorthand_returns_japanese() {
    // v0.39.0 — the plain shorthand follows v0.36.0's
    // Default = Ja convention. Pre-v0.39.0 this returned
    // English (page was hardcoded EN); the v0.39.0 break
    // is intentional and called out in the CHANGELOG.
    let html = login_page("csrf", None, None);
    assert!(html.contains("サインインする"),
        "default-locale login shorthand must render JA per v0.36.0 Default = Ja");
}

#[test]
fn login_page_for_en_passkey_failed_message_in_inline_js() {
    // The JS error message comes through the catalog and
    // is interpolated as a JS string literal. Pin both
    // that the EN string is present and that it sits
    // inside double quotes (i.e., is a string literal,
    // not raw text).
    let html = login_page_for("csrf", None, None, true, Locale::En);
    assert!(html.contains(r#""Passkey sign-in didn't work. Try the email option.""#),
        "EN passkey-failed message must appear as a JS string literal: {html}");
}

#[test]
fn login_page_for_ja_passkey_failed_message_in_inline_js() {
    // The JA string contains multi-byte UTF-8; our
    // js_string_literal helper passes those through
    // verbatim. Pin that the JA string lands intact.
    let html = login_page_for("csrf", None, None, true, Locale::Ja);
    assert!(html.contains("パスキーでサインインできませんでした"),
        "JA passkey-failed message must appear in script body: {html}");
}

// ---------------------------------------------------------------------
// totp_enroll_page
// ---------------------------------------------------------------------

#[test]
fn totp_enroll_page_for_en_renders_english_chrome() {
    let html = totp_enroll_page_for("<svg/>", "JBSW", "csrf", None, Locale::En);
    assert!(html.contains("Set up an authenticator"));
    assert!(html.contains("Confirm with a code"));
    assert!(html.contains("Confirm and enable"));
    assert!(html.contains("Cancel and go back"));
    assert!(!html.contains("Authenticator を設定する"));
}

#[test]
fn totp_enroll_page_for_ja_renders_japanese_chrome() {
    let html = totp_enroll_page_for("<svg/>", "JBSW", "csrf", None, Locale::Ja);
    assert!(html.contains("Authenticator を設定する"));
    assert!(html.contains("確認して有効化する"));
    assert!(!html.contains("Set up an authenticator"));
}

#[test]
fn totp_enroll_page_for_en_qr_aria_label_translated() {
    let html = totp_enroll_page_for("<svg/>", "X", "csrf", None, Locale::En);
    assert!(html.contains(r#"aria-label="QR code containing your TOTP secret""#),
        "EN aria-label must be translated: {html}");
}

#[test]
fn totp_enroll_page_for_ja_qr_aria_label_translated() {
    let html = totp_enroll_page_for("<svg/>", "X", "csrf", None, Locale::Ja);
    assert!(html.contains(r#"aria-label="TOTP シークレットを含む QR コード""#),
        "JA aria-label must be translated: {html}");
}

// ---------------------------------------------------------------------
// totp_verify_page
// ---------------------------------------------------------------------

#[test]
fn totp_verify_page_for_en_renders_english_chrome() {
    let html = totp_verify_page_for("csrf", None, Locale::En);
    assert!(html.contains("Enter your code"));
    assert!(html.contains("Authenticator code"));
    assert!(html.contains("Lost your authenticator?"));
    assert!(html.contains("Use recovery code"));
    assert!(!html.contains("Authenticator コード"));
}

#[test]
fn totp_verify_page_for_ja_renders_japanese_chrome() {
    let html = totp_verify_page_for("csrf", None, Locale::Ja);
    assert!(html.contains("コードを入力してください"));
    assert!(html.contains("Authenticator コード"));
    assert!(html.contains("リカバリーコード"));
    assert!(!html.contains("Enter your code"));
}

// ---------------------------------------------------------------------
// security_center_page_for
// ---------------------------------------------------------------------

#[test]
fn security_center_page_for_en_renders_english_chrome() {
    let state = SecurityCenterState {
        primary_method: PrimaryAuthMethod::Passkey,
        totp_enabled: false,
        recovery_codes_remaining: 0,
        active_sessions_count: None,
    };
    let html = security_center_page_for(&state, "", Locale::En);
    assert!(html.contains(">Security<"),                       "EN page title");
    assert!(html.contains("Sign-in method"),                    "EN primary heading");
    assert!(html.contains("Two-factor authentication (TOTP)"),  "EN TOTP heading");
    assert!(html.contains("Active sessions"),                   "EN sessions heading");
    assert!(html.contains("View sessions"),                     "EN sessions link");
    assert!(html.contains("Back to home"),                      "EN back link");
    assert!(html.contains("Enable TOTP"),                       "EN enable-link (disabled state)");
    assert!(!html.contains("セキュリティ"));
}

#[test]
fn security_center_page_for_ja_renders_japanese_chrome() {
    let state = SecurityCenterState {
        primary_method: PrimaryAuthMethod::Passkey,
        totp_enabled: false,
        recovery_codes_remaining: 0,
        active_sessions_count: None,
    };
    let html = security_center_page_for(&state, "", Locale::Ja);
    assert!(html.contains("セキュリティ"));
    assert!(html.contains("サインイン方法"));
    assert!(html.contains("二段階認証 (TOTP)"));
    assert!(html.contains("TOTP を有効化する"));
    assert!(!html.contains("Sign-in method"));
}

#[test]
fn security_center_page_for_en_anonymous_notice_translated() {
    let state = SecurityCenterState {
        primary_method: PrimaryAuthMethod::Anonymous,
        totp_enabled: false,
        recovery_codes_remaining: 0,
        active_sessions_count: None,
    };
    let html = security_center_page_for(&state, "", Locale::En);
    assert!(html.contains("anonymous trial"),
        "EN anonymous TOTP notice must be translated: {html}");
    // We deliberately do NOT assert that no JA chars appear:
    // `PrimaryAuthMethod::label()` is independently localized
    // (still pre-i18n at v0.39.0; defer to v0.39.1+) and may
    // emit JA into the primary-row {label} slot regardless of
    // the page's negotiated locale. Migrating PrimaryAuthMethod
    // is a separable thread (it touches the admin console too).
}

// ---------------------------------------------------------------------
// RFC 106 (v0.67.0) — Security Center TOTP enabled + recovery banners
//
// Closes the JA-hardcode hole that v0.39.0 deferred for the
// totp-enabled badge, the disable link, and the N=0 / N=1 / N≥2
// recovery banner copy.
// ---------------------------------------------------------------------

#[test]
fn security_center_recovery_zero_renders_catalog_ja() {
    let state = SecurityCenterState {
        primary_method: PrimaryAuthMethod::Passkey,
        totp_enabled: true,
        recovery_codes_remaining: 0,
        active_sessions_count: None,
    };
    let html = security_center_page_for(&state, "", Locale::Ja);
    assert!(html.contains("リカバリーコード残なし。"),
        "JA recovery N=0 banner title must come from catalog: {html}");
    assert!(html.contains("flash--danger"),
        "N=0 must surface as a danger banner");
}

#[test]
fn security_center_recovery_zero_renders_catalog_en() {
    let state = SecurityCenterState {
        primary_method: PrimaryAuthMethod::Passkey,
        totp_enabled: true,
        recovery_codes_remaining: 0,
        active_sessions_count: None,
    };
    let html = security_center_page_for(&state, "", Locale::En);
    assert!(html.contains("No recovery codes remaining."),
        "EN recovery N=0 banner title must come from catalog: {html}");
    // Recovery banner JA strings must not leak into the EN page.
    assert!(!html.contains("リカバリーコード残なし"),
        "JA recovery banner must not leak into EN page");
}

#[test]
fn security_center_recovery_one_renders_catalog_ja() {
    let state = SecurityCenterState {
        primary_method: PrimaryAuthMethod::Passkey,
        totp_enabled: true,
        recovery_codes_remaining: 1,
        active_sessions_count: None,
    };
    let html = security_center_page_for(&state, "", Locale::Ja);
    assert!(html.contains("リカバリーコード: 残り 1 個。"),
        "JA recovery N=1 banner title must come from catalog: {html}");
    assert!(html.contains("flash--warning"),
        "N=1 must surface as a warning banner");
}

#[test]
fn security_center_recovery_one_renders_catalog_en() {
    let state = SecurityCenterState {
        primary_method: PrimaryAuthMethod::Passkey,
        totp_enabled: true,
        recovery_codes_remaining: 1,
        active_sessions_count: None,
    };
    let html = security_center_page_for(&state, "", Locale::En);
    assert!(html.contains("Recovery codes: 1 remaining."),
        "EN recovery N=1 banner title must come from catalog: {html}");
    assert!(!html.contains("リカバリーコード"),
        "JA recovery banner must not leak into EN page");
}

#[test]
fn security_center_recovery_many_renders_catalog_with_substitution() {
    // N >= 2 path: the catalog template carries `{n}` and the
    // template fn replaces it with the actual count.
    let state_ja = SecurityCenterState {
        primary_method: PrimaryAuthMethod::Passkey,
        totp_enabled: true,
        recovery_codes_remaining: 5,
        active_sessions_count: None,
    };
    let html_ja = security_center_page_for(&state_ja, "", Locale::Ja);
    assert!(html_ja.contains("リカバリーコード: 5 個有効"),
        "JA N>=2 path must substitute the count: {html_ja}");
    // The `{n}` placeholder itself must not leak into the rendered
    // output — that would mean the substitution never ran.
    assert!(!html_ja.contains("{n}"),
        "{{n}} placeholder must be replaced before rendering");

    // RFC 107 (ADR-013 §Q4 plural closure): EN now uses
    // proper plural agreement — `5 valid recovery codes`, not the
    // pre-v0.73.0 substitution form `Recovery codes: 5 valid`.
    let html_en = security_center_page_for(&state_ja, "", Locale::En);
    assert!(html_en.contains("5 valid recovery codes"),
        "EN N>=2 plural path (RFC 107) must use plural-aware form: {html_en}");
    assert!(!html_en.contains("{n}"),
        "{{n}} placeholder must be replaced before rendering (EN)");
}

#[test]
fn security_center_recovery_singular_renders_plural_one_form() {
    // RFC 107: N==1 path goes through the dedicated singular banner
    // (SecurityRecoveryOneTitle / OneDetail), NOT through
    // lookup_plural. But the existence of `Plural::One` and
    // `lookup_plural(SecurityRecoveryRemaining, En, 1)` is documented
    // separately — this test guards the i18n catalog.
    use cesauth_core::i18n::{lookup_plural, MessageKey};
    let en_one = lookup_plural(MessageKey::SecurityRecoveryRemaining, Locale::En, 1);
    assert_eq!(en_one, "1 valid recovery code",
        "EN plural::One form for SecurityRecoveryRemaining must use singular noun");
    let en_other = lookup_plural(MessageKey::SecurityRecoveryRemaining, Locale::En, 5);
    assert_eq!(en_other, "{n} valid recovery codes",
        "EN plural::Other form must use plural noun + {{n}} placeholder");
    let ja_one = lookup_plural(MessageKey::SecurityRecoveryRemaining, Locale::Ja, 1);
    let ja_two = lookup_plural(MessageKey::SecurityRecoveryRemaining, Locale::Ja, 2);
    assert_eq!(ja_one, ja_two,
        "JA is plural-invariant — same string for any count");
}

#[test]
fn security_center_totp_enabled_badge_uses_catalog() {
    let state = SecurityCenterState {
        primary_method: PrimaryAuthMethod::Passkey,
        totp_enabled: true,
        recovery_codes_remaining: 8,
        active_sessions_count: None,
    };
    let html_ja = security_center_page_for(&state, "", Locale::Ja);
    let html_en = security_center_page_for(&state, "", Locale::En);
    // Both locales surface the catalog-localized badge + disable link.
    // JA: "有効" / "TOTP を無効化する"  EN: "Enabled" / "Disable TOTP"
    assert!(html_ja.contains(">有効<"),
        "JA enabled badge must come from catalog: {html_ja}");
    assert!(html_ja.contains("TOTP を無効化する"),
        "JA disable link must come from catalog: {html_ja}");
    assert!(html_en.contains(">Enabled<"),
        "EN enabled badge must come from catalog: {html_en}");
    assert!(html_en.contains("Disable TOTP"),
        "EN disable link must come from catalog: {html_en}");
    // No JA bleed in EN
    assert!(!html_en.contains(">有効<"),
        "JA enabled badge must not leak into EN page: {html_en}");
    assert!(!html_en.contains("TOTP を無効化する"),
        "JA disable link must not leak into EN page: {html_en}");
}

// =====================================================================
// v0.47.0 — i18n-2 continuation: magic link / recovery codes /
// disable / error pages + PrimaryAuthMethod::label_for
// =====================================================================

#[test]
fn magic_link_sent_page_for_renders_japanese_default() {
    let html = magic_link_sent_page_for("alice@example.com", "csrf-tok", Locale::Ja);
    assert!(html.contains("メールを確認してください"));
    assert!(html.contains("ワンタイムコード"));
    assert!(html.contains("続ける"));
    // Privacy phrasing — must NOT confirm registration.
    assert!(html.contains("登録されている場合"),
        "JA intro must keep the privacy-preserving 'if registered' phrasing: {html}");
}

#[test]
fn magic_link_sent_page_for_renders_english() {
    let html = magic_link_sent_page_for("alice@example.com", "csrf", Locale::En);
    assert!(html.contains("Check your inbox"));
    assert!(html.contains("One-time code"));
    assert!(html.contains(">Continue<"));
    assert!(html.contains("If that address is registered"),
        "EN intro must keep the privacy-preserving 'if registered' phrasing: {html}");
}

#[test]
fn magic_link_sent_legacy_shorthand_now_renders_ja_default() {
    // v0.47.0 behavior change: pre-v0.47.0 the shorthand
    // rendered EN; v0.47.0 routes through _for with
    // Locale::default() which is Ja. Production handlers
    // were already on negotiated locales since v0.39.0,
    // so the shorthand isn't on the production hot path.
    let html = magic_link_sent_page("alice@example.com", "csrf");
    assert!(html.contains("メールを確認してください"),
        "v0.47.0 shorthand routes through Locale::default() (Ja): {html}");
    assert!(!html.contains(">Check your inbox<"));
}

#[test]
fn totp_recovery_codes_page_for_renders_japanese_default() {
    let codes = vec!["AAAA-BBBB-CCCC".to_owned()];
    let html = totp_recovery_codes_page_for(&codes, "csrf-test", Locale::Ja);
    assert!(html.contains("リカバリーコードを保存してください"));
    assert!(html.contains("これらのコードが表示されるのはこの一度だけです"));
    assert!(html.contains("AAAA-BBBB-CCCC"),
        "codes must surface verbatim regardless of locale");
}

#[test]
fn totp_recovery_codes_page_for_renders_english() {
    let codes = vec!["AAAA-BBBB".to_owned()];
    let html = totp_recovery_codes_page_for(&codes, "csrf-test", Locale::En);
    assert!(html.contains("Save your recovery codes"));
    assert!(html.contains("This is the only time these codes will be shown"));
    // RFC 076: old link replaced by form + checkbox + button
    assert!(html.contains("I have saved my recovery codes"),
        "EN save gate confirm label must appear");
    assert!(html.contains(r#"disabled"#),
        "proceed button must start disabled");
}

#[test]
fn totp_disable_confirm_page_for_renders_japanese_default() {
    let html = totp_disable_confirm_page_for("csrf", Locale::Ja);
    assert!(html.contains("二要素認証を無効にしますか?"));
    assert!(html.contains("アカウントのTOTPがオフになります"));
    assert!(html.contains("TOTPを無効にする"));
    assert!(html.contains("キャンセルして戻る"),
        "cancel link reuses TotpEnrollCancelLink");
}

#[test]
fn totp_disable_confirm_page_for_renders_english() {
    let html = totp_disable_confirm_page_for("csrf", Locale::En);
    assert!(html.contains("Disable two-factor authentication?"));
    assert!(html.contains("Yes, disable TOTP"));
    assert!(html.contains("Cancel and go back"),
        "EN cancel link reuses TotpEnrollCancelLink");
}

#[test]
fn error_page_for_renders_localized_back_link() {
    // title and detail are caller-supplied; only the
    // back-to-sign-in link uses the catalog.
    let html_ja = error_page_for("Title-JA", "detail", Locale::Ja);
    let html_en = error_page_for("Title-EN", "detail", Locale::En);
    assert!(html_ja.contains("サインインに戻る"));
    assert!(html_en.contains(">Back to sign in<"));
    // Titles surface verbatim.
    assert!(html_ja.contains("Title-JA"));
    assert!(html_en.contains("Title-EN"));
}

#[test]
fn primary_auth_method_label_for_renders_each_locale() {
    use PrimaryAuthMethod::*;
    assert_eq!(Passkey  .label_for(Locale::Ja), "パスキー");
    assert_eq!(Passkey  .label_for(Locale::En), "Passkey");
    assert_eq!(MagicLink.label_for(Locale::Ja), "メールリンク");
    assert_eq!(MagicLink.label_for(Locale::En), "Magic Link");
    assert_eq!(Anonymous.label_for(Locale::Ja), "匿名トライアル");
    assert_eq!(Anonymous.label_for(Locale::En), "Anonymous trial");
}

// =====================================================================
