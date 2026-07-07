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
// RFC 106 (v0.67.0) — Security Center TOTP enabled + recovery banners
//
// Closes the JA-hardcode hole that v0.39.0 deferred for the
// totp-enabled badge, the disable link, and the N=0 / N=1 / N≥2
// recovery banner copy.
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

// =====================================================================
// v0.47.0 — i18n-2 continuation: magic link / recovery codes /
// disable / error pages + PrimaryAuthMethod::label_for
// =====================================================================

#[test]
fn magic_link_sent_page_for_renders_japanese_default() {
    let html = magic_link_sent_page_for("alice@example.com", "csrf-tok", None, Locale::Ja);
    assert!(html.contains("メールを確認してください"));
    assert!(html.contains("ワンタイムコード"));
    assert!(html.contains("続ける"));
    // Privacy phrasing — must NOT confirm registration.
    assert!(html.contains("登録されている場合"),
        "JA intro must keep the privacy-preserving 'if registered' phrasing: {html}");
}

#[test]
fn magic_link_sent_page_for_renders_english() {
    let html = magic_link_sent_page_for("alice@example.com", "csrf", None, Locale::En);
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
