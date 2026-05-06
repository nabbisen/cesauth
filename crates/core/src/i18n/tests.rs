//! Unit tests for `cesauth_core::i18n`.

use super::*;

// =====================================================================
// Locale
// =====================================================================

#[test]
fn locale_default_is_ja_to_preserve_existing_ux() {
    // Existing v0.4 — v0.35.0 user-facing surfaces are
    // hardcoded Japanese. The default-locale tie-breaker
    // must keep that behavior for users who don't send
    // Accept-Language at all (mobile apps, scripts, etc.).
    assert_eq!(Locale::default(), Locale::Ja);
}

#[test]
fn locale_bcp47_returns_iso_639_1_subtag() {
    assert_eq!(Locale::Ja.bcp47(), "ja");
    assert_eq!(Locale::En.bcp47(), "en");
}

#[test]
fn from_primary_subtag_recognizes_supported() {
    assert_eq!(Locale::from_primary_subtag("ja"), Some(Locale::Ja));
    assert_eq!(Locale::from_primary_subtag("en"), Some(Locale::En));
}

#[test]
fn from_primary_subtag_is_case_insensitive() {
    // Real Accept-Language headers are normally lowercase
    // but RFC 5646 says language tags are case-insensitive.
    assert_eq!(Locale::from_primary_subtag("JA"), Some(Locale::Ja));
    assert_eq!(Locale::from_primary_subtag("Ja"), Some(Locale::Ja));
    assert_eq!(Locale::from_primary_subtag("EN"), Some(Locale::En));
}

#[test]
fn from_primary_subtag_strips_region_subtags() {
    // We don't distinguish ja-JP from ja, en-US from en —
    // see ADR-013 §"i18n-1 vs i18n-4 scoping". Region-aware
    // catalogs are i18n-4, deferred until real demand.
    assert_eq!(Locale::from_primary_subtag("ja-JP"), Some(Locale::Ja));
    assert_eq!(Locale::from_primary_subtag("en-US"), Some(Locale::En));
    assert_eq!(Locale::from_primary_subtag("en-GB"), Some(Locale::En));
}

#[test]
fn from_primary_subtag_returns_none_for_unsupported() {
    assert_eq!(Locale::from_primary_subtag("fr"),    None);
    assert_eq!(Locale::from_primary_subtag("zh-CN"), None);
    assert_eq!(Locale::from_primary_subtag(""),      None);
    assert_eq!(Locale::from_primary_subtag("xx"),    None);
}

// =====================================================================
// lookup() completeness
// =====================================================================

/// Iterate every `MessageKey` variant. The match here is
/// **compiler-exhaustive**: adding a new variant without
/// adding it to this list is a build error, not a silently-
/// missed test. This replaces the v0.36.0 manually-listed
/// array which had become tedious + error-prone with the 47
/// new variants v0.39.0 added.
///
/// The function takes a closure rather than returning a
/// collection because returning would either box the
/// closure-friendly iterator (allocation in tests is fine
/// but ugly) or build a `Vec` (also allocation). The
/// closure shape is the cleanest of the three.
fn for_each_key(mut f: impl FnMut(MessageKey)) {
    use MessageKey::*;
    // The match below MUST stay exhaustive. If you add a
    // variant to MessageKey, you'll get a compile error here
    // — fix it by adding the variant to one of the arms
    // below. Variants are grouped by surface (matching the
    // enum definition's grouping) to make the list scannable.
    let pin: MessageKey = FlashTotpEnabled;
    match pin {
        FlashTotpEnabled | FlashTotpDisabled | FlashTotpRecovered |
        FlashLoggedOut   | FlashSessionRevoked |
        TotpEnrollWrongCode |
        SessionsPageTitle | SessionsPageIntro | SessionsPageEmpty |
        SessionsBackLink  |
        SessionsCurrentBadge | SessionsCurrentDisabled |
        SessionsCurrentDisabledTitle | SessionsRevokeButton |
        SessionsAuthMethodPasskey | SessionsAuthMethodMagicLink |
        SessionsAuthMethodAdmin   | SessionsAuthMethodUnknown |
        SessionsLabelSignIn   | SessionsLabelLastSeen |
        SessionsLabelClient   | SessionsLabelSessionId |
        // v0.39.0 — login
        LoginTitle  | LoginIntro |
        LoginPasskeyHeading  | LoginPasskeyButton  |
        LoginPasskeyJsRequired | LoginPasskeyFailed |
        LoginEmailHeading    | LoginEmailLabel     | LoginEmailButton |
        LoginPageTitleHtml   |
        // v0.39.0 — TOTP enroll
        TotpEnrollTitle | TotpEnrollIntro | TotpEnrollQrAriaLabel |
        TotpEnrollManualSummary | TotpEnrollManualMeta |
        TotpEnrollConfirmHeading | TotpEnrollConfirmIntro |
        TotpEnrollCodeLabel | TotpEnrollConfirmButton |
        TotpEnrollCancelLink | TotpEnrollPageTitleHtml |
        // v0.39.0 — TOTP verify
        TotpVerifyTitle | TotpVerifyIntro |
        TotpVerifyHeading | TotpVerifyCodeLabel |
        TotpVerifyContinueButton | TotpVerifyLostSummary |
        TotpVerifyRecoverIntro | TotpVerifyRecoverAriaLabel |
        TotpVerifyRecoverCodeLabel | TotpVerifyRecoverButton |
        TotpVerifyPageTitleHtml | TotpVerifyWrongCode |
        // v0.39.0 — Security Center index
        SecurityTitle | SecurityIntro | SecurityPrimaryHeading |
        SecurityTotpHeading | SecurityTotpAnonymousNotice |
        SecurityTotpDisabledBadge | SecurityTotpDisabledIntro |
        SecurityTotpEnableLink |
        SecuritySessionsHeading | SecuritySessionsIntro |
        SecuritySessionsLink | SecurityBackLink | SecurityPageTitleHtml |
        // v0.45.0 — bulk revoke
        SessionsRevokeOthersButton | SessionsRevokeOthersConfirm |
        FlashOtherSessionsRevoked | FlashOtherSessionsRevokeFailed |
        FlashNoOtherSessions
            => {}  // exhaustiveness pin — body is irrelevant
    }
    // Now actually iterate. The list below mirrors the match
    // above; the match is the build-time guard, this is the
    // runtime walker.
    let all = [
        FlashTotpEnabled, FlashTotpDisabled, FlashTotpRecovered,
        FlashLoggedOut,   FlashSessionRevoked,
        TotpEnrollWrongCode,
        SessionsPageTitle, SessionsPageIntro, SessionsPageEmpty,
        SessionsBackLink,
        SessionsCurrentBadge, SessionsCurrentDisabled,
        SessionsCurrentDisabledTitle, SessionsRevokeButton,
        SessionsAuthMethodPasskey, SessionsAuthMethodMagicLink,
        SessionsAuthMethodAdmin,   SessionsAuthMethodUnknown,
        SessionsLabelSignIn,   SessionsLabelLastSeen,
        SessionsLabelClient,   SessionsLabelSessionId,
        LoginTitle,  LoginIntro,
        LoginPasskeyHeading,  LoginPasskeyButton,
        LoginPasskeyJsRequired, LoginPasskeyFailed,
        LoginEmailHeading,    LoginEmailLabel,     LoginEmailButton,
        LoginPageTitleHtml,
        TotpEnrollTitle, TotpEnrollIntro, TotpEnrollQrAriaLabel,
        TotpEnrollManualSummary, TotpEnrollManualMeta,
        TotpEnrollConfirmHeading, TotpEnrollConfirmIntro,
        TotpEnrollCodeLabel, TotpEnrollConfirmButton,
        TotpEnrollCancelLink, TotpEnrollPageTitleHtml,
        TotpVerifyTitle, TotpVerifyIntro,
        TotpVerifyHeading, TotpVerifyCodeLabel,
        TotpVerifyContinueButton, TotpVerifyLostSummary,
        TotpVerifyRecoverIntro, TotpVerifyRecoverAriaLabel,
        TotpVerifyRecoverCodeLabel, TotpVerifyRecoverButton,
        TotpVerifyPageTitleHtml, TotpVerifyWrongCode,
        SecurityTitle, SecurityIntro, SecurityPrimaryHeading,
        SecurityTotpHeading, SecurityTotpAnonymousNotice,
        SecurityTotpDisabledBadge, SecurityTotpDisabledIntro,
        SecurityTotpEnableLink,
        SecuritySessionsHeading, SecuritySessionsIntro,
        SecuritySessionsLink, SecurityBackLink, SecurityPageTitleHtml,
        SessionsRevokeOthersButton, SessionsRevokeOthersConfirm,
        FlashOtherSessionsRevoked, FlashOtherSessionsRevokeFailed,
        FlashNoOtherSessions,
    ];
    for k in all { f(k); }
}

/// Every supported locale must resolve every MessageKey to a
/// non-empty string.
#[test]
fn every_message_key_resolves_in_every_locale_to_nonempty() {
    for_each_key(|key| {
        for locale in [Locale::Ja, Locale::En] {
            let text = lookup(key, locale);
            assert!(!text.is_empty(),
                "lookup({key:?}, {locale:?}) returned empty string — \
                 every key must have a real translation in every locale");
        }
    });
}

/// Within one locale, no two keys may resolve to the SAME
/// rendered text. If they do, either the keys are redundant
/// or the translations have drifted to be indistinguishable.
/// Some legitimate exceptions are listed in `is_legitimate_duplicate`.
#[test]
fn no_two_keys_share_text_within_a_locale() {
    /// Returns true for the rare cases where two keys
    /// SHOULD share text (brand strings, repeated labels
    /// across locale boundaries).
    fn is_legitimate_duplicate(text: &str) -> bool {
        // Brand and term-of-art strings: legitimately the
        // same in every locale or across multiple keys.
        const SHARED: &[&str] = &[
            "Magic Link",
            "パスキー",
            "Passkey",
            // The phrase "Active sessions" / "アクティブなセッション"
            // is used both as the dedicated `/me/security/sessions`
            // page title (`SessionsPageTitle`) and as the
            // section heading on the Security Center index
            // (`SecuritySessionsHeading`). Same concept, two
            // surfaces; reusing the canonical translation is
            // correct.
            "Active sessions",
            "アクティブなセッション",
        ];
        SHARED.contains(&text)
    }

    for locale in [Locale::Ja, Locale::En] {
        let mut seen: std::collections::HashMap<&str, MessageKey> =
            std::collections::HashMap::new();
        for_each_key(|key| {
            let text = lookup(key, locale);
            if is_legitimate_duplicate(text) { return; }
            if let Some(prev) = seen.insert(text, key) {
                panic!(
                    "duplicate text {text:?} in locale {locale:?}: \
                     {prev:?} and {key:?} resolve to the same string"
                );
            }
        });
    }
}

// =====================================================================
// parse_accept_language()
// =====================================================================

#[test]
fn accept_language_empty_returns_default() {
    assert_eq!(parse_accept_language(""),    Locale::default());
    assert_eq!(parse_accept_language("   "), Locale::default());
}

#[test]
fn accept_language_single_supported() {
    assert_eq!(parse_accept_language("ja"), Locale::Ja);
    assert_eq!(parse_accept_language("en"), Locale::En);
}

#[test]
fn accept_language_with_region_subtag() {
    // Browsers commonly send "en-US,en;q=0.9". We strip
    // region subtags transparently.
    assert_eq!(parse_accept_language("en-US"),    Locale::En);
    assert_eq!(parse_accept_language("ja-JP"),    Locale::Ja);
    assert_eq!(parse_accept_language("zh-Hant"),  Locale::default(),
        "unsupported language with script subtag falls through");
}

#[test]
fn accept_language_q_value_priority() {
    // Lower q on the first entry: the second wins.
    assert_eq!(
        parse_accept_language("ja;q=0.5,en;q=1.0"),
        Locale::En,
    );
    // Higher q on the first entry: the first wins.
    assert_eq!(
        parse_accept_language("ja;q=1.0,en;q=0.5"),
        Locale::Ja,
    );
}

#[test]
fn accept_language_q_value_default_is_one() {
    // RFC 7231: a missing q is implicitly 1.0. So in
    // "fr;q=0.5,ja", the ja entry wins because its q is 1.0.
    assert_eq!(parse_accept_language("fr;q=0.5,ja"), Locale::Ja);
}

#[test]
fn accept_language_typical_browser_header() {
    // The shape Chrome / Firefox actually send.
    assert_eq!(
        parse_accept_language("en-US,en;q=0.9,ja;q=0.8"),
        Locale::En,
    );
    assert_eq!(
        parse_accept_language("ja-JP,ja;q=0.9,en;q=0.8"),
        Locale::Ja,
    );
}

#[test]
fn accept_language_q_zero_is_dropped() {
    // RFC 7231: q=0 means "not acceptable". "ja;q=0,en"
    // must NOT pick ja even though it's first in document
    // order.
    assert_eq!(parse_accept_language("ja;q=0,en"), Locale::En);
}

#[test]
fn accept_language_wildcard_resolves_to_default() {
    assert_eq!(parse_accept_language("*"),         Locale::default());
    assert_eq!(parse_accept_language("fr,*;q=0.5"), Locale::default());
}

#[test]
fn accept_language_all_unsupported_falls_through_to_default() {
    assert_eq!(parse_accept_language("fr"),        Locale::default());
    assert_eq!(parse_accept_language("fr,de,es"), Locale::default());
}

#[test]
fn accept_language_malformed_q_treated_as_one() {
    // Lenient: a garbage q value is treated as the implicit
    // 1.0 rather than rejecting the entry.
    assert_eq!(parse_accept_language("ja;q=garbage"), Locale::Ja);
    assert_eq!(parse_accept_language("ja;q="),         Locale::Ja);
}

#[test]
fn accept_language_handles_extra_whitespace() {
    assert_eq!(parse_accept_language("  ja  ,  en  ;  q=0.5  "), Locale::Ja);
    assert_eq!(parse_accept_language(" en ; q=0.9 , ja ; q=0.8 "), Locale::En);
}

#[test]
fn accept_language_tie_breaks_in_document_order() {
    // RFC 7231 doesn't specify tie-break; we go with
    // document order so the result is deterministic and
    // matches user intent (first-listed wins).
    assert_eq!(
        parse_accept_language("ja;q=0.8,en;q=0.8"),
        Locale::Ja,
    );
    assert_eq!(
        parse_accept_language("en;q=0.8,ja;q=0.8"),
        Locale::En,
    );
}
