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

/// Every supported locale must resolve every MessageKey to a
/// non-empty string. Pinning this property here prevents a
/// future "I added a new MessageKey variant and forgot the
/// `En` arm" regression from sneaking through review (the
/// compiler enforces match exhaustiveness, but a developer
/// could still write an empty literal).
#[test]
fn every_message_key_resolves_in_every_locale_to_nonempty() {
    let all_keys = [
        MessageKey::FlashTotpEnabled,
        MessageKey::FlashTotpDisabled,
        MessageKey::FlashTotpRecovered,
        MessageKey::FlashLoggedOut,
        MessageKey::FlashSessionRevoked,
        MessageKey::TotpEnrollWrongCode,
        MessageKey::SessionsPageTitle,
        MessageKey::SessionsPageIntro,
        MessageKey::SessionsPageEmpty,
        MessageKey::SessionsBackLink,
        MessageKey::SessionsCurrentBadge,
        MessageKey::SessionsCurrentDisabled,
        MessageKey::SessionsCurrentDisabledTitle,
        MessageKey::SessionsRevokeButton,
        MessageKey::SessionsAuthMethodPasskey,
        MessageKey::SessionsAuthMethodMagicLink,
        MessageKey::SessionsAuthMethodAdmin,
        MessageKey::SessionsAuthMethodUnknown,
        MessageKey::SessionsLabelSignIn,
        MessageKey::SessionsLabelLastSeen,
        MessageKey::SessionsLabelClient,
        MessageKey::SessionsLabelSessionId,
    ];

    for key in all_keys {
        for locale in [Locale::Ja, Locale::En] {
            let text = lookup(key, locale);
            assert!(!text.is_empty(),
                "lookup({key:?}, {locale:?}) returned empty string — \
                 every key must have a real translation in every locale");
        }
    }
}

/// Within one locale, no two keys may resolve to the SAME
/// rendered text. If they do, either the keys are redundant
/// (consolidate) or the translations have drifted to be
/// indistinguishable (a localization bug). This is a
/// soft-but-useful invariant; relax it later if a legitimate
/// duplicate emerges (e.g., "Cancel" used in two distinct
/// contexts where the developer wants per-context
/// flexibility).
#[test]
fn no_two_keys_share_text_within_a_locale() {
    let all_keys = [
        MessageKey::FlashTotpEnabled,
        MessageKey::FlashTotpDisabled,
        MessageKey::FlashTotpRecovered,
        MessageKey::FlashLoggedOut,
        MessageKey::FlashSessionRevoked,
        MessageKey::TotpEnrollWrongCode,
        MessageKey::SessionsPageTitle,
        MessageKey::SessionsPageIntro,
        MessageKey::SessionsPageEmpty,
        MessageKey::SessionsBackLink,
        MessageKey::SessionsCurrentBadge,
        MessageKey::SessionsCurrentDisabled,
        MessageKey::SessionsCurrentDisabledTitle,
        MessageKey::SessionsRevokeButton,
        // SessionsAuthMethodMagicLink intentionally omitted —
        // "Magic Link" is the same text in both ja and en
        // (the brand string), and that's expected.
        MessageKey::SessionsAuthMethodPasskey,
        MessageKey::SessionsAuthMethodAdmin,
        MessageKey::SessionsAuthMethodUnknown,
        MessageKey::SessionsLabelSignIn,
        MessageKey::SessionsLabelLastSeen,
        MessageKey::SessionsLabelClient,
        MessageKey::SessionsLabelSessionId,
    ];

    for locale in [Locale::Ja, Locale::En] {
        let mut seen: std::collections::HashMap<&str, MessageKey> =
            std::collections::HashMap::new();
        for key in all_keys {
            let text = lookup(key, locale);
            if let Some(prev) = seen.insert(text, key) {
                panic!(
                    "duplicate text {text:?} in locale {locale:?}: \
                     {prev:?} and {key:?} resolve to the same string"
                );
            }
        }
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
