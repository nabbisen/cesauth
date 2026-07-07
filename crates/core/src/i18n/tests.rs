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

// ─── Themed test groups split into sibling files (v0.78.0) ────────
mod lookup_completeness;
mod accept_language;
mod plural;
