//! Originally part of `crates/core/src/i18n/tests.rs`.
//! Split into a sibling file in v0.78.0.

use super::super::*;

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

// =====================================================================
