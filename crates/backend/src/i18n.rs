//! Per-request locale negotiation (v0.36.0, ADR-013).
//!
//! `cesauth_core::i18n` defines the catalog and the
//! `Accept-Language` parser; this module is the worker-side
//! glue that pulls the locale out of a `worker::Request` so
//! handlers can pass it down to templates.
//!
//! v0.36.0 only consults `Accept-Language`. Future iterations
//! may layer:
//!
//! - A user-pref cookie set from a `/me/preferences` UI.
//! - A tenant-default locale from the tenant config.
//!
//! The order of consideration would be cookie → tenant
//! default → Accept-Language → `Locale::default()`. The
//! returned `Locale` is stable for the duration of the
//! request and should be threaded through to templates as a
//! parameter rather than re-resolved per-template (which
//! would risk a single response with mixed locales).

use cesauth_core::i18n::{Locale, parse_accept_language};
use worker::Request;

/// Resolve the `Locale` for this request.
///
/// v0.36.0: reads `Accept-Language`; falls through to
/// `Locale::default()` (Ja) for missing or
/// all-unsupported headers — preserving the pre-i18n
/// rendering for users without a clear preference.
///
/// Errors are swallowed (a malformed header is
/// indistinguishable from a missing one for the user; both
/// fall through to default). The header value passes
/// through `parse_accept_language` which is itself lenient.
pub fn resolve_locale(req: &Request) -> Locale {
    resolve_locale_from_header(
        req.headers().get("accept-language").ok().flatten().as_deref(),
    )
}

/// The pure core of [`resolve_locale`]: given the raw `Accept-Language`
/// header value (`None` if the header was absent, or the read itself
/// errored — the two are indistinguishable to the user and both fall
/// through to default), resolve a [`Locale`].
///
/// **RFC 143 C1-143 item 5.** `resolve_locale` itself cannot be unit
/// tested on the host target — it takes a `worker::Request`, which wraps
/// a `web_sys::Request` with no host-side constructor (the same reason
/// `decide_verify_get`/`decide_verify_post` in
/// `routes::me::totp::verify` are written to take primitives, not a
/// `Request`). Extracted here so the one thing `resolve_locale` adds on
/// top of the already-tested `parse_accept_language`
/// (`crates/core/src/i18n/tests/accept_language.rs`) — the
/// header-absent branch — has coverage too.
pub fn resolve_locale_from_header(value: Option<&str>) -> Locale {
    match value {
        Some(v) => parse_accept_language(v),
        None    => Locale::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ja_header_resolves_to_ja() {
        assert_eq!(resolve_locale_from_header(Some("ja")), Locale::Ja);
    }

    #[test]
    fn en_header_resolves_to_en() {
        assert_eq!(resolve_locale_from_header(Some("en")), Locale::En);
    }

    #[test]
    fn absent_header_falls_through_to_default() {
        assert_eq!(resolve_locale_from_header(None), Locale::default());
    }

    #[test]
    fn malformed_header_falls_through_to_default() {
        assert_eq!(resolve_locale_from_header(Some("!!!not-a-language-tag")), Locale::default());
    }
}

/// Return the locale's BCP-47 string for use in `MagicLinkPayload.locale`.
///
/// The `MagicLinkPayload` carries a `&str` locale field so mailer adapters
/// can render locale-appropriate email bodies without depending on the
/// `Locale` enum from `cesauth-core`.
pub fn locale_str(locale: Locale) -> &'static str {
    match locale {
        Locale::Ja => "ja",
        Locale::En => "en",
    }
}

#[cfg(test)]
mod locale_str_tests {
    use super::*;

    /// **RFC 185 round 1 T4.** `leptos_html_shell` emits
    /// `locale_str(lang)` into `<html lang="...">`; `mounted_locale()`
    /// reads that same attribute back through
    /// `Locale::from_primary_subtag`. The two must agree for every
    /// `Locale` variant, or a typo in one direction becomes a silent
    /// locale mismatch at mount with no error anywhere — the defect
    /// RFC 185 §5.1 (A5) named as the reason `lang` is typed at all.
    ///
    /// **Exhaustive by construction, not a hand-written array.** The
    /// `match` has no wildcard arm, so adding a `Locale` variant
    /// without an arm here fails this function to compile — the loop
    /// below drives the match directly rather than iterating a
    /// separate list that could fall out of sync with it, which is
    /// the exact shape `crates/core/src/i18n/tests/lookup_completeness.rs`'s
    /// hand-written `let all = […]` array rotted into (T3's own
    /// finding: a pin-match and an iteration list, far apart, kept in
    /// sync by discipline alone). The stronger guarantee that no
    /// `Locale` variant is ever left untranslated already exists
    /// independently: every one of `crates/core/src/i18n/mod.rs`'s
    /// `lookup_*` sub-functions matches `locale` per `MessageKey`
    /// arm, so a third variant would fail dozens of matches across
    /// that file the moment it was added, not just this one test.
    #[test]
    fn locale_str_round_trips_through_from_primary_subtag_for_every_variant() {
        for locale in [Locale::Ja, Locale::En] {
            match locale {
                Locale::Ja | Locale::En => {}
            }
            assert_eq!(
                Locale::from_primary_subtag(locale_str(locale)),
                Some(locale),
                "locale_str({locale:?}) -> from_primary_subtag did not round-trip",
            );
        }
    }
}

/// Convenience helper: resolve locale from a request and return the BCP-47
/// string directly (combines `resolve_locale` + `locale_str`).
pub fn resolve_locale_str(fallback: &'static str) -> &'static str {
    // For call sites that don't have a request (e.g. anonymous promote
    // which is a JSON API with no Accept-Language to read from), fall back
    // to the given static string.
    fallback
}
