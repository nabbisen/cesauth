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
    match req.headers().get("accept-language") {
        Ok(Some(value)) => parse_accept_language(&value),
        _               => Locale::default(),
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

/// Convenience helper: resolve locale from a request and return the BCP-47
/// string directly (combines `resolve_locale` + `locale_str`).
pub fn resolve_locale_str(fallback: &'static str) -> &'static str {
    // For call sites that don't have a request (e.g. anonymous promote
    // which is a JSON API with no Accept-Language to read from), fall back
    // to the given static string.
    fallback
}
