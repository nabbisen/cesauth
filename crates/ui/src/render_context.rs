//! `RenderContext` — per-request rendering parameters.
//!
//! **v0.52.0 (RFC 006)**: Introduction of `RenderContext` bundles the two
//! parameters that every HTML template now requires:
//!
//! - `locale` — BCP-47 locale for i18n string lookup.
//! - `nonce` — CSP nonce value to inject into inline `<style>`/`<script>` tags.
//!
//! Before v0.52.0, template functions took a bare `Locale` parameter.
//! Adding `CspNonce` as a second parameter to every function would cause
//! wide call-site churn; bundling into `RenderContext` keeps the diff
//! contained to one new type and the per-function signature change is a
//! single parameter swap.
//!
//! ## Upgrade path for call sites (v0.51.x → v0.52.0)
//!
//! Old:
//! ```rust,ignore
//! cesauth_ui::templates::login_page_for(csrf, None, sitekey, locale)
//! ```
//!
//! New:
//! ```rust,ignore
//! let ctx = RenderContext::new(locale, &nonce);
//! cesauth_ui::templates::login_page_for(csrf, None, sitekey, &ctx)
//! ```

use cesauth_core::i18n::Locale;
use cesauth_core::security_headers::CspNonce;

/// Per-request rendering context.
///
/// Construct one per HTML response via `RenderContext::new` and pass it
/// to every template function. The context is cheap to clone (two fields:
/// a `Locale` enum variant and a `String` wrapper).
#[derive(Debug, Clone)]
pub struct RenderContext {
    pub locale: Locale,
    pub nonce:  String,
}

impl RenderContext {
    /// Construct from a `Locale` and a fresh `CspNonce`.
    pub fn new(locale: Locale, nonce: &CspNonce) -> Self {
        Self {
            locale,
            nonce: nonce.as_str().to_owned(),
        }
    }

    /// The nonce string (without `'nonce-...'` wrapper) — for use in
    /// `<style nonce="...">` and `<script nonce="...">` attributes.
    pub fn nonce_str(&self) -> &str {
        &self.nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_context_exposes_locale_and_nonce() {
        // Create a synthetic nonce for tests. CspNonce::generate() requires
        // a CSPRNG; in unit tests we use a known value via the From<String>
        // conversion used in test helpers.
        let ctx = RenderContext {
            locale: Locale::En,
            nonce:  "testnonce123".to_owned(),
        };
        assert_eq!(ctx.locale, Locale::En);
        assert_eq!(ctx.nonce_str(), "testnonce123");
    }
}
