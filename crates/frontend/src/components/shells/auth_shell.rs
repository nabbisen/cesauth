//! AuthShell — public authentication layout (login, OTP, TOTP, invite, error).
//!
//! Imported from the mockup repository's `src/components/
//! shells/auth_shell.rs` at pin `df3d9d0` (RFC 180, R2b). No tenant
//! administration links, no auto-redirect, calm and minimal.
//!
//! **Dormant, like every file this cycle imports** — nothing routes to
//! it yet (R3). Its four footer strings (`PoweredBy`, `Privacy`,
//! `Terms`, `Status`) resolve through `cesauth_core::i18n::lookup`,
//! the same per-request path the server-rendered pre-auth templates
//! already use (RFC 180 §4.3: pre-auth is `server`-classified per
//! RFC 132 §13 q1, so there is no reactive mount-time locale here —
//! `locale` is a plain prop a future server-side caller supplies from
//! the request, not read from the DOM the way the CSR shells below
//! read it once at mount).
//!
//! **No `LocaleToggle`** — see `nav/topbar.rs`'s own doc comment for
//! why; this file's `<LocaleToggle/>` was dropped along with it.

use leptos::prelude::*;

use crate::components::nav::topbar::BrandMark;
use cesauth_core::i18n::{lookup, Locale, MessageKey};

/// The four footer strings this shell renders, in render order
/// (`PoweredBy`, `Privacy`, `Terms`, `Status`). Factored out of the
/// `view!` body so a host test can assert exactly what this caller
/// renders — asserting that the four `MessageKey` variants exist and
/// resolve (already covered by `lookup_completeness.rs`) is not the
/// same as asserting this shell calls them, in this order, in both
/// locales.
fn footer_strings(locale: Locale) -> [&'static str; 4] {
    [
        lookup(MessageKey::PoweredBy, locale),
        lookup(MessageKey::Privacy, locale),
        lookup(MessageKey::Terms, locale),
        lookup(MessageKey::Status, locale),
    ]
}

#[component]
pub fn AuthShell(
    #[prop(default = Locale::default())] locale: Locale,
    children: Children,
) -> impl IntoView {
    let [powered_by, privacy, terms, status] = footer_strings(locale);
    view! {
        <div class="auth-shell">
            <header class="auth-header">
                <BrandMark href="/login"/>
            </header>

            <main id="main" class="auth-main">
                {children()}
            </main>

            <footer class="auth-footer">
                <span>{powered_by}</span>
                " · "
                <a href="#">{privacy}</a>
                " · "
                <a href="#">{terms}</a>
                " · "
                <a href="#">{status}</a>
            </footer>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn footer_strings_render_in_japanese() {
        assert_eq!(
            footer_strings(Locale::Ja),
            ["Cloudflare 上でホスト", "プライバシー", "利用規約", "ステータス"],
        );
    }

    #[test]
    fn footer_strings_render_in_english() {
        assert_eq!(
            footer_strings(Locale::En),
            ["Hosted on Cloudflare", "Privacy", "Terms", "Status"],
        );
    }
}
