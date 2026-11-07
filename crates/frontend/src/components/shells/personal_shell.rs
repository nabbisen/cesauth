//! PersonalShell — authenticated user's self-service shell.
//!
//! Imported from the mockup repository's `src/components/
//! shells/personal_shell.rs` at pin `df3d9d0` (RFC 180, R2b). Security
//! posture is the main mental model; navigation is shallow.
//!
//! **No mock data**: the mockup's `user_email` prop was optional,
//! defaulting to `"alice@example.com"`. RFC 131 §5 bars committing
//! mock data at any intermediate step, so it is now a required prop
//! — a future caller (R3) must supply the real session email.
//!
//! **No `LocaleToggle`** — see `nav/topbar.rs`'s own doc comment.
//! `locale` is a plain prop (RFC 180 §5: no reactive locale context).

use leptos::prelude::*;
use leptos_router::components::A;

use crate::components::nav::topbar::{BrandMark, UserPill};
use cesauth_core::i18n::{lookup, Locale, MessageKey};

#[component]
pub fn PersonalShell(
    #[prop(into)] user_email: String,
    #[prop(default = Locale::default())] locale: Locale,
    children: Children,
) -> impl IntoView {
    view! {
        <div class="personal-shell">
            <header class="personal-topbar">
                <div class="row">
                    <BrandMark href="/me/security"/>
                    <nav aria-label="Personal" class="row">
                        <A href="/me/security">{lookup(MessageKey::SecurityTitle, locale)}</A>
                        // RFC 180 (R2b): the mockup linked "/me/sessions",
                        // which the worker never registered -- the real
                        // path is "/me/security/sessions". Corrected
                        // rather than carried forward.
                        <A href="/me/security/sessions">{lookup(MessageKey::SessionsPageTitle, locale)}</A>
                    </nav>
                </div>
                <div class="user-menu">
                    <UserPill initials="AT" name=user_email/>
                    <a href="/login" class="btn btn-ghost btn-sm">
                        {lookup(MessageKey::ActionSignOut, locale)}
                    </a>
                </div>
            </header>

            <main id="main" class="personal-main">
                {children()}
            </main>

            <footer class="auth-footer">
                <span>{lookup(MessageKey::PoweredBy, locale)}</span>
            </footer>
        </div>
    }
}
