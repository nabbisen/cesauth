//! Permission-denied panel — RFC 015.
//!
//! Imported from the mockup repository's `src/components/
//! primitives/permission_denied.rs` at pin `df3d9d0` (RFC 180, R2b).
//! This is one of R2a's two deliberate exclusions (RFC 131); it is
//! excluded no longer — see RFC 131's updated R2a note.

use cesauth_core::i18n::{lookup, Locale, MessageKey};
use leptos::prelude::*;

#[component]
pub fn PermissionDenied(
    #[prop(into, optional)] scope: Option<String>,
    #[prop(into, optional)] back_href: Option<String>,
    #[prop(default = Locale::default())] locale: Locale,
) -> impl IntoView {
    view! {
        <section class="card stack-md" style="border-color:var(--color-status-warning-border)">
            <h2 class="card-title">{lookup(MessageKey::PermissionDeniedTitle, locale)}</h2>
            <p>{lookup(MessageKey::PermissionDeniedBody, locale)}</p>
            {scope.map(|s| view! {
                <p class="text-small text-muted">"Scope attempted: " <code>{s}</code></p>
            })}
            {back_href.map(|href| view! {
                <a href=href class="btn btn-secondary btn-sm">
                    {lookup(MessageKey::ActionBack, locale)}
                </a>
            })}
        </section>
    }
}
