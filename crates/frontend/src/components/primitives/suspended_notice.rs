//! Suspended-tenant notice — RFC 015.
//!
//! Imported from the mockup repository's `src/components/
//! primitives/suspended_notice.rs` at pin `df3d9d0` (RFC 180, R2b).
//! This is one of R2a's two deliberate exclusions (RFC 131); it is
//! excluded no longer — see RFC 131's updated R2a note.

use cesauth_core::i18n::{lookup, Locale, MessageKey};
use leptos::prelude::*;

#[component]
pub fn SuspendedNotice(
    #[prop(into)] tenant_display: String,
    #[prop(default = Locale::default())] locale: Locale,
) -> impl IntoView {
    view! {
        <section class="card stack-md" style="border-color:var(--color-status-danger-border)">
            <div class="row">
                <span class="badge badge-danger">{lookup(MessageKey::StatusSuspended, locale)}</span>
                <strong>{tenant_display.clone()}</strong>
            </div>
            <h2 class="card-title">{lookup(MessageKey::SuspendedTenantTitle, locale)}</h2>
            <p>{lookup(MessageKey::SuspendedTenantBody, locale)}</p>
        </section>
    }
}
