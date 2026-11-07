//! Top bar used by personal, admin, and operator shells.
//!
//! Imported from the mockup repository's `src/components/
//! nav/topbar.rs` at pin `df3d9d0` (RFC 180, R2b). Slots: brand,
//! optional center context (tenant switcher), trailing user pill.
//!
//! **`LocaleToggle` is deliberately not imported.** The mockup's
//! version is a *live* switcher (`use_locale()`, a reactive signal,
//! `on:click` handlers that call `locale.set(...)`) — exactly what
//! RFC 180 §5 bars: "do not build a locale switcher or a reactive
//! locale context." `MessageKey::LocaleSwitchLabel` (the aria-label
//! string it would use) is still in the catalog, in case a future,
//! non-reactive rendering wants it; the component itself is not here.

use leptos::prelude::*;
use leptos_router::components::A;

use crate::icons::IconLogo;

#[component]
pub fn BrandMark(
    /// Where the brand mark links to.
    #[prop(into, optional, default = "/".to_string())]
    href: String,
) -> impl IntoView {
    view! {
        <A href=href attr:class="brand-mark">
            <IconLogo/>
            <span>"cesauth"</span>
        </A>
    }
}

#[component]
pub fn UserPill(#[prop(into)] initials: String, #[prop(into)] name: String) -> impl IntoView {
    let init = initials.clone();
    view! {
        <span class="user-pill">
            <span class="user-avatar" aria-hidden="true">{init}</span>
            <span>{name}</span>
        </span>
    }
}
