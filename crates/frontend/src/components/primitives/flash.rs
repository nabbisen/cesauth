//! Flash message — appears after PRG-style success in the mockup.
//!
//! The owning page controls visibility via the `visible` signal so the same
//! flash can be triggered by any dummy action.

use leptos::prelude::*;

#[component]
pub fn Flash(visible: RwSignal<Option<String>>) -> impl IntoView {
    view! {
        <Show when=move || visible.get().is_some() fallback=|| ()>
            <div class="flash" role="status" aria-live="polite">
                { move || visible.get().unwrap_or_default() }
            </div>
        </Show>
    }
}
