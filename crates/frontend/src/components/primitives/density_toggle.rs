//! DensityToggle — Simple / Detailed segmented control (RFC 038).
//!
//! Embodies the "less is more" principle: the default (Simple) shows the
//! smallest useful column set; matured users opt into Detailed.

use leptos::prelude::*;

#[component]
pub fn DensityToggle(
    /// `false` = Simple (default), `true` = Detailed.
    detailed: RwSignal<bool>,
) -> impl IntoView {
    view! {
        <div class="density-toggle" role="group" aria-label="View density">
            <button
                type="button"
                class=move || if !detailed.get() { "density-btn active" } else { "density-btn" }
                aria-pressed=move || (!detailed.get()).to_string()
                on:click=move |_| detailed.set(false)
            >
                "Simple"
            </button>
            <button
                type="button"
                class=move || if detailed.get() { "density-btn active" } else { "density-btn" }
                aria-pressed=move || detailed.get().to_string()
                on:click=move |_| detailed.set(true)
            >
                "Detailed"
            </button>
        </div>
    }
}
