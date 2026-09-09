//! Tabs.
//!
//! Tabs are presentational here — selection lives in the page; a click sets a
//! signal the page reads to render the active panel.

use leptos::prelude::*;

#[component]
pub fn Tabs(
    /// (key, label) pairs.
    tabs: Vec<(String, String)>,
    /// Reactive active key.
    active: RwSignal<String>,
) -> impl IntoView {
    view! {
        <div class="tabs" role="tablist">
            {tabs.into_iter().map(|(key, label)| {
                let key_for_click = key.clone();
                let key_for_match = key.clone();
                let selected = move || active.get() == key_for_match;
                view! {
                    <button
                        class="tab"
                        role="tab"
                        aria-selected=move || selected().to_string()
                        on:click=move |_| active.set(key_for_click.clone())
                    >
                        {label}
                    </button>
                }
            }).collect::<Vec<_>>()}
        </div>
    }
}
