//! Status / scope badge.

use leptos::prelude::*;

#[component]
pub fn Badge(
    /// CSS class on top of `.badge` — `badge-success`, `badge-warning`,
    /// `badge-danger`, `badge-info`, `badge-neutral`, or a `badge-scope-*`.
    #[prop(into)]
    class: String,
    children: Children,
) -> impl IntoView {
    let cls = format!("badge {}", class);
    view! { <span class=cls>{children()}</span> }
}
