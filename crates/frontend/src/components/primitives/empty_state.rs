//! Empty state with a clear next step.

use leptos::prelude::*;

#[component]
pub fn EmptyState(
    #[prop(into)] title: String,
    #[prop(into)] description: String,
    #[prop(optional)] children: Option<Children>,
) -> impl IntoView {
    view! {
        <div class="empty-state">
            <h3>{title}</h3>
            <p>{description}</p>
            {children.map(|c| c())}
        </div>
    }
}
