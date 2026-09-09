//! DangerZone — separated section for high-impact / irreversible actions.
//!
//! Per RFC 002: separate heading, consequence text before controls, audit
//! event name where known.

use leptos::prelude::*;

#[component]
pub fn DangerZone(
    #[prop(into)] title: String,
    #[prop(into, optional)] description: Option<String>,
    children: Children,
) -> impl IntoView {
    let aria = title.clone();
    view! {
        <section class="danger-zone" aria-label=aria>
            <h2 class="card-title">{title}</h2>
            {description.map(|d| view! { <p>{d}</p> })}
            {children()}
        </section>
    }
}

#[component]
pub fn DangerImpact(children: Children) -> impl IntoView {
    view! { <div class="impact">{children()}</div> }
}
