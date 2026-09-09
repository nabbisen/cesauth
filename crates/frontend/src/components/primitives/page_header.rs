//! Page header — the canonical layout per RFC 001 §"Page header contract".
//!
//! `ScopeLabel`, `Title`, `Description`, optional `PrimaryAction`, optional
//! `MetaLine`. Anything more belongs in the workspace or context panel.

use leptos::prelude::*;

#[component]
pub fn PageHeader(
    #[prop(into, optional)] scope_label: Option<String>,
    #[prop(into)] title: String,
    #[prop(into, optional)] description: Option<String>,
    #[prop(optional)] children: Option<Children>,
) -> impl IntoView {
    view! {
        <header class="page-header">
            <div class="page-header-text">
                {scope_label.map(|s| view! {
                    <div class="scope-breadcrumb" aria-label="Scope">
                        <span class="crumb">{s}</span>
                    </div>
                })}
                <h1 class="page-h1">{title}</h1>
                {description.map(|d| view! { <p class="page-description">{d}</p> })}
            </div>
            {children.map(|c| view! { <div class="page-actions">{c()}</div> })}
        </header>
    }
}
