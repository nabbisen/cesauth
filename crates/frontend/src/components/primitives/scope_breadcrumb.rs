//! ScopeBreadcrumb — surfaces the authorization scope path.
//!
//! Per RFC 002 / mockup external design §8.2: ancestors are clickable when
//! the current actor has permission; current scope is visually emphasized.

use leptos::prelude::*;
use leptos_router::components::A;

#[derive(Clone, Debug)]
pub struct ScopeCrumb {
    /// e.g. "Tenant", "Organization", "User".
    pub kind: &'static str,
    /// Display label (slug or display name).
    pub label: String,
    /// Optional URL — `None` means non-clickable (current or restricted).
    pub href: Option<String>,
    /// True for the current/leaf crumb (gets visual emphasis).
    pub current: bool,
}

#[component]
pub fn ScopeBreadcrumb(crumbs: Vec<ScopeCrumb>) -> impl IntoView {
    let last = crumbs.len().saturating_sub(1);
    let items: Vec<_> = crumbs
        .into_iter()
        .enumerate()
        .map(|(i, crumb)| {
            let label = format!("{}: {}", crumb.kind, crumb.label);
            let inner = match (crumb.href.clone(), crumb.current) {
                (Some(href), false) => view! {
                    <A href=href attr:class="crumb">{label.clone()}</A>
                }
                .into_any(),
                _ => view! {
                    <span
                        class=if crumb.current { "crumb crumb-current" } else { "crumb" }
                        aria-current=if crumb.current { "page" } else { "" }
                    >
                        {label.clone()}
                    </span>
                }
                .into_any(),
            };
            view! {
                {inner}
                {(i < last).then(|| view! { <span class="sep" aria-hidden="true">" / "</span> })}
            }
        })
        .collect();

    view! {
        <nav class="scope-breadcrumb" aria-label="Scope">
            {items}
        </nav>
    }
}
