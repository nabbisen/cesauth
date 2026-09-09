//! Inline alert.
//!
//! For form errors, callers should set `role="alert"` via the
//! `is_form_error` prop. Status updates (success/info) get `aria-live=polite`.

use leptos::prelude::*;

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum AlertKind {
    Info,
    Success,
    Warning,
    Danger,
}

impl AlertKind {
    fn class(self) -> &'static str {
        match self {
            AlertKind::Info => "alert alert-info",
            AlertKind::Success => "alert alert-success",
            AlertKind::Warning => "alert alert-warning",
            AlertKind::Danger => "alert alert-danger",
        }
    }
    fn icon(self) -> &'static str {
        match self {
            AlertKind::Info => "i",
            AlertKind::Success => "✓",
            AlertKind::Warning => "!",
            AlertKind::Danger => "!",
        }
    }
}

#[component]
pub fn Alert(
    kind: AlertKind,
    #[prop(into, optional)] title: Option<String>,
    #[prop(default = false)] is_form_error: bool,
    children: Children,
) -> impl IntoView {
    let role = if is_form_error { "alert" } else { "status" };
    let live = if is_form_error { "assertive" } else { "polite" };

    view! {
        <div class=kind.class() role=role aria-live=live>
            <span class="alert-icon" aria-hidden="true">{kind.icon()}</span>
            <div class="alert-body">
                {title.map(|t| view! { <div class="alert-title">{t}</div> })}
                <div class="alert-text">{children()}</div>
            </div>
        </div>
    }
}
