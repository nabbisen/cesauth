//! ErrorSummary — RFC 015 §"Multi-field error summary".
//!
//! Shown above a form when multiple fields fail. Each item links to the field.

use leptos::prelude::*;

#[component]
pub fn ErrorSummary(errors: Vec<(&'static str, String)>) -> impl IntoView {
    if errors.is_empty() {
        return view! {}.into_any();
    }
    view! {
        <div class="error-summary" role="alert" tabindex="-1">
            <h2 class="error-summary-title">"Check the form"</h2>
            <ul class="error-summary-list">
                {errors.into_iter().map(|(id, msg)| view! {
                    <li>
                        <a href=format!("#{id}")>{msg}</a>
                    </li>
                }).collect::<Vec<_>>()}
            </ul>
        </div>
    }
    .into_any()
}
