//! Disclosure — native <details>/<summary> wrapper (RFC 038).
//!
//! Used for advanced filters and advanced form sections. Zero-JS and
//! keyboard accessible by construction. Closed by default unless `open`.

use leptos::prelude::*;

#[component]
pub fn Disclosure(
    /// Text shown on the always-visible summary line.
    #[prop(into)]
    summary: String,
    /// Whether the disclosure starts open. Defaults to closed.
    #[prop(optional)]
    open: bool,
    children: Children,
) -> impl IntoView {
    view! {
        <details class="disclosure" open=open>
            <summary class="disclosure-summary">
                <span class="disclosure-chevron" aria-hidden="true">"›"</span>
                {summary}
            </summary>
            <div class="disclosure-body">
                {children()}
            </div>
        </details>
    }
}
