//! MetricStrip / MetricChip — compact summary strip (RFC 039).
//!
//! Replaces heavy metric-card grids. Conveys a summary in one line so it does
//! not compete with attention items for the top of a dashboard. Each chip can
//! link to the section it summarises.

use leptos::prelude::*;
use leptos_router::components::A;

#[component]
pub fn MetricStrip(children: Children) -> impl IntoView {
    view! {
        <div class="metric-strip" role="list">
            {children()}
        </div>
    }
}

#[component]
pub fn MetricChip(
    /// Short label, e.g. "Users".
    #[prop(into)]
    label: String,
    /// Value, e.g. "12" or "Pro".
    #[prop(into)]
    value: String,
    /// Optional link target; when set the chip is a link.
    #[prop(into, optional)]
    href: Option<String>,
    /// Optional tone class suffix: "good" | "warn" | "danger". Neutral if unset.
    #[prop(into, optional)]
    tone: Option<String>,
) -> impl IntoView {
    let tone_class = tone
        .map(|t| format!("metric-chip metric-chip-{t}"))
        .unwrap_or_else(|| "metric-chip".to_string());

    match href {
        Some(h) => view! {
            <A href=h attr:class=format!("{tone_class} metric-chip-link") attr:role="listitem">
                <span class="metric-chip-label">{label}</span>
                <span class="metric-chip-value">{value}</span>
            </A>
        }
        .into_any(),
        None => view! {
            <span class=tone_class role="listitem">
                <span class="metric-chip-label">{label}</span>
                <span class="metric-chip-value">{value}</span>
            </span>
        }
        .into_any(),
    }
}
