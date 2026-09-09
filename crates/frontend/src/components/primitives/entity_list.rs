//! EntityList and EntityCard — RFC 002 §"EntityList" and §"EntityCard".
//!
//! Responsive table/list hybrid. Desktop: table with visible filters and sort.
//! Mobile (< 640 px): card list via `data-label` CSS — no JS required.

use leptos::prelude::*;

/// Column definition for EntityList desktop table header.
#[derive(Clone)]
pub struct Column {
    pub key: &'static str,
    pub label: &'static str,
    /// Hide on narrow screens (available via `data-label` in card view).
    pub secondary: bool,
}

impl Column {
    pub fn new(key: &'static str, label: &'static str) -> Self {
        Self {
            key,
            label,
            secondary: false,
        }
    }
    pub fn secondary(mut self) -> Self {
        self.secondary = true;
        self
    }
}

/// Responsive table/card container.
///
/// Children are the `<tbody>` rows; the component wraps them with the correct
/// `<table>` chrome. Rows must use `data-label` attributes on each `<td>` for
/// the mobile card layout to work.
///
/// ```html
/// <EntityList columns=cols empty_label="No users found.">
///     <tr>
///         <td data-label="Name">"Alice"</td>
///         <td data-label="Status">"Active"</td>
///     </tr>
/// </EntityList>
/// ```
#[component]
pub fn EntityList(
    columns: Vec<Column>,
    #[prop(into, optional)] aria_label: Option<String>,
    #[prop(into, optional)] empty_label: Option<String>,
    /// Render the actual row content (tbody).
    #[prop(optional)]
    has_rows: bool,
    children: Children,
) -> impl IntoView {
    let aria = aria_label.unwrap_or_else(|| "List".to_string());
    view! {
        <div class="table-wrap">
            {if !has_rows {
                view! {
                    <p class="empty-state-inline text-muted text-small">
                        {empty_label.unwrap_or_else(|| "No entries found.".into())}
                    </p>
                }.into_any()
            } else {
                view! {
                    <table class="entity-table" aria-label=aria>
                        <thead>
                            <tr>
                                {columns.into_iter().map(|col| view! {
                                    <th class=if col.secondary { "col-secondary" } else { "" }>
                                        {col.label}
                                    </th>
                                }).collect::<Vec<_>>()}
                            </tr>
                        </thead>
                        <tbody>
                            {children()}
                        </tbody>
                    </table>
                }.into_any()
            }}
        </div>
    }
}

/// Mobile entity card — the card-list item shown at < 640 px.
///
/// Wraps a set of `EntityCardRow` items. Also usable in the showcase for
/// explicit card-view demos at any screen width.
#[component]
pub fn EntityCard(children: Children) -> impl IntoView {
    view! {
        <div class="entity-card">{children()}</div>
    }
}

/// One label/value row inside an `EntityCard`.
#[component]
pub fn EntityCardRow(#[prop(into)] label: String, children: Children) -> impl IntoView {
    view! {
        <div class="entity-card-line">
            <span class="entity-card-label">{label}</span>
            <span class="entity-card-value">{children()}</span>
        </div>
    }
}
