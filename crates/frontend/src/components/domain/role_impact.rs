//! RoleImpactPreview — explains what a role assignment will allow before
//! the administrator submits. Most important admin UX in the mockup.
//!
//! Imported from the mockup repository's `src/components/
//! domain/role_impact.rs` at pin `df3d9d0` (RFC 180, R2b). Continuously
//! builds a "grant statement" as inputs change.
//!
//! `locale` is a plain prop (RFC 180 §5: no reactive locale context).

use leptos::prelude::*;

use crate::view_models::roles::RoleView;
use cesauth_core::i18n::{lookup, Locale, MessageKey};

#[component]
pub fn RoleImpactPreview(
    #[prop(into)] principal_label: String,
    #[prop(into)] scope_label: String,
    #[prop(default = Locale::default())] locale: Locale,
    role: RoleView,
) -> impl IntoView {
    let allowed = role.allowed.clone();
    let not_allowed = role.not_allowed.clone();
    let role_name = role.display_name.clone();
    let role_name_for_p = role_name.clone();

    view! {
        <section class="card stack-md" aria-label="Role impact preview">
            <h3 class="card-title">"Impact preview"</h3>
            <p>
                "Grant "
                <strong>{role_name_for_p}</strong>
                " to "
                <strong>{principal_label.clone()}</strong>
                " for "
                <strong>{scope_label.clone()}</strong>
                "."
            </p>
            <div class="grid grid-cards-2">
                <div>
                    <h4 class="text-small text-muted" style="text-transform:uppercase">
                        {lookup(MessageKey::RoleAssignPreviewAllowed, locale)}
                    </h4>
                    <ul>
                        {allowed.into_iter().map(|a| view! {
                            <li>"✓ " {a}</li>
                        }).collect::<Vec<_>>()}
                    </ul>
                </div>
                <div>
                    <h4 class="text-small text-muted" style="text-transform:uppercase">
                        {lookup(MessageKey::RoleAssignPreviewNotAllowed, locale)}
                    </h4>
                    <ul>
                        {not_allowed.into_iter().map(|a| view! {
                            <li>"× " {a}</li>
                        }).collect::<Vec<_>>()}
                    </ul>
                </div>
            </div>
            <p class="alert alert-info" role="status">
                <span class="alert-icon" aria-hidden="true">"i"</span>
                <span class="alert-body">
                    {lookup(MessageKey::RoleAssignAuditNotice, locale)}
                </span>
            </p>
        </section>
    }
}
