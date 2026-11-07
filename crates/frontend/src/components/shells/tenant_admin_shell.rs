//! TenantAdminShell — grouped sidebar (RFC 018, RFC 030).
//!
//! Imported from the mockup repository's `src/components/
//! shells/tenant_admin_shell.rs` at pin `df3d9d0` (RFC 180, R2b).
//! RFC 030 replaces the `EffectiveRole` enum with `TenantCapabilitiesView`.
//!
//! **No mock data**: the mockup hardcoded `UserPill initials="AT"
//! name="alice@example.com"`. RFC 131 §5 bars committing mock data at
//! any intermediate step, so both are now required props — a future
//! caller (R3) must supply the real session identity.
//!
//! **No `LocaleToggle`** — see `nav/topbar.rs`'s own doc comment.
//! `locale` is a plain prop (RFC 180 §5: no reactive locale context).

use crate::components::nav::topbar::{BrandMark, UserPill};
use crate::view_models::shared::TenantCapabilitiesView;
use cesauth_core::i18n::{lookup, Locale, MessageKey};
use leptos::prelude::*;
use leptos_router::components::A;

#[component]
pub fn TenantAdminShell(
    #[prop(into)] tenant_slug: String,
    #[prop(into)] tenant_display: String,
    #[prop(into)] active: String,
    #[prop(into)] admin_initials: String,
    #[prop(into)] admin_name: String,
    #[prop(default = Locale::default())] locale: Locale,
    /// Optional status badge: `Some((css_class, label_text))` or `None`.
    /// Pass `None` when no badge is available.
    tenant_badge: Option<(String, String)>,
    /// Capability set for the authenticated user. `None` → full admin access.
    capabilities: Option<TenantCapabilitiesView>,
    children: Children,
) -> impl IntoView {
    let caps = capabilities.unwrap_or_else(TenantCapabilitiesView::tenant_admin);
    let s = tenant_slug.clone();
    let ak2 = active.clone();

    fn sidebar_nav_item(
        href: String,
        label: &'static str,
        is_active: bool,
        locked: bool,
    ) -> impl leptos::prelude::IntoView {
        use leptos::prelude::*;
        if locked {
            view! {
                <a href=href class="sidebar-link sidebar-link-locked"
                    aria-disabled="true" tabindex="-1">
                    <span aria-hidden="true">"\u{1F512} "</span>{label}
                </a>
            }
            .into_any()
        } else {
            view! {
                <a href=href class=if is_active { "sidebar-link active" } else { "sidebar-link" }>
                    {label}
                </a>
            }
            .into_any()
        }
    }

    let is_auditor = !caps.can_manage_users && caps.can_read_audit;

    view! {
        <div class="admin-shell">
            <header class="admin-topbar">
                <div class="row">
                    <BrandMark href="/"/>
                    <button class="tenant-switcher" type="button" aria-haspopup="menu">
                        <span class="tenant-switcher-label">{lookup(MessageKey::ScopeTenant, locale)} ":"</span>
                        <strong>{tenant_display.clone()}</strong>
                        {tenant_badge.map(|(cls, lbl)| view! {
                            <span class=cls>{lbl}</span>
                        })}
                    </button>
                </div>
                <div class="user-menu">
                    <UserPill initials=admin_initials name=admin_name/>
                    <a href="/login" class="btn btn-ghost btn-sm">
                        {lookup(MessageKey::ActionSignOut, locale)}
                    </a>
                </div>
            </header>

            <nav class="admin-sidebar" aria-label="Tenant administration">
                // RFC 180 (R2b): the mockup linked "/admin/t/{slug}/overview"
                // and "/admin/t/{slug}/users#invitations" — neither matches
                // what the worker registers (`/admin/t/:slug` with no
                // "/overview" suffix; invitations is its own page, not a
                // hash fragment on /users). Corrected to the real paths
                // rather than carried forward; roles/groups/oidc-clients/
                // audit below have no registered route at all yet (no
                // mismatch to correct — there is nothing to point them at).
                {sidebar_nav_item(format!("/admin/t/{s}"), lookup(MessageKey::TenantAdminOverview, locale), active == "overview", !caps.can_view_overview)}

                <h3 class="sidebar-group">{lookup(MessageKey::SidebarGroupMembers, locale)}</h3>
                {sidebar_nav_item(format!("/admin/t/{s}/users"), lookup(MessageKey::TenantAdminUsers, locale), active == "users", !caps.can_manage_users)}
                {sidebar_nav_item(format!("/admin/t/{s}/invitations"), lookup(MessageKey::TenantInvitePageTitle, locale), active == "invitations", !caps.can_manage_users)}
                {sidebar_nav_item(format!("/admin/t/{s}/deletion-requests"), lookup(MessageKey::TenantDeletionPageTitle, locale), active == "deletion-requests", !caps.can_manage_users)}

                <h3 class="sidebar-group">{lookup(MessageKey::SidebarGroupAccess, locale)}</h3>
                // No registered route yet for a tenant-scoped roles catalog
                // page -- placeholder link, dormant like the rest of this file.
                {sidebar_nav_item(format!("/admin/t/{s}/roles"), lookup(MessageKey::RolesCatalogTitle, locale), active == "roles", !caps.can_manage_roles)}
                {sidebar_nav_item(format!("/admin/t/{s}/organizations"), lookup(MessageKey::TenantAdminOrganizations, locale), active == "organizations", !caps.can_manage_orgs)}
                // No registered route yet for a top-level groups listing
                // (only "/groups/:gid/..." sub-actions exist) -- placeholder.
                {sidebar_nav_item(format!("/admin/t/{s}/groups"), lookup(MessageKey::TenantAdminGroups, locale), active == "groups", !caps.can_manage_groups)}

                <h3 class="sidebar-group">{lookup(MessageKey::SidebarGroupApplications, locale)}</h3>
                // No registered route yet for tenant-scoped OIDC clients -- placeholder.
                {sidebar_nav_item(format!("/admin/t/{s}/oidc-clients"), lookup(MessageKey::OidcClientsTitle, locale), active == "oidc-clients", !caps.can_manage_oidc_clients)}

                <h3 class="sidebar-group">{lookup(MessageKey::SidebarGroupSettings, locale)}</h3>
                {sidebar_nav_item(format!("/admin/t/{s}/subscription"), lookup(MessageKey::TenantAdminSubscription, locale), active == "subscription", !caps.can_manage_subscription)}
                // No registered route yet for a tenant-scoped audit page
                // (only the system-operator "/admin/console/audit" exists) -- placeholder.
                {sidebar_nav_item(format!("/admin/t/{s}/audit"), lookup(MessageKey::TenantAuditTitle, locale), active == "audit", false)}
            </nav>

            {is_auditor.then(|| view! {
                <div class="audit-viewer-banner" role="status">
                    <span class="badge badge-warning">"Read-only"</span>
                    " "
                    {lookup(MessageKey::AuditorRoleReadOnly, locale)}
                    " Only the Audit section is accessible."
                </div>
            })}
            <main id="main" class="admin-main">
                <div class="admin-content">{children()}</div>
            </main>

            <nav class="mobile-bottom-nav" aria-label="Section navigation">
                {let c_ov = ak2 == "overview";
                 let c_us = ak2 == "users";
                 let c_ro = ak2 == "roles";
                 let c_st = ak2 == "subscription" || ak2 == "audit";
                 view! {
                    <A href=format!("/admin/t/{tenant_slug}")
                        attr:class=move || if c_ov { "active" } else { "" }
                        attr:aria-current=move || if c_ov { "page" } else { "" }>
                        {lookup(MessageKey::TenantAdminOverview, locale)}
                    </A>
                    <A href=format!("/admin/t/{tenant_slug}/users")
                        attr:class=move || if c_us { "active" } else { "" }
                        attr:aria-current=move || if c_us { "page" } else { "" }>
                        {lookup(MessageKey::TenantAdminUsers, locale)}
                    </A>
                    <A href=format!("/admin/t/{tenant_slug}/roles")
                        attr:class=move || if c_ro { "active" } else { "" }
                        attr:aria-current=move || if c_ro { "page" } else { "" }>
                        {lookup(MessageKey::RolesCatalogTitle, locale)}
                    </A>
                    <A href=format!("/admin/t/{tenant_slug}/subscription")
                        attr:class=move || if c_st { "active" } else { "" }
                        attr:aria-current=move || if c_st { "page" } else { "" }>
                        "Settings"
                    </A>
                }}
            </nav>
        </div>
    }
}
