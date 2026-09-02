//! Leptos application root with client-side router.
//!
//! The `App` component is the single mount point for the Leptos CSR
//! bundle.  It owns the `<Router>` and declares every client-side
//! route.  Routes are added here as screens are migrated from the
//! old string-template layer.
//!
//! ## Route ownership
//!
//! `leptos_router` handles URL parsing and renders the matching
//! `<Route>` component.  The backend still owns the initial HTTP
//! response (returning the HTML shell); the router takes over all
//! subsequent navigation.
//!
//! ## Adding a new screen
//!
//! 1. Create `crates/frontend/src/pages/<screen>.rs`.
//! 2. Add `pub mod <screen>;` to `crates/frontend/src/pages/mod.rs`.
//! 3. Add a `<Route path=path!(…) view=…/>` entry below. `leptos_router`
//!    0.8 requires the `path!()` macro, not a bare `&str` — a bare string
//!    literal fails to compile (RFC 127).
//! 4. Add/update the corresponding backend route to return the Leptos
//!    HTML shell instead of the old string template.

use leptos::prelude::*;
use leptos_router::components::{Router, Routes, Route};
use leptos_router::path;

use crate::pages::login::Login;
use crate::pages::operator::{
    console::{
        ConsoleAlerts, ConsoleAudit, ConsoleAuditChain, ConsoleConfig,
        ConsoleCost, ConsoleOperations, ConsoleOverview, ConsoleSafety,
        ConsoleTokens,
    },
    tenancy::{TenancyOverview, TenancyTenantDetail, TenancyTenants},
};
use crate::pages::security_center::SecurityCenter;
use crate::pages::sessions::Sessions;
use crate::pages::tenant_admin::{
    forms::{AddTenantMember, NewOrganization},
    invitations::TenantInvitations,
    organizations::TenantOrganizations,
    overview::TenantOverview,
    subscription::TenantSubscription,
    users::TenantUsers,
};
use crate::pages::totp::{TotpDisable, TotpEnroll, TotpVerify};

// ─── Root component ──────────────────────────────────────────────────────────

/// Root Leptos component — mounted by `leptos_start()` in `lib.rs`.
#[component]
pub fn App() -> impl IntoView {
    view! {
        <Router>
            <Routes fallback=|| view! { <NotFound/> }>
                // ── Migrated screens (Phase C) ───────────────────────
                <Route path=path!("/")                         view=Login />
                <Route path=path!("/login")                    view=Login />
                <Route path=path!("/me/security")              view=SecurityCenter />
                <Route path=path!("/me/security/sessions")     view=Sessions />
                <Route path=path!("/me/security/totp/enroll")  view=TotpEnroll />
                <Route path=path!("/me/security/totp/verify")  view=TotpVerify />
                <Route path=path!("/me/security/totp/disable") view=TotpDisable />

                // ── Tenant admin ──────────────────────────────────
                <Route path=path!("/admin/t/:slug")                   view=TenantOverview />
                <Route path=path!("/admin/t/:slug/users")             view=TenantUsers />
                <Route path=path!("/admin/t/:slug/organizations")     view=TenantOrganizations />
                <Route path=path!("/admin/t/:slug/subscription")      view=TenantSubscription />
                <Route path=path!("/admin/t/:slug/invitations")       view=TenantInvitations />
                <Route path=path!("/admin/t/:slug/organizations/new") view=NewOrganization />
                <Route path=path!("/admin/t/:slug/memberships/new")   view=AddTenantMember />
                // ── System operator console ───────────────────────
                <Route path=path!("/admin/console")             view=ConsoleOverview />
                <Route path=path!("/admin/console/operations")  view=ConsoleOperations />
                <Route path=path!("/admin/console/audit")       view=ConsoleAudit />
                <Route path=path!("/admin/console/audit/chain") view=ConsoleAuditChain />
                <Route path=path!("/admin/console/safety")      view=ConsoleSafety />
                <Route path=path!("/admin/console/cost")        view=ConsoleCost />
                <Route path=path!("/admin/console/tokens")      view=ConsoleTokens />
                <Route path=path!("/admin/console/alerts")      view=ConsoleAlerts />
                <Route path=path!("/admin/console/config")      view=ConsoleConfig />
                // ── Tenancy console ───────────────────────────────
                <Route path=path!("/admin/tenancy")              view=TenancyOverview />
                <Route path=path!("/admin/tenancy/tenants")      view=TenancyTenants />
                <Route path=path!("/admin/tenancy/tenants/:tid") view=TenancyTenantDetail />
            </Routes>
        </Router>
    }
}

// ─── 404 fallback ────────────────────────────────────────────────────────────

#[component]
fn NotFound() -> impl IntoView {
    view! {
        <main>
            <h1>"Page not found"</h1>
            <p><a href="/">"Return to sign-in"</a></p>
        </main>
    }
}
