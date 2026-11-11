//! OperatorShell — grouped operator sidebar (RFC 021/018, RFC 028).
//!
//! Imported from the mockup repository's `src/components/
//! shells/operator_shell.rs` at pin `df3d9d0` (RFC 180, R2b).
//!
//! RFC 028: routes split into /admin/tenancy/* (tenants, users) and
//!          /admin/console/* (dashboard, audit, investigate, operations,
//!          tokens, config).
//!
//! **Locale policy — ADR-013, amended by RFC 185 (2026-11-11).** This
//! comment previously cited `rfcs/done/034-introspect-handler-wiring.md`
//! for "operator console is Japanese-only"; that RFC contains no
//! mention of locale, Japanese, or ADR-013 at all — RFC 185 §2 found
//! the wrong citation by checking, which nobody had before. ADR-013's
//! `## v0.36.0 migration scope` → Out of scope list
//! is the actual source, and as of RFC 185 the Japanese-only state is
//! a **starting point for conversion, not a permanent policy**: the
//! deferral's own trigger ("if/when demand surfaces") has fired.
//! `const LOCALE: Locale = Locale::Ja` below is unchanged by this —
//! RFC 185 §5.2/D3 baselines this file's literals rather than
//! converting them, since `OperatorShell` has zero mount sites (RFC
//! 179, extended by RFC 185 §3/A7) and converting code nobody renders
//! would be done blind. The mockup enforced the same JA pin with a
//! reactive `LocaleContext::provide_fixed(Locale::Ja)`; RFC 180 §5
//! bars building any reactive locale context at all, fixed or not,
//! so this shell instead just calls `lookup(_, Locale::Ja)` directly
//! — same JA-only result, no context, no signal.
//!
//! **No mock data**: the mockup hardcoded `UserPill initials="PO"
//! name="platform-op@example.test"`. RFC 131 §5 bars committing mock
//! data at any intermediate step, so both are now required props a
//! future caller (R3) must supply.

use crate::components::nav::topbar::{BrandMark, UserPill};
use cesauth_core::i18n::{lookup, Locale, MessageKey};
use leptos::prelude::*;

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Environment {
    Production,
    Staging,
    Local,
}
impl Environment {
    fn class(self) -> &'static str {
        match self {
            Environment::Production => "env-badge production",
            Environment::Staging => "env-badge",
            Environment::Local => "env-badge local",
        }
    }
}

#[component]
pub fn OperatorShell(
    #[prop(into)] active: String,
    #[prop(default = Environment::Production)] environment: Environment,
    #[prop(into)] operator_initials: String,
    #[prop(into)] operator_name: String,
    children: Children,
) -> impl IntoView {
    const LOCALE: Locale = Locale::Ja;

    let a = active.clone();
    let is_active = move |k: &str| {
        if k == a {
            "sidebar-link active"
        } else {
            "sidebar-link"
        }
    };
    let env_label = match environment {
        Environment::Production => lookup(MessageKey::EnvironmentProduction, LOCALE),
        Environment::Staging => lookup(MessageKey::EnvironmentStaging, LOCALE),
        Environment::Local => lookup(MessageKey::EnvironmentLocal, LOCALE),
    };
    view! {
        <div class="operator-shell">
            <header class="operator-topbar">
                <div class="row">
                    <BrandMark href="/"/>
                    <span class="operator-badge">{lookup(MessageKey::AdminScopeSystem, LOCALE)}</span>
                    <span class=environment.class()>{env_label}</span>
                </div>
                <div class="user-menu">
                    // No LocaleToggle here (RFC 180 §5 bars the mockup's live
                    // switcher) — the console stays pinned to Locale::Ja per
                    // ADR-013 until an RFC 185 §5.3 conversion flips it.
                    <UserPill initials=operator_initials name=operator_name/>
                    <a href="/login" class="btn btn-ghost btn-sm">
                        {lookup(MessageKey::ActionSignOut, LOCALE)}
                    </a>
                </div>
            </header>
            <nav class="admin-sidebar" aria-label="Operator console">
                // RFC 180 (R2b): the mockup linked "/admin/console/dashboard",
                // which the worker never registered -- the dashboard IS
                // "/admin/console" itself. Corrected rather than carried
                // forward.
                <a href="/admin/console" class=is_active("dashboard")>
                    {lookup(MessageKey::OperatorDashboardTitle, LOCALE)}
                </a>

                <h3 class="sidebar-group">"Tenants"</h3>
                <a href="/admin/tenancy/tenants" class=is_active("tenants")>"All tenants"</a>
                // No registered route yet for a top-level cross-tenant users
                // listing (only "/admin/tenancy/users/:uid/role_assignments"
                // exists) -- placeholder, dormant like the rest of this file.
                <a href="/admin/tenancy/users"   class=is_active("users")>"Cross-tenant users"</a>

                <h3 class="sidebar-group">"Investigate"</h3>
                <a href="/admin/console/audit"       class=is_active("audit")>{lookup(MessageKey::AuditViewerPageTitle, LOCALE)}</a>
                // No registered route yet for "/admin/console/investigate" -- placeholder.
                <a href="/admin/console/investigate" class=is_active("investigate")>
                    {lookup(MessageKey::InvestigateTitle, LOCALE)}
                </a>

                <h3 class="sidebar-group">"Operate"</h3>
                <a href="/admin/console/operations" class=is_active("operations")>
                    {lookup(MessageKey::OperationsTitle, LOCALE)}
                </a>
                <a href="/admin/console/safety" class=is_active("safety")>
                    "Safety"
                </a>

                <h3 class="sidebar-group">"Platform"</h3>
                <a href="/admin/console/tokens" class=is_active("tokens")>
                    {lookup(MessageKey::TokensTitle, LOCALE)}
                </a>
                <a href="/admin/console/config" class=is_active("config")>
                    {lookup(MessageKey::ConfigTitle, LOCALE)}
                </a>
            </nav>
            <main id="main" class="operator-main">
                <div class="operator-content">{children()}</div>
            </main>
        </div>
    }
}
