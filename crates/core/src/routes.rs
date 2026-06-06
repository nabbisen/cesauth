//! Centralized URL path constants (RFC 102).
//!
//! This module is the single source of truth for all HTTP route paths
//! used by the cesauth worker. Worker route registration (`lib.rs`),
//! UI template form `action=` / link `href=` strings, and docs all
//! reference these constants so that a route rename is a one-line change.
//!
//! # Convention
//! - Static paths: `pub const` `&str`
//! - Parameterized paths: `pub fn` returning `String`
//! - Admin surfaces are under [`admin`], [`tenant_admin`], and [`tenancy_console`]
//! - End-user self-service is under [`me`]
//! - OIDC / OAuth2 is under [`oidc`]

/// System operator admin console — bearer-token authenticated.
pub mod admin {
    // ── Overview ──────────────────────────────────────────────────────────
    pub const OVERVIEW:       &str = "/admin/console";
    pub const COST:           &str = "/admin/console/cost";
    pub const SAFETY:         &str = "/admin/console/safety";
    pub const AUDIT:          &str = "/admin/console/audit";
    pub const AUDIT_EXPORT:   &str = "/admin/console/audit/export";
    pub const AUDIT_CHAIN:    &str = "/admin/console/audit/chain";
    pub const AUDIT_CHAIN_VERIFY: &str = "/admin/console/audit/chain/verify";
    pub const CONFIG:         &str = "/admin/console/config";
    pub const CONFIG_EDIT:    &str = "/admin/console/config/edit";
    pub const ALERTS:         &str = "/admin/console/alerts";
    pub const TOKENS:         &str = "/admin/console/tokens";
    pub const TOKENS_NEW:     &str = "/admin/console/tokens/new";
    pub const OPERATIONS:     &str = "/admin/console/operations";
    // ── Tenancy console redirect ──────────────────────────────────────────
    pub const TENANCY:        &str = "/admin/tenancy";
}

/// Tenancy management console (`/admin/tenancy/*`).
pub mod tenancy_console {
    pub const ROOT:           &str = "/admin/tenancy";
    pub fn tenant(slug: &str) -> String { format!("/admin/tenancy/{slug}") }
    pub fn tenant_orgs(slug: &str) -> String { format!("/admin/tenancy/{slug}/organizations") }
    pub fn tenant_groups(slug: &str) -> String { format!("/admin/tenancy/{slug}/groups") }
    pub fn tenant_users(slug: &str) -> String { format!("/admin/tenancy/{slug}/users") }
    pub fn tenant_subscription(slug: &str) -> String { format!("/admin/tenancy/{slug}/subscription") }
}

/// Tenant admin surface (`/admin/t/<slug>/*`).
pub mod tenant_admin {
    pub fn overview(slug: &str) -> String { format!("/admin/t/{slug}") }
    pub fn organizations(slug: &str) -> String { format!("/admin/t/{slug}/organizations") }
    pub fn org_detail(slug: &str, org_id: &str) -> String { format!("/admin/t/{slug}/organizations/{org_id}") }
    pub fn groups(slug: &str) -> String { format!("/admin/t/{slug}/groups") }
    pub fn users(slug: &str) -> String { format!("/admin/t/{slug}/users") }
    pub fn invitations(slug: &str) -> String { format!("/admin/t/{slug}/invitations") }
    pub fn invitation_revoke(slug: &str, id: &str) -> String { format!("/admin/t/{slug}/invitations/{id}/revoke") }
    pub fn deletion_requests(slug: &str) -> String { format!("/admin/t/{slug}/deletion-requests") }
    pub fn deletion_cancel(slug: &str, id: &str) -> String { format!("/admin/t/{slug}/deletion-requests/{id}/cancel") }
    pub fn deletion_execute(slug: &str, id: &str) -> String { format!("/admin/t/{slug}/deletion-requests/{id}/execute") }
    pub fn role_assignments(slug: &str) -> String { format!("/admin/t/{slug}/role-assignments") }
    pub fn subscription(slug: &str) -> String { format!("/admin/t/{slug}/subscription") }
}

/// End-user self-service surface (`/me/*`).
pub mod me {
    pub const SECURITY:       &str = "/me/security";
    pub const SESSIONS:       &str = "/me/security/sessions";
    pub const SESSIONS_REVOKE_OTHERS: &str = "/me/security/sessions/revoke-others";
    pub fn session_revoke(id: &str) -> String { format!("/me/security/sessions/{id}/revoke") }
    pub const TOTP_ENROLL:    &str = "/me/security/totp/enroll";
    /// POST target for the TOTP enrollment confirm step (verifies the
    /// first 6-digit code and commits the authenticator).
    pub const TOTP_ENROLL_CONFIRM: &str = "/me/security/totp/enroll/confirm";
    pub const TOTP_VERIFY:    &str = "/me/security/totp/verify";
    pub const TOTP_DISABLE:   &str = "/me/security/totp/disable";
    pub const TOTP_RECOVER:   &str = "/me/security/totp/recover";
    pub const TOTP_RECOVER_CONFIRM: &str = "/me/security/totp/recover/confirm";
}

/// Authentication flows (login, magic-link, WebAuthn).
pub mod auth {
    pub const LOGIN:                 &str = "/login";
    pub const LOGOUT:                &str = "/logout";
    pub const MAGIC_LINK_REQUEST:    &str = "/magic-link/request";
    pub fn magic_link_verify(handle: &str) -> String { format!("/magic-link/verify/{handle}") }
    /// Form action for the OTP-entry magic-link form (no handle in URL —
    /// the handle is carried inside the form body).
    pub const MAGIC_LINK_VERIFY_FORM: &str = "/magic-link/verify";
    /// WebAuthn registration ceremony (`/webauthn/register/*`).
    ///
    /// Note: these paths are NOT under `/me/` even though they're
    /// authenticated. v0.67.0 audit (RFC 108 prep) found the original
    /// catalog values `/me/webauthn/register*` were aspirational —
    /// the worker has always registered `/webauthn/register/*` and
    /// `/webauthn/authenticate/*`.
    pub const PASSKEY_REGISTER_START:  &str = "/webauthn/register/start";
    pub const PASSKEY_REGISTER_FINISH: &str = "/webauthn/register/finish";
    /// WebAuthn authentication ceremony — invoked from inline JS on
    /// the login page. See `templates/login.rs::login_page_for`.
    pub const PASSKEY_AUTH_START:    &str = "/webauthn/authenticate/start";
    pub const PASSKEY_AUTH_FINISH:   &str = "/webauthn/authenticate/finish";
}

/// OIDC / OAuth2 endpoints.
pub mod oidc {
    pub const AUTHORIZE:        &str = "/oidc/authorize";
    pub const TOKEN:            &str = "/oidc/token";
    pub const INTROSPECT:       &str = "/oidc/introspect";
    pub const USERINFO:         &str = "/oidc/userinfo";
    pub const JWKS:             &str = "/.well-known/jwks.json";
    pub const DISCOVERY:        &str = "/.well-known/openid-configuration";
    pub const END_SESSION:      &str = "/oidc/end-session";
}
