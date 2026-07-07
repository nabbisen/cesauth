//! Centralized URL path constants (RFC 102).
//!
//! This module is the single source of truth for all HTTP route paths
//! used by the cesauth worker. Worker route registration (`lib.rs`),
//! UI template form `action=` / link `href=` strings, and docs all
//! reference these constants so that a route rename is a one-line change.
//!
//! # Convention
//!
//! - Static paths: `pub const` `&str`
//! - Parameterized paths: `pub fn` returning `String` — the function
//!   interpolates parameters verbatim; the **template** is responsible
//!   for HTML-escaping the result before embedding it in an attribute.
//!   See `crates/ui/src/templates/security_center.rs::render_session_row_for`
//!   for the canonical pattern.
//! - Admin surfaces are under [`admin`], [`tenant_admin`], and [`tenancy_console`]
//! - End-user self-service is under [`me`]
//! - OIDC / OAuth2 is under [`oidc`]
//! - Auth / WebAuthn / magic-link flows are under [`auth`]
//!
//! # Drift correctness (RFC 108)
//!
//! Every const and fn in this module mirrors a route registered by
//! `crates/backend/src/lib.rs`. Renames of either side must update both
//! atomically; `scripts/drift-scan.sh` is the planned CI gate for that
//! (turned on once the admin template migration completes).
//!
//! Historical note: v0.66.0 (RFC 102) shipped four WebAuthn paths and
//! the `tenancy_console::tenant(slug)` family with values that never
//! matched the worker. v0.68.0 corrected WebAuthn; v0.69.0 corrected
//! `tenancy_console::*` (worker registers `/admin/tenancy/tenants/{tid}/...`,
//! not `/admin/tenancy/{slug}/...`).

/// System operator admin console (`/admin/console/*`) — bearer-token authenticated.
pub mod admin {
    // ── Overview / read-only pages ───────────────────────────────────────
    pub const OVERVIEW:           &str = "/admin/console";
    pub const COST:               &str = "/admin/console/cost";
    pub const SAFETY:             &str = "/admin/console/safety";
    pub const AUDIT:              &str = "/admin/console/audit";
    pub const AUDIT_EXPORT:       &str = "/admin/console/audit/export";
    pub const AUDIT_CHAIN:        &str = "/admin/console/audit/chain";
    pub const AUDIT_CHAIN_VERIFY: &str = "/admin/console/audit/chain/verify";
    pub const CONFIG:             &str = "/admin/console/config";
    pub const ALERTS:             &str = "/admin/console/alerts";
    pub const TOKENS:             &str = "/admin/console/tokens";
    pub const TOKENS_NEW:         &str = "/admin/console/tokens/new";
    pub const OPERATIONS:         &str = "/admin/console/operations";

    // ── Parameterised config / safety / token routes (RFC 018 preview-apply) ──
    /// `GET /admin/console/config/{bucket}/edit` — render the edit form.
    pub fn config_edit(bucket: &str) -> String {
        format!("/admin/console/config/{bucket}/edit")
    }
    /// `POST /admin/console/config/{bucket}/preview` — dry-run a config change.
    pub fn config_preview(bucket: &str) -> String {
        format!("/admin/console/config/{bucket}/preview")
    }
    /// `POST /admin/console/config/{bucket}/apply` — commit a previewed change.
    pub fn config_apply(bucket: &str) -> String {
        format!("/admin/console/config/{bucket}/apply")
    }
    /// `POST /admin/console/safety/{bucket}/verify` — operator-driven verify pass.
    pub fn safety_verify(bucket: &str) -> String {
        format!("/admin/console/safety/{bucket}/verify")
    }
    /// `POST /admin/console/tokens/{id}/disable` — disable an admin API token.
    pub fn token_disable(id: &str) -> String {
        format!("/admin/console/tokens/{id}/disable")
    }
    /// `POST /admin/console/thresholds/{name}` — update an alert threshold.
    pub fn threshold(name: &str) -> String {
        format!("/admin/console/thresholds/{name}")
    }

    // ── Cross-link to the tenancy console ────────────────────────────────
    pub const TENANCY:            &str = "/admin/tenancy";
}

/// Tenancy management console (`/admin/tenancy/*`).
///
/// **v0.69.0 catalog correction**: the v0.66.0 catalog claimed
/// `/admin/tenancy/{slug}/...` for per-tenant routes, but the worker
/// has always registered `/admin/tenancy/tenants/{tid}/...`. Same
/// pattern as the v0.68.0 WebAuthn correction.
pub mod tenancy_console {
    pub const ROOT:           &str = "/admin/tenancy";

    // ── Tenant catalogue ────────────────────────────────────────────────
    pub const TENANTS:        &str = "/admin/tenancy/tenants";
    pub const TENANTS_NEW:    &str = "/admin/tenancy/tenants/new";
    pub fn tenant(tid: &str) -> String { format!("/admin/tenancy/tenants/{tid}") }
    pub fn tenant_suspend(tid: &str) -> String { format!("/admin/tenancy/tenants/{tid}/suspend") }
    pub fn tenant_restore(tid: &str) -> String { format!("/admin/tenancy/tenants/{tid}/restore") }
    pub fn tenant_status(tid: &str) -> String { format!("/admin/tenancy/tenants/{tid}/status") }
    pub fn tenant_orgs_new(tid: &str) -> String { format!("/admin/tenancy/tenants/{tid}/organizations/new") }
    pub fn tenant_groups_new(tid: &str) -> String { format!("/admin/tenancy/tenants/{tid}/groups/new") }
    pub fn tenant_memberships_new(tid: &str) -> String { format!("/admin/tenancy/tenants/{tid}/memberships/new") }
    pub fn tenant_membership_delete(tid: &str, uid: &str) -> String {
        format!("/admin/tenancy/tenants/{tid}/memberships/{uid}/delete")
    }
    pub fn tenant_subscription_plan(tid: &str) -> String {
        format!("/admin/tenancy/tenants/{tid}/subscription/plan")
    }
    pub fn tenant_subscription_status(tid: &str) -> String {
        format!("/admin/tenancy/tenants/{tid}/subscription/status")
    }
    pub fn tenant_subscription_history(tid: &str) -> String {
        format!("/admin/tenancy/tenants/{tid}/subscription/history")
    }

    // ── Organization sub-tree ───────────────────────────────────────────
    pub fn organization(oid: &str) -> String {
        format!("/admin/tenancy/organizations/{oid}")
    }
    pub fn organization_status(oid: &str) -> String {
        format!("/admin/tenancy/organizations/{oid}/status")
    }
    pub fn organization_groups_new(oid: &str) -> String {
        format!("/admin/tenancy/organizations/{oid}/groups/new")
    }
    pub fn organization_memberships_new(oid: &str) -> String {
        format!("/admin/tenancy/organizations/{oid}/memberships/new")
    }
    pub fn organization_membership_delete(oid: &str, uid: &str) -> String {
        format!("/admin/tenancy/organizations/{oid}/memberships/{uid}/delete")
    }

    // ── Groups / role-assignments / user drill-ins ──────────────────────
    pub fn group_delete(gid: &str) -> String {
        format!("/admin/tenancy/groups/{gid}/delete")
    }
    pub fn group_memberships_new(gid: &str) -> String {
        format!("/admin/tenancy/groups/{gid}/memberships/new")
    }
    pub fn group_membership_delete(gid: &str, uid: &str) -> String {
        format!("/admin/tenancy/groups/{gid}/memberships/{uid}/delete")
    }
    pub fn role_assignment_delete(id: &str) -> String {
        format!("/admin/tenancy/role_assignments/{id}/delete")
    }
    pub fn user_role_assignments(uid: &str) -> String {
        format!("/admin/tenancy/users/{uid}/role_assignments")
    }
    pub fn user_role_assignments_new(uid: &str) -> String {
        format!("/admin/tenancy/users/{uid}/role_assignments/new")
    }
    pub fn user_tokens_new(uid: &str) -> String {
        format!("/admin/tenancy/users/{uid}/tokens/new")
    }
}

/// Tenant admin surface (`/admin/t/{slug}/*`).
pub mod tenant_admin {
    // ── Pages ────────────────────────────────────────────────────────────
    pub fn overview(slug: &str) -> String { format!("/admin/t/{slug}") }
    pub fn organizations(slug: &str) -> String { format!("/admin/t/{slug}/organizations") }
    pub fn organizations_new(slug: &str) -> String { format!("/admin/t/{slug}/organizations/new") }
    pub fn org_detail(slug: &str, oid: &str) -> String {
        format!("/admin/t/{slug}/organizations/{oid}")
    }
    pub fn org_status(slug: &str, oid: &str) -> String {
        format!("/admin/t/{slug}/organizations/{oid}/status")
    }
    pub fn org_groups_new(slug: &str, oid: &str) -> String {
        format!("/admin/t/{slug}/organizations/{oid}/groups/new")
    }
    pub fn org_memberships(slug: &str, oid: &str) -> String {
        format!("/admin/t/{slug}/organizations/{oid}/memberships")
    }
    pub fn org_memberships_new(slug: &str, oid: &str) -> String {
        format!("/admin/t/{slug}/organizations/{oid}/memberships/new")
    }
    pub fn org_membership_delete(slug: &str, oid: &str, uid: &str) -> String {
        format!("/admin/t/{slug}/organizations/{oid}/memberships/{uid}/delete")
    }
    pub fn users(slug: &str) -> String { format!("/admin/t/{slug}/users") }
    pub fn user_role_assignments(slug: &str, uid: &str) -> String {
        format!("/admin/t/{slug}/users/{uid}/role_assignments")
    }
    pub fn user_role_assignments_new(slug: &str, uid: &str) -> String {
        format!("/admin/t/{slug}/users/{uid}/role_assignments/new")
    }
    pub fn role_assignment_delete(slug: &str, id: &str) -> String {
        format!("/admin/t/{slug}/role_assignments/{id}/delete")
    }
    pub fn invitations(slug: &str) -> String { format!("/admin/t/{slug}/invitations") }
    pub fn invitation_revoke(slug: &str, id: &str) -> String {
        format!("/admin/t/{slug}/invitations/{id}/revoke")
    }
    pub fn deletion_requests(slug: &str) -> String {
        format!("/admin/t/{slug}/deletion-requests")
    }
    pub fn deletion_cancel(slug: &str, id: &str) -> String {
        format!("/admin/t/{slug}/deletion-requests/{id}/cancel")
    }
    pub fn deletion_execute(slug: &str, id: &str) -> String {
        format!("/admin/t/{slug}/deletion-requests/{id}/execute")
    }
    pub fn subscription(slug: &str) -> String { format!("/admin/t/{slug}/subscription") }

    // ── Groups + memberships ────────────────────────────────────────────
    pub fn group_delete(slug: &str, gid: &str) -> String {
        format!("/admin/t/{slug}/groups/{gid}/delete")
    }
    pub fn group_memberships(slug: &str, gid: &str) -> String {
        format!("/admin/t/{slug}/groups/{gid}/memberships")
    }
    pub fn group_memberships_new(slug: &str, gid: &str) -> String {
        format!("/admin/t/{slug}/groups/{gid}/memberships/new")
    }
    pub fn group_membership_delete(slug: &str, gid: &str, uid: &str) -> String {
        format!("/admin/t/{slug}/groups/{gid}/memberships/{uid}/delete")
    }

    // ── Tenant-level memberships (org-less) ─────────────────────────────
    pub fn memberships(slug: &str) -> String { format!("/admin/t/{slug}/memberships") }
    pub fn memberships_new(slug: &str) -> String { format!("/admin/t/{slug}/memberships/new") }
    pub fn membership_delete(slug: &str, uid: &str) -> String {
        format!("/admin/t/{slug}/memberships/{uid}/delete")
    }
}

/// End-user self-service surface (`/me/*`).
pub mod me {
    pub const SECURITY:       &str = "/me/security";
    pub const SESSIONS:       &str = "/me/security/sessions";
    pub const SESSIONS_REVOKE_OTHERS: &str = "/me/security/sessions/revoke-others";
    /// Catalog builder for the per-row revoke action.
    ///
    /// **Escape contract** (RFC 108): the returned string interpolates
    /// `id` verbatim. Templates **must** call `escape(...)` on the
    /// result before embedding it in an HTML attribute — see the
    /// pinned inline comment in `templates/security_center.rs::render_session_row_for`.
    pub fn session_revoke(id: &str) -> String {
        format!("/me/security/sessions/{id}/revoke")
    }
    pub const TOTP_ENROLL:         &str = "/me/security/totp/enroll";
    /// POST target for the TOTP enrollment confirm step (verifies the
    /// first 6-digit code and commits the authenticator).
    pub const TOTP_ENROLL_CONFIRM: &str = "/me/security/totp/enroll/confirm";
    pub const TOTP_VERIFY:         &str = "/me/security/totp/verify";
    pub const TOTP_DISABLE:        &str = "/me/security/totp/disable";
    pub const TOTP_RECOVER:        &str = "/me/security/totp/recover";
    pub const TOTP_RECOVER_CONFIRM:&str = "/me/security/totp/recover/confirm";
}

/// Authentication flows (login, magic-link, WebAuthn).
pub mod auth {
    pub const LOGIN:                 &str = "/login";
    pub const LOGOUT:                &str = "/logout";
    pub const MAGIC_LINK_REQUEST:    &str = "/magic-link/request";
    /// Magic-link verification URL emitted in the email.
    /// The handle is part of the URL path.
    pub fn magic_link_verify(handle: &str) -> String {
        format!("/magic-link/verify/{handle}")
    }
    /// Form action for the OTP-entry magic-link form (no handle in URL —
    /// the handle is carried inside the form body).
    pub const MAGIC_LINK_VERIFY_FORM: &str = "/magic-link/verify";

    // ── WebAuthn ─────────────────────────────────────────────────────────
    /// `/webauthn/register/start` — registration ceremony begin.
    ///
    /// Note: these paths are NOT under `/me/` even though they require
    /// authentication. The v0.66.0 catalog (RFC 102) shipped wrong
    /// values (`/me/webauthn/register*` and `/auth/webauthn/*`); v0.68.0
    /// corrected them to match what the worker has always served.
    pub const PASSKEY_REGISTER_START:  &str = "/webauthn/register/start";
    pub const PASSKEY_REGISTER_FINISH: &str = "/webauthn/register/finish";
    /// `/webauthn/authenticate/start` — invoked from inline JS on the
    /// login page. See `templates/login.rs::login_page_for`.
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
