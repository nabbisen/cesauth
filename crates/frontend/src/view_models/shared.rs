//! Shared view-model primitives used across all screen families.
//!
//! # FormContract (RFC 029)
//!
//! Every mutating form in the UI is driven by a [`FormContract`] resolved
//! on the server. The contract carries every value the form needs to render
//! correctly: the HTTP action, CSRF token, Turnstile site key, field
//! configuration, and the route to redirect to after success. The UI never
//! builds these values itself.
//!
//! # TenantCapabilitiesView / OperatorCapabilitiesView (RFC 030)
//!
//! Authorization is expressed as flat struct-of-bools built by the server
//! after the permission check, not as a role enum. Components read individual
//! capability bits; they do not make authorization decisions themselves.

use serde::{Deserialize, Serialize};

// ── FormContract ─────────────────────────────────────────────────────────────

/// HTTP method used for a mutating form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FormMethod {
    Post,
    Delete,
}

/// Encoding used for a mutating form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FormEncoding {
    /// `application/x-www-form-urlencoded` (default for HTML forms).
    UrlEncoded,
    /// `multipart/form-data` (used when file uploads are present).
    Multipart,
}

impl Default for FormEncoding {
    fn default() -> Self {
        FormEncoding::UrlEncoded
    }
}

/// A hidden field injected into a mutating form.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HiddenField {
    /// The `name` attribute value.
    pub name: String,
    /// The `value` attribute value.
    pub value: String,
}

/// Outcome configuration: where to redirect on success.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FormOutcome {
    /// URL to redirect to after a successful submission.
    pub success_redirect: String,
    /// i18n key for the retriable error message shown inline.
    pub retriable_error_key: Option<String>,
    /// URL to redirect to for terminal (non-retriable) errors.
    pub terminal_error_route: Option<String>,
}

/// Contract for a destructive action that requires typed confirmation.
/// The user must type `required_phrase` exactly before the form submits.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DestructiveConfirmContract {
    /// The phrase the user must type verbatim.
    pub required_phrase: String,
    /// i18n key for the label shown above the confirmation input.
    pub prompt_key: String,
}

/// The full contract for a mutating HTML form.
///
/// Resolved by the server before the page is rendered; the UI renders
/// the form mechanically from this struct.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FormContract {
    /// HTML `action` attribute — the URL this form submits to.
    pub action: String,
    /// HTTP method.
    pub method: FormMethod,
    /// Content encoding.
    #[serde(default)]
    pub encoding: FormEncoding,
    /// CSRF token field (name + value). Always present for mutating forms.
    pub csrf: HiddenField,
    /// Cloudflare Turnstile widget site key. `None` means no challenge.
    pub turnstile_site_key: Option<String>,
    /// Extra hidden fields (e.g. `handle`, `invitation_token`).
    #[serde(default)]
    pub hidden_fields: Vec<HiddenField>,
    /// Post-submission outcome.
    pub outcome: FormOutcome,
    /// Audit event name written to the audit log on success.
    /// `None` means this form does not generate an audit event directly;
    /// the "recorded in audit log" copy MUST NOT render when this is `None`.
    pub audit_event: Option<String>,
    /// If present, the form requires a typed confirmation phrase.
    pub destructive_confirm: Option<DestructiveConfirmContract>,
}

impl FormContract {
    /// Construct a minimal contract for use in workbench adapters.
    /// All security-sensitive fields are filled with obvious fake values.
    pub fn workbench_stub(action: impl Into<String>, audit_event: impl Into<String>) -> Self {
        FormContract {
            action: action.into(),
            method: FormMethod::Post,
            encoding: FormEncoding::UrlEncoded,
            csrf: HiddenField {
                name: "csrf_token".into(),
                value: "WORKBENCH-CSRF-STUB".into(),
            },
            turnstile_site_key: None,
            hidden_fields: vec![],
            outcome: FormOutcome {
                success_redirect: "/".into(),
                retriable_error_key: None,
                terminal_error_route: None,
            },
            audit_event: Some(audit_event.into()),
            destructive_confirm: None,
        }
    }
}

// ── TenantCapabilitiesView (RFC 030) ─────────────────────────────────────────

/// Capability set for the authenticated user within a specific tenant.
///
/// Built by the server after calling the permission-check service. Components
/// consume individual bits — they do not re-derive capabilities from a role.
///
/// Invariant: a user with `can_read_audit` true but all `can_manage_*` false
/// is operating in audit-viewer (read-only) mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantCapabilitiesView {
    pub can_view_overview: bool,
    pub can_manage_users: bool,
    pub can_manage_roles: bool,
    pub can_manage_orgs: bool,
    pub can_manage_groups: bool,
    pub can_manage_oidc_clients: bool,
    pub can_manage_subscription: bool,
    pub can_read_audit: bool,
    pub can_invite_users: bool,
    pub can_revoke_sessions: bool,
    pub can_process_deletion_requests: bool,
}

impl TenantCapabilitiesView {
    /// Full tenant-admin capability set (all permissions granted).
    ///
    /// Also available as a `const` for use in `static` arrays (e.g. knob
    /// option tables in workbench route components that call `make_knob`).
    pub const TENANT_ADMIN: TenantCapabilitiesView = TenantCapabilitiesView {
        can_view_overview: true,
        can_manage_users: true,
        can_manage_roles: true,
        can_manage_orgs: true,
        can_manage_groups: true,
        can_manage_oidc_clients: true,
        can_manage_subscription: true,
        can_read_audit: true,
        can_invite_users: true,
        can_revoke_sessions: true,
        can_process_deletion_requests: true,
    };

    /// Audit-viewer capability set: read-only access to the audit log only.
    pub const AUDIT_VIEWER: TenantCapabilitiesView = TenantCapabilitiesView {
        can_view_overview: false,
        can_manage_users: false,
        can_manage_roles: false,
        can_manage_orgs: false,
        can_manage_groups: false,
        can_manage_oidc_clients: false,
        can_manage_subscription: false,
        can_read_audit: true,
        can_invite_users: false,
        can_revoke_sessions: false,
        can_process_deletion_requests: false,
    };

    /// Full tenant-admin capability set (function form for ergonomics).
    pub fn tenant_admin() -> Self {
        Self::TENANT_ADMIN
    }

    /// Audit-viewer capability set (function form for ergonomics).
    pub fn audit_viewer() -> Self {
        Self::AUDIT_VIEWER
    }
}

// ── OperatorCapabilitiesView (RFC 030) ───────────────────────────────────────

/// Capability set for an authenticated platform operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorCapabilitiesView {
    pub can_view_dashboard: bool,
    pub can_manage_tenants: bool,
    pub can_view_cross_tenant_users: bool,
    pub can_read_audit: bool,
    pub can_investigate: bool,
    pub can_run_operations: bool,
    pub can_manage_tokens: bool,
    pub can_manage_config: bool,
    pub can_manage_safety: bool,
}

impl OperatorCapabilitiesView {
    /// Full operator capability set (all permissions granted).
    pub fn operator() -> Self {
        OperatorCapabilitiesView {
            can_view_dashboard: true,
            can_manage_tenants: true,
            can_view_cross_tenant_users: true,
            can_read_audit: true,
            can_investigate: true,
            can_run_operations: true,
            can_manage_tokens: true,
            can_manage_config: true,
            can_manage_safety: true,
        }
    }
}
