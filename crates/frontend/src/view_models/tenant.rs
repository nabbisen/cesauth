//! Tenant-admin view models and mutation contracts (RFC 032, RFC 033).
//!
//! Each mutating operation in the tenant-admin surface is expressed as a
//! typed [`FormContract`]. The contract is resolved by the server before
//! the page renders; the UI never constructs action URLs or CSRF tokens.
//!
//! # Audit copy rule (RFC 032 §critical invariant)
//!
//! The "this action was recorded in the audit log" copy MUST render only
//! when `form.audit_event` is `Some(_)`. Components must not render this
//! copy unconditionally.

use super::shared::{DestructiveConfirmContract, FormContract};
use serde::{Deserialize, Serialize};

// ── Invitation mutations ──────────────────────────────────────────────────────

/// Contract for inviting a user to a tenant.
/// Action: `POST /admin/t/:slug/users/invite`
/// Permission: `TenantCapabilitiesView::can_invite_users`
/// Audit event: `InvitationSent`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteUserContract {
    pub form: FormContract,
}

/// Contract for revoking a pending invitation.
/// Action: `DELETE /admin/t/:slug/invitations/:id`
/// Permission: `can_invite_users`
/// Audit event: `InvitationRevoked`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeInvitationContract {
    pub invitation_id: String,
    pub invitee_email: String,
    pub form: FormContract,
}

// ── Role mutations ────────────────────────────────────────────────────────────

/// Contract for granting a role to a user.
/// Action: `POST /admin/t/:slug/roles/grant`
/// Permission: `can_manage_roles`
/// Audit event: `RoleAssigned`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrantRoleContract {
    pub form: FormContract,
}

/// Contract for revoking a role assignment.
/// Action: `DELETE /admin/t/:slug/roles/assignments/:id`
/// Permission: `can_manage_roles`
/// Audit event: `RoleRevoked`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeRoleContract {
    pub assignment_id: String,
    pub form: FormContract,
    pub confirm: DestructiveConfirmContract,
}

// ── Session mutations ─────────────────────────────────────────────────────────

/// Contract for revoking a single session (admin view).
/// Action: `DELETE /admin/t/:slug/users/:user/sessions/:session_id`
/// Permission: `can_revoke_sessions`
/// Audit event: `SessionRevoked`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeSessionContract {
    pub session_id: String,
    pub form: FormContract,
}

/// Contract for batch-revoking all sessions of a user.
/// Action: `DELETE /admin/t/:slug/users/:user/sessions`
/// Permission: `can_revoke_sessions`
/// Audit event: `AllSessionsRevoked`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeAllSessionsContract {
    pub target_user_email: String,
    pub form: FormContract,
    pub confirm: DestructiveConfirmContract,
}

// ── Tenant lifecycle mutations ────────────────────────────────────────────────

/// Contract for suspending a tenant.
/// Action: `POST /admin/t/:slug/suspend`
/// Permission: `can_manage_subscription`
/// Audit event: `TenantSuspended`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SuspendTenantContract {
    pub tenant_display: String,
    pub form: FormContract,
    pub confirm: DestructiveConfirmContract,
}

/// Contract for restoring a suspended tenant.
/// Action: `POST /admin/t/:slug/restore`
/// Permission: `can_manage_subscription`
/// Audit event: `TenantRestored`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RestoreTenantContract {
    pub tenant_display: String,
    pub form: FormContract,
}

// ── Account deletion mutations ────────────────────────────────────────────────

/// Contract for requesting account deletion (user self-service).
/// Action: `POST /me/delete`
/// Audit event: `DeletionRequested`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestDeletionContract {
    pub form: FormContract,
    pub confirm: DestructiveConfirmContract,
}

/// Contract for processing (approving or rejecting) a deletion request.
/// Action: `POST /admin/t/:slug/deletion-requests/:id/process`
/// Permission: `can_process_deletion_requests`
/// Audit event: `DeletionApproved` or `DeletionRejected`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessDeletionContract {
    pub request_id: String,
    pub target_email: String,
    pub approve_form: FormContract,
    pub reject_form: FormContract,
}

// ── OIDC client mutations (RFC 033) ───────────────────────────────────────────

/// View model for a single OIDC client entry in the list.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcClientSummary {
    pub client_id: String,
    pub display_name: String,
    pub is_active: bool,
    pub redirect_uri_count: usize,
}

/// Contract for creating a new OIDC client.
/// Action: `POST /admin/t/:slug/oidc-clients`
/// Permission: `can_manage_oidc_clients`
/// Audit event: `OidcClientCreated`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateOidcClientContract {
    pub form: FormContract,
}

/// One-time secret reveal contract (RFC 033 §secret reveal).
///
/// The client secret is revealed exactly once via a server-issued reveal token.
/// After the first reveal the endpoint returns 410 Gone. The UI must display
/// a prominent copy-warning before the user can see the secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretRevealContract {
    /// Server-issued single-use token for the reveal endpoint.
    pub reveal_token: String,
    /// Endpoint to `GET` with the reveal token to receive the secret.
    pub reveal_endpoint: String,
    /// i18n key for the "copy now, this will not be shown again" warning.
    pub copy_warning_key: String,
    /// When the reveal token expires (ISO-8601).
    pub expires_at: String,
}

/// Contract for rotating an OIDC client secret.
/// Action: `POST /admin/t/:slug/oidc-clients/:client/rotate`
/// Permission: `can_manage_oidc_clients`
/// Audit event: `OidcClientSecretRotated`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotateSecretContract {
    pub client_display_name: String,
    pub form: FormContract,
    pub confirm: DestructiveConfirmContract,
    /// Present after a successful rotation; `None` before the rotation.
    pub new_secret_reveal: Option<SecretRevealContract>,
}

/// Contract for disabling an OIDC client.
/// Action: `POST /admin/t/:slug/oidc-clients/:client/disable`
/// Permission: `can_manage_oidc_clients`
/// Audit event: `OidcClientDisabled`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisableOidcClientContract {
    pub client_display_name: String,
    pub form: FormContract,
    pub confirm: DestructiveConfirmContract,
}

/// Contract for enabling a disabled OIDC client.
/// Action: `POST /admin/t/:slug/oidc-clients/:client/enable`
/// Permission: `can_manage_oidc_clients`
/// Audit event: `OidcClientEnabled`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnableOidcClientContract {
    pub form: FormContract,
}

/// Contract for deleting an OIDC client.
/// Action: `DELETE /admin/t/:slug/oidc-clients/:client`
/// Permission: `can_manage_oidc_clients`
/// Audit event: `OidcClientDeleted`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeleteOidcClientContract {
    pub client_display_name: String,
    pub form: FormContract,
    pub confirm: DestructiveConfirmContract,
}
