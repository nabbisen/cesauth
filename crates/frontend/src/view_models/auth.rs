//! Authentication form view models and contracts (RFC 031).
//!
//! Every auth screen accepts one of these view models as its primary prop.
//! The form contracts specify the exact HTTP plumbing needed for production;
//! the workbench adapter fills these with fake values.

use super::shared::FormContract;
use serde::{Deserialize, Serialize};

// ── AUTH-01: Sign-in (Passkey / Magic-link entry) ────────────────────────────

/// View model for the sign-in entry screen (AUTH-01 → `/login`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignInView {
    /// Opaque OIDC `state` parameter — carried through from the auth request.
    /// None when the user arrived directly (no OIDC flow in progress).
    pub oidc_state: Option<String>,
    /// Magic-link request form contract.
    pub magic_link_form: FormContract,
}

// ── AUTH-02: Magic-link request ───────────────────────────────────────────────

/// View model for the magic-link request screen (AUTH-02 → `/magic-link/request`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MagicLinkRequestView {
    pub form: FormContract,
    /// Opaque continuation handle — injected as a hidden field so the server
    /// can park the OIDC request while the magic-link flow runs.
    pub handle: Option<String>,
}

// ── AUTH-03: Magic-link verify ────────────────────────────────────────────────

/// View model for the magic-link verify screen (AUTH-03 → `/magic-link/verify`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MagicLinkVerifyView {
    /// Email address the code was sent to (for display only).
    pub destination_email: String,
    /// Form contract for submitting the 6-digit code.
    pub form: FormContract,
}

// ── AUTH-04: TOTP verify ─────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TotpMode {
    /// Normal TOTP 6-digit code entry.
    Totp,
    /// Recovery-code entry (8-character alphanumeric).
    Recovery,
}

/// View model for the TOTP verify screen (AUTH-04 → `/totp/verify`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TotpVerifyView {
    pub mode: TotpMode,
    pub form: FormContract,
    /// Form contract for switching to recovery mode.
    pub recovery_form: FormContract,
}

// ── AUTH-05: Accept invitation ────────────────────────────────────────────────

/// View model for the invitation-accept screen (AUTH-05 → `/accept-invite`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvitationAcceptView {
    /// Tenant display name shown in the heading.
    pub tenant_display: String,
    /// Inviter display name shown in the body.
    pub inviter_display: String,
    /// Invitation ID — injected as a hidden field.
    pub invitation_id: String,
    /// Accept form contract.
    pub form: FormContract,
}

// ── AUTH-06: Terminal error ───────────────────────────────────────────────────

/// View model for the terminal error screen (AUTH-06 → `/auth/error`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TerminalErrorView {
    /// i18n key for the error title.
    pub title_key: String,
    /// i18n key for the error body.
    pub body_key: String,
    /// Optional restart URL (e.g. return to the OIDC client).
    pub restart_url: Option<String>,
}

// ── Logout contract (all shells) ─────────────────────────────────────────────

/// Contract for the logout action. Logout is a form POST, not a link, so
/// the CSRF token is required.
///
/// The logout form is rendered inline in each shell's user-menu area.
/// The form submits to `POST /logout` and redirects to `/login`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogoutContract {
    pub form: FormContract,
}

impl LogoutContract {
    /// Workbench stub.
    pub fn workbench() -> Self {
        LogoutContract {
            form: FormContract::workbench_stub("/logout", "SessionEnded"),
        }
    }
}
