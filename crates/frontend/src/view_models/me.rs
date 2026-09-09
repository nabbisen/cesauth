//! Personal-scope (ME) view models (RFC 029).

use super::shared::FormContract;
use serde::{Deserialize, Serialize};

/// Contract for revoking the current user's own session.
/// Action: `DELETE /me/sessions/:session_id`
/// Audit event: `SessionRevoked`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeSelfSessionContract {
    pub session_id: String,
    pub form: FormContract,
}

/// Contract for TOTP enrolment confirmation.
/// Action: `POST /me/totp/confirm`
/// Audit event: `TotpEnrolled`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TotpEnrollConfirmContract {
    pub form: FormContract,
}

/// Contract for disabling TOTP.
/// Action: `POST /me/totp/disable`
/// Audit event: `TotpDisabled`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TotpDisableContract {
    pub form: FormContract,
}

/// Contract for regenerating recovery codes.
/// Action: `POST /me/recovery-codes/regenerate`
/// Audit event: `RecoveryCodesRegenerated`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegenerateRecoveryCodesContract {
    pub form: FormContract,
}

/// Contract for requesting account self-deletion.
/// Action: `POST /me/delete`
/// Audit event: `DeletionRequested`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestSelfDeletionContract {
    pub form: FormContract,
}
