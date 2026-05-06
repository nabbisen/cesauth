//! Fallback mailer for unconfigured deployments.
//!
//! Returns `MailerError::NotConfigured` on every send. The calling handler
//! audits this as `MagicLinkDeliveryFailed { kind: "not_configured" }` and
//! logs at Error level, but still returns the normal "check your inbox"
//! page to the user (no enumeration leak via differential response).
//!
//! Operators see a spike in `magic_link_delivery_failed` audit events with
//! `kind=not_configured` on first Magic Link attempt, which is the intended
//! misconfig signal.

use cesauth_core::magic_link::{DeliveryReceipt, MailerError, MagicLinkMailer, MagicLinkPayload};

/// Mailer adapter for deployments that have not yet wired a real mail provider.
///
/// Returns `NotConfigured` on every send, surfacing the misconfig loudly
/// via audit rather than crashing cesauth or leaking delivery state to users.
pub struct UnconfiguredMailer;

impl MagicLinkMailer for UnconfiguredMailer {
    async fn send(
        &self,
        _payload: &MagicLinkPayload<'_>,
    ) -> Result<DeliveryReceipt, MailerError> {
        Err(MailerError::NotConfigured)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unconfigured_mailer_returns_not_configured() {
        let mailer = UnconfiguredMailer;
        let payload = MagicLinkPayload {
            recipient: "user@example.com",
            handle:    "handle_abc",
            code:      "TESTCODE",
            locale:    "en",
            tenant_id: None,
            reason:    cesauth_core::magic_link::MagicLinkReason::InitialAuth,
        };
        let err = mailer.send(&payload).await.unwrap_err();
        assert!(matches!(err, MailerError::NotConfigured));
        assert_eq!(err.audit_kind(), "not_configured");
    }
}
