//! `MagicLinkMailer` — port for delivering a Magic Link OTP to a user.
//!
//! ## v0.51.0 (RFC 010)
//!
//! Prior to v0.51.0 cesauth had no mailer abstraction. The OTP plaintext
//! was written into the audit log (`EventKind::MagicLinkIssued` `reason`
//! field) and operators were expected to ship the audit stream to a script
//! that parsed `code=<OTP>` lines and SMTPd them. This was a security
//! violation (RFC 008) and a structural gap: no contract existed between
//! cesauth and a real mail provider.
//!
//! This module defines the contract. Operator-side crates implement
//! `MagicLinkMailer` and wire their implementation into cesauth's worker
//! factory (`cesauth_worker::adapter::mailer::from_env`). Four reference
//! adapters ship in `cesauth-adapter-cloudflare`:
//!
//! - `DevConsoleMailer` — logs the handle to stdout (never the code);
//!   enabled only when `WRANGLER_LOCAL=1`.
//! - `UnconfiguredMailer` — returns `MailerError::NotConfigured`; used
//!   when no provider env var is set. Surfaces misconfig via audit.
//! - `ServiceBindingMailer` — sends through a Cloudflare service binding
//!   to an operator-deployed mail worker.
//! - `HttpsProviderMailer` — sends a POST to a provider HTTP API
//!   (SendGrid / SES / Postmark / Resend shape).
//!
//! ## Trust boundary
//!
//! Implementors receive the OTP plaintext via `MagicLinkPayload::code`.
//! Implementors **MUST NOT** log, audit, persist, or otherwise transmit
//! the plaintext outside the immediate delivery channel. The audit log
//! receives only the handle (`EventKind::MagicLinkDelivered` or
//! `EventKind::MagicLinkDeliveryFailed`) — never the code.
//!
//! ## Audit boundary (compile-time)
//!
//! `cesauth-core` does NOT depend on `cesauth-worker::audit`. Mailer
//! adapter crates likewise. A mailer adapter cannot call `audit::write_*`
//! because the symbol is not in scope — Cargo's crate graph enforces the
//! boundary structurally. Audit writes are the calling worker handler's
//! responsibility only.

use std::future::Future;

// ─────────────────────────────────────────────────────────────────────────────
// Core trait
// ─────────────────────────────────────────────────────────────────────────────

/// Port for delivering a Magic Link OTP to a user.
///
/// Implementors are responsible for rendering and sending the email body.
/// cesauth supplies the payload; the implementor supplies the mail channel.
///
/// All methods are async. Implementors on the Cloudflare Workers runtime
/// must be `Send + Sync` to satisfy the worker event-handler bound.
pub trait MagicLinkMailer: Send + Sync {
    /// Deliver the OTP. Returns `Ok(DeliveryReceipt)` on successful enqueue
    /// — this is the *provider's accept*, not guaranteed inbox receipt.
    /// Returns `Err` on delivery failure.
    ///
    /// The caller renders the same success-shaped HTTP response regardless
    /// of this return value (no enumeration leak via differential response).
    fn send(
        &self,
        payload: &MagicLinkPayload<'_>,
    ) -> impl Future<Output = Result<DeliveryReceipt, MailerError>> + Send;
}

// ─────────────────────────────────────────────────────────────────────────────
// Payload
// ─────────────────────────────────────────────────────────────────────────────

/// Data passed to `MagicLinkMailer::send` for each issuance.
#[derive(Debug)]
pub struct MagicLinkPayload<'a> {
    /// Recipient email address. Matches `users.email` for returning users;
    /// raw input for first-time / anonymous-promote flows.
    pub recipient: &'a str,
    /// Cesauth's server-side challenge handle. Not secret. Useful for
    /// operator audit correlation (appears in `MagicLinkDelivered` event).
    pub handle: &'a str,
    /// **Secret.** OTP plaintext. Only this mailer instance receives it.
    /// Do not log, persist, or forward outside the delivery channel.
    pub code: &'a str,
    /// BCP-47 locale string (e.g. `"ja"`, `"en"`) from Accept-Language
    /// negotiation. Used by adapters that render their own email body.
    pub locale: &'a str,
    /// Originating tenant ID if known. Used for per-tenant SMTP config
    /// in multi-tenant deployments. `None` in single-tenant setups.
    pub tenant_id: Option<&'a str>,
    /// Why the link was issued — allows adapters to render different
    /// subject lines or body copy per reason.
    pub reason: MagicLinkReason,
}

/// Reason why a Magic Link was issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MagicLinkReason {
    /// User initiated login from `/login` or `/authorize` cold path.
    InitialAuth,
    /// Returning user re-authenticating.
    ReturningUserAuth,
    /// Anonymous trial user promoting to a registered account.
    AnonymousPromote,
}

impl MagicLinkReason {
    /// Snake-case identifier for use in JSON envelopes and log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InitialAuth       => "initial_auth",
            Self::ReturningUserAuth => "returning_user_auth",
            Self::AnonymousPromote  => "anonymous_promote",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Receipt
// ─────────────────────────────────────────────────────────────────────────────

/// Confirmation that the mailer accepted the outbound send request.
#[derive(Debug, Clone)]
pub struct DeliveryReceipt {
    /// Provider-assigned message identifier (opaque from cesauth's view).
    /// Present for API providers; absent for console/service-binding adapters
    /// that don't surface a provider message ID.
    pub provider_message_id: Option<String>,
    /// Unix timestamp when the mailer accepted the payload.
    pub queued_at_unix: i64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by a `MagicLinkMailer::send` implementation.
#[derive(Debug, thiserror::Error)]
pub enum MailerError {
    /// Delivery attempt failed but may succeed on retry (network hiccup,
    /// provider rate limit, etc.).
    #[error("mailer transient failure: {0}")]
    Transient(String),
    /// Delivery attempt failed definitively (invalid address, blocked
    /// domain, provider rejection, etc.). Retrying is futile.
    #[error("mailer permanent failure: {0}")]
    Permanent(String),
    /// No mailer is configured for this environment. cesauth is operational
    /// but Magic Link is unavailable until an adapter is wired in.
    #[error("mailer not configured")]
    NotConfigured,
}

impl MailerError {
    /// Snake-case failure category for audit payloads.
    ///
    /// Operators can alert on `permanent` (likely misconfigured address /
    /// provider rejection) and `not_configured` (deployment misconfiguration)
    /// independently from `transient` (provider blips, retryable).
    pub fn audit_kind(&self) -> &'static str {
        match self {
            Self::Transient(_)  => "transient",
            Self::Permanent(_)  => "permanent",
            Self::NotConfigured => "not_configured",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailer_error_audit_kind_returns_snake_case() {
        assert_eq!(MailerError::Transient("x".into()).audit_kind(),  "transient");
        assert_eq!(MailerError::Permanent("x".into()).audit_kind(),  "permanent");
        assert_eq!(MailerError::NotConfigured.audit_kind(),          "not_configured");
    }

    #[test]
    fn magic_link_reason_as_str_returns_snake_case() {
        assert_eq!(MagicLinkReason::InitialAuth.as_str(),       "initial_auth");
        assert_eq!(MagicLinkReason::ReturningUserAuth.as_str(), "returning_user_auth");
        assert_eq!(MagicLinkReason::AnonymousPromote.as_str(),  "anonymous_promote");
    }

    #[test]
    fn magic_link_reason_eq_and_copy() {
        let a = MagicLinkReason::InitialAuth;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(a, MagicLinkReason::AnonymousPromote);
    }
}
