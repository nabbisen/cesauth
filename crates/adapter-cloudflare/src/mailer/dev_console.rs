//! Dev-only mailer: logs the challenge handle to the worker console.
//!
//! The OTP code is NEVER logged. Developers running `wrangler dev`
//! can retrieve the challenge from local D1:
//!
//! ```sh
//! wrangler d1 execute cesauth-db --local \
//!   --command "SELECT code_hash FROM auth_challenges WHERE handle = '<handle>'"
//! ```
//!
//! For local testing, the developer tool `scripts/dev-otp.sh` (if present)
//! can derive the plaintext from the hash against the short known alphabet.
//!
//! **Guard**: this adapter MUST NOT be active outside `WRANGLER_LOCAL=1`.
//! The `from_env` factory enforces this guard before constructing.

use cesauth_core::magic_link::{DeliveryReceipt, MailerError, MagicLinkMailer, MagicLinkPayload};

/// Mailer adapter for local `wrangler dev` sessions.
///
/// Logs `handle` and `recipient` to the worker console. Never logs
/// `payload.code`. Suitable only for development; the factory rejects
/// this adapter outside `WRANGLER_LOCAL=1`.
pub struct DevConsoleMailer;

impl MagicLinkMailer for DevConsoleMailer {
    async fn send(
        &self,
        payload: &MagicLinkPayload<'_>,
    ) -> Result<DeliveryReceipt, MailerError> {
        // Deliberately do NOT log payload.code.
        // The developer fetches the OTP from local D1 by handle.
        worker::console_log!(
            "magic_link dev-console: handle={} recipient={} reason={} \
             (retrieve OTP from local D1 by handle)",
            payload.handle,
            payload.recipient,
            payload.reason.as_str(),
        );
        Ok(DeliveryReceipt {
            provider_message_id: None,
            queued_at_unix: worker::Date::now().as_millis() as i64 / 1000,
        })
    }
}
