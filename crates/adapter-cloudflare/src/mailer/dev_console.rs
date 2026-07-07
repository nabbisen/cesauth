//! Dev-only mailer: logs the magic-link OTP code and handle to the worker
//! console so developers can complete the login flow without an email
//! provider configured.
//!
//! **Guard**: this adapter MUST NOT be active outside `WRANGLER_LOCAL=1`.
//! The `from_env` factory in `crates/adapter-cloudflare/src/mailer.rs`
//! enforces this guard before constructing. The production `wrangler.toml`
//! sets `WRANGLER_LOCAL = "0"`; developers set it to `"1"` only in
//! `.dev.vars` (which is git-ignored).
//!
//! ## Local login flow
//!
//! 1. Create `.dev.vars` in the repo root (git-ignored) with:
//!    ```
//!    WRANGLER_LOCAL = "1"
//!    ```
//! 2. Run `wrangler dev`.
//! 3. Request a magic link at `/magic-link/request`.
//! 4. Watch the **wrangler dev terminal** — you will see a log line like:
//!    ```
//!    [magic_link dev] recipient=you@example.com  handle=abc123  code=ABCD2345
//!    ```
//! 5. Enter `ABCD2345` into the code field on the verification page
//!    (it is case-insensitive; the handler normalises before comparing).
//!
//! The code is logged **only to the local terminal**. It is never written
//! to any persistent storage and never appears in production logs.

use cesauth_core::magic_link::{DeliveryReceipt, MailerError, MagicLinkMailer, MagicLinkPayload};

/// Mailer adapter for local `wrangler dev` sessions.
///
/// Logs the OTP code, handle, and recipient to the worker console.
/// Safe because the `from_env` factory refuses to construct this
/// outside `WRANGLER_LOCAL=1`, so the log line only ever appears in
/// a local terminal with no retention or forwarding.
pub struct DevConsoleMailer;

impl MagicLinkMailer for DevConsoleMailer {
    async fn send(
        &self,
        payload: &MagicLinkPayload<'_>,
    ) -> Result<DeliveryReceipt, MailerError> {
        // Log the OTP code so local devs can complete login without
        // an email provider.  Intentional and safe: DevConsoleMailer
        // is never constructed outside WRANGLER_LOCAL=1 (enforced by
        // the from_env factory), so this only appears in a local
        // wrangler dev terminal.
        worker::console_log!(
            "[magic_link dev] recipient={}  handle={}  code={}  reason={}",
            payload.recipient,
            payload.handle,
            payload.code,
            payload.reason.as_str(),
        );
        Ok(DeliveryReceipt {
            provider_message_id: None,
            queued_at_unix: worker::Date::now().as_millis() as i64 / 1000,
        })
    }
}
