//! Mailer adapters for the Cloudflare Workers runtime.
//!
//! See `cesauth_core::magic_link::mailer` for the trait and value types.
//! This module provides four reference adapters and the `from_env` factory.
//!
//! **RFC 031**: The factory previously returned `Box<dyn MagicLinkMailer>`,
//! which is not possible because `MagicLinkMailer` uses `async fn` (not
//! object-safe in Rust). The `CloudflareMagicLinkMailer` enum replaces the
//! `Box<dyn>` — it statically dispatches to the four variants and implements
//! `MagicLinkMailer` directly.

pub mod dev_console;
pub mod https_provider;
pub mod service_binding;
pub mod unconfigured;

pub use dev_console::DevConsoleMailer;
pub use https_provider::HttpsProviderMailer;
pub use service_binding::ServiceBindingMailer;
pub use unconfigured::UnconfiguredMailer;

use cesauth_core::magic_link::{DeliveryReceipt, MailerError, MagicLinkMailer, MagicLinkPayload};
use worker::Env;

/// Concrete enum dispatcher for the four Cloudflare mailer variants.
///
/// Implements `MagicLinkMailer` directly, replacing the old `Box<dyn
/// MagicLinkMailer>` factory pattern which was incompatible with `async fn`
/// in traits (not object-safe).
pub enum CloudflareMagicLinkMailer<'env> {
    Dev(DevConsoleMailer),
    Https(HttpsProviderMailer),
    ServiceBinding(ServiceBindingMailer<'env>),
    Unconfigured(UnconfiguredMailer),
}

impl MagicLinkMailer for CloudflareMagicLinkMailer<'_> {
    async fn send(
        &self,
        payload: &MagicLinkPayload<'_>,
    ) -> Result<DeliveryReceipt, MailerError> {
        match self {
            Self::Dev(m)            => m.send(payload).await,
            Self::Https(m)          => m.send(payload).await,
            Self::ServiceBinding(m) => m.send(payload).await,
            Self::Unconfigured(m)   => m.send(payload).await,
        }
    }
}

/// Select and construct the appropriate mailer adapter from the runtime env.
///
/// Selection priority (first match wins):
///
/// 1. `WRANGLER_LOCAL=1` → `DevConsoleMailer` (development only).
/// 2. `MAGIC_LINK_MAILER` service binding present → `ServiceBindingMailer`.
/// 3. `MAILER_PROVIDER_URL` set → `HttpsProviderMailer`.
/// 4. Nothing configured → `UnconfiguredMailer` (audits misconfig on use).
pub fn from_env(env: &Env) -> CloudflareMagicLinkMailer<'_> {
    if env.var("WRANGLER_LOCAL")
        .map(|v| v.to_string() == "1")
        .unwrap_or(false)
    {
        return CloudflareMagicLinkMailer::Dev(DevConsoleMailer);
    }

    if let Ok(m) = ServiceBindingMailer::new(env) {
        return CloudflareMagicLinkMailer::ServiceBinding(m);
    }

    if let Ok(m) = HttpsProviderMailer::from_env(env) {
        return CloudflareMagicLinkMailer::Https(m);
    }

    CloudflareMagicLinkMailer::Unconfigured(UnconfiguredMailer)
}
