//! Mailer adapters for the Cloudflare Workers runtime.
//!
//! See `cesauth_core::magic_link::mailer` for the trait and value types.
//! This module provides four reference adapters and the `from_env` factory.

pub mod dev_console;
pub mod https_provider;
pub mod service_binding;
pub mod unconfigured;

pub use dev_console::DevConsoleMailer;
pub use https_provider::HttpsProviderMailer;
pub use service_binding::ServiceBindingMailer;
pub use unconfigured::UnconfiguredMailer;

use cesauth_core::magic_link::MagicLinkMailer;
use worker::Env;

/// Select and construct the appropriate mailer adapter from the runtime env.
///
/// Selection priority (first match wins):
///
/// 1. `WRANGLER_LOCAL=1` → `DevConsoleMailer` (development only).
/// 2. `MAGIC_LINK_MAILER` service binding present → `ServiceBindingMailer`.
/// 3. `MAILER_PROVIDER_URL` set → `HttpsProviderMailer`.
/// 4. Nothing configured → `UnconfiguredMailer` (audits misconfig on use).
///
/// The returned `Box<dyn MagicLinkMailer>` is heap-allocated because the
/// concrete adapter type is not known until runtime.
pub fn from_env(env: &Env) -> Box<dyn MagicLinkMailer> {
    // Guard: DevConsoleMailer is ONLY allowed in local dev.
    if env.var("WRANGLER_LOCAL")
        .map(|v| v.to_string() == "1")
        .unwrap_or(false)
    {
        return Box::new(DevConsoleMailer);
    }

    // Service binding takes priority over HTTPS — CF-internal is preferred.
    if let Ok(m) = ServiceBindingMailer::new(env) {
        return Box::new(m);
    }

    // HTTPS provider fallback.
    if let Ok(m) = HttpsProviderMailer::from_env(env) {
        return Box::new(m);
    }

    // Nothing configured — surface misconfig via audit on first use.
    Box::new(UnconfiguredMailer)
}
