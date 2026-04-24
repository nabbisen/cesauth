//! Magic Link fallback endpoints.
//!
//! Two endpoints:
//!
//! * `POST /magic-link/request` - user submits an email; we mint an OTP,
//!   stash its hash in the `AuthChallenge` DO, and hand off to a mail
//!   provider. Response is the same whether or not the email exists
//!   (account-enumeration mitigation).
//! * `POST /magic-link/verify` - user submits the handle and the OTP;
//!   we bump the attempt counter, check the hash, and on success start
//!   an `ActiveSession`, set the session cookie, and - if an
//!   `/authorize` flow was parked as a `PendingAuthorize` challenge -
//!   mint an `AuthCode` and 302 back to the client's `redirect_uri`.
//!
//! Rate limiting: both endpoints hit `RateLimitStore` with bucket keys
//! scoped by (IP, email) so a single address cannot be used to flood
//! one user's inbox, and a single IP cannot mass-request codes. When
//! the rate limiter escalates, we flip a KV flag that makes Turnstile
//! mandatory on subsequent hits against the same bucket - honest users
//! see zero challenges until something looks wrong.
//!
//! Mail delivery is intentionally abstracted away: in this handler we
//! log the plaintext code into the audit sink (marked with a special
//! `reason` so it's easy to filter) rather than actually sending email.
//! A production deploy should replace that with an HTTP call to a
//! transactional mail provider using the `MAGIC_LINK_MAIL_API_KEY`
//! secret declared in `wrangler.toml`.
//!
//! One submodule per handler. Shared state (rate-limit constants,
//! Turnstile flag helpers) lives in this parent file.

use cesauth_cf::ports::cache::CloudflareCache;
use cesauth_core::ports::cache::CacheStore;
use cesauth_core::turnstile;
use worker::Env;

use crate::config::{Config, load_turnstile_secret};
use crate::turnstile::HttpTurnstileVerifier;

mod request;
mod verify;

pub use request::request;
pub use verify::verify;

/// Rate limits. Generous on purpose: users mis-type emails, and honest
/// bursts of 2-3 requests in 5 minutes are normal after "didn't get
/// the email" confusion. The `escalate_after` threshold is lower so
/// Turnstile fires before the hard limit.
const MAIL_REQUEST_WINDOW_SECS: i64 = 300;
const MAIL_REQUEST_LIMIT:       u32 = 5;
const MAIL_REQUEST_ESCALATE:    u32 = 3;

const MAIL_VERIFY_WINDOW_SECS:  i64 = 600;
const MAIL_VERIFY_LIMIT:        u32 = 5;
const MAIL_VERIFY_ESCALATE:     u32 = 3;

/// The form field name Turnstile's widget injects into the form. We
/// read it here if Turnstile enforcement is active for this bucket.
const TURNSTILE_FIELD: &str = "cf-turnstile-response";

/// Key prefix in the CACHE KV for "this bucket currently requires
/// Turnstile". Lives for `ttl` seconds from the last escalation signal,
/// matching the rate-limit window so challenges expire with the heat.
fn turnstile_flag_key(bucket: &str) -> String {
    format!("turnstile:required:{bucket}")
}

/// Is the given bucket currently flagged as requiring Turnstile?
async fn turnstile_required(env: &Env, bucket: &str) -> bool {
    let cache = CloudflareCache::new(env);
    matches!(cache.get(&turnstile_flag_key(bucket)).await, Ok(Some(_)))
}

/// Record that the given bucket has escalated; future requests will be
/// challenged until the flag expires. The TTL matches the rate limit's
/// own window so the escalation fades with the underlying signal.
async fn flag_turnstile_required(env: &Env, bucket: &str, ttl_secs: i64) {
    let cache = CloudflareCache::new(env);
    let ttl = ttl_secs.max(1) as u32;
    let _ = cache.put(&turnstile_flag_key(bucket), b"1", ttl).await;
}

/// If Turnstile is flagged for this bucket, consume and validate the
/// token. Returns `Ok(())` to proceed; `Err(..)` to reject without
/// doing any further work. When Turnstile is NOT flagged we return
/// `Ok(())` immediately (no secret lookup, no siteverify call).
async fn enforce_turnstile(
    env:    &Env,
    cfg:    &Config,
    bucket: &str,
    token:  Option<&str>,
) -> core::result::Result<(), cesauth_core::CoreError> {
    if !turnstile_required(env, bucket).await {
        return Ok(());
    }
    let token = token.unwrap_or("");
    if token.is_empty() {
        return Err(cesauth_core::CoreError::InvalidRequest("turnstile required"));
    }
    let secret = match load_turnstile_secret(env) {
        Some(s) => s,
        // If the flag is on but the secret isn't configured, fail
        // closed: we cannot prove the token is real.
        None    => return Err(cesauth_core::CoreError::Internal),
    };
    // We verify the hostname matches our RP id. Turnstile's hostname
    // claim covers host-only checks; the full origin check is already
    // done by CSP + Host header upstream.
    let expected = Some(cfg.rp_id.as_str());
    turnstile::verify(&HttpTurnstileVerifier, &secret, token, None, expected).await
}
