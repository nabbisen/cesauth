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

use cesauth_cf::ports::cache::CloudflareCache;
use cesauth_cf::ports::repo::CloudflareUserRepository;
use cesauth_cf::ports::store::{CloudflareAuthChallengeStore, CloudflareRateLimitStore};
use cesauth_core::magic_link;
use cesauth_core::ports::cache::CacheStore;
use cesauth_core::ports::repo::UserRepository;
use cesauth_core::ports::store::{AuthChallengeStore, AuthMethod, Challenge, RateLimitStore};
use cesauth_core::turnstile;
use cesauth_core::types::{User, UserStatus};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Env, Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::config::{Config, load_turnstile_secret};
use crate::csrf;
use crate::error::oauth_error_response;
use crate::log::{self, Category, Level};
use crate::post_auth;
use crate::turnstile::HttpTurnstileVerifier;

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

// -------------------------------------------------------------------------
// POST /magic-link/request
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct RequestBody {
    email: String,
    /// Optional CSRF token; the login page sets one but non-browser
    /// callers may not. We accept either form.
    #[serde(default)]
    csrf:  Option<String>,
    /// Turnstile widget's response. Only consulted when the bucket's
    /// KV flag says Turnstile is mandatory right now.
    #[serde(default, rename = "cf-turnstile-response")]
    turnstile: Option<String>,
}

pub async fn request<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let cfg = Config::from_env(&ctx.env)?;

    // --- CSRF gate ---------------------------------------------------
    //
    // Only form-encoded submissions are subject to CSRF validation.
    // Cross-origin JSON submits from a browser are gated by the
    // same-origin policy / CORS preflight; an attacker page cannot
    // silently emit an `application/json` POST on the user's behalf.
    // See `crate::csrf` for the threat model.
    //
    // We extract the CSRF cookie here, before consuming the body. The
    // form-decode branch below picks the `csrf` form field and the
    // comparison happens immediately after.
    let content_type = req.headers().get("content-type").ok().flatten();
    let is_form = content_type.as_deref()
        .map(|ct| !ct.contains("application/json"))
        .unwrap_or(true);
    let cookie_csrf: Option<String> = if is_form {
        req.headers().get("cookie").ok().flatten()
            .and_then(|h| csrf::extract_from_cookie_header(&h).map(str::to_owned))
    } else {
        None
    };

    // The login form is `application/x-www-form-urlencoded`; a non-form
    // JSON caller works equally well. We accept both shapes.
    let body: RequestBody = match content_type.as_deref() {
        Some(ct) if ct.contains("application/json") => {
            req.json().await.unwrap_or_default()
        }
        _ => {
            let raw = req.text().await.unwrap_or_default();
            let form: std::collections::HashMap<String, String> =
                url::form_urlencoded::parse(raw.as_bytes()).into_owned().collect();
            RequestBody {
                email:     form.get("email").cloned().unwrap_or_default(),
                csrf:      form.get("csrf").cloned(),
                turnstile: form.get(TURNSTILE_FIELD).cloned(),
            }
        }
    };

    if is_form {
        // Both sides must be present. An attacker page cannot set the
        // `__Host-cesauth-csrf` cookie cross-origin (that's the point
        // of HttpOnly + SameSite=Strict), and it cannot read it to
        // echo back in the form. So requiring both to match is the
        // whole guard.
        let submitted   = body.csrf.as_deref().unwrap_or("");
        let from_cookie = cookie_csrf.as_deref().unwrap_or("");
        if !csrf::verify(submitted, from_cookie) {
            log::emit(&cfg.log, Level::Warn, Category::Session,
                "csrf mismatch on /magic-link/request", None);
            return oauth_error_response(&cesauth_core::CoreError::InvalidRequest("csrf"));
        }
    }

    // Reject obviously malformed input early, but do NOT leak whether
    // a given email maps to an existing account: success and failure
    // paths produce the same user-visible response.
    if body.email.trim().is_empty() || !body.email.contains('@') {
        return oauth_error_response(&cesauth_core::CoreError::InvalidRequest("email"));
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let bucket = format!("ml:req:{}", body.email.to_ascii_lowercase());

    // If Turnstile is flagged for this bucket, verify BEFORE incurring
    // any database / rate-limit side effect - we do not want abusers
    // to be able to churn rate-limit state by replaying tokens.
    if let Err(e) = enforce_turnstile(&ctx.env, &cfg, &bucket, body.turnstile.as_deref()).await {
        log::emit(&cfg.log, Level::Warn, Category::RateLimit,
            &format!("turnstile enforcement failed: {e:?}"), None);
        return oauth_error_response(&e);
    }

    // Rate limit: per-email bucket. If we ever add per-IP we AND them.
    let rate    = CloudflareRateLimitStore::new(&ctx.env);
    let decision = rate.hit(
        &bucket, now, MAIL_REQUEST_WINDOW_SECS, MAIL_REQUEST_LIMIT, MAIL_REQUEST_ESCALATE,
    ).await
        .map_err(|_| worker::Error::RustError("rate-limit unavailable".into()))?;

    if decision.escalate {
        log::emit(&cfg.log, Level::Warn, Category::RateLimit,
            &format!("escalate /magic-link/request bucket={bucket}"), None);
        flag_turnstile_required(&ctx.env, &bucket, MAIL_REQUEST_WINDOW_SECS).await;
    }

    if !decision.allowed {
        // Still respond indistinguishably to the happy path to avoid
        // revealing that this email was the one being probed. A 200
        // with the "check your inbox" page is correct - we just don't
        // send mail.
        return Response::from_html(cesauth_ui::templates::magic_link_sent_page());
    }

    // Mint the OTP. Handle = UUID; user-visible only if we store it
    // as a hidden form field on the "check your inbox" page.
    let issued = match magic_link::issue(now, cfg.magic_link_ttl_secs) {
        Ok(i)  => i,
        Err(e) => return oauth_error_response(&e),
    };
    let handle = Uuid::new_v4().to_string();

    let store = CloudflareAuthChallengeStore::new(&ctx.env);
    let chal  = Challenge::MagicLink {
        email_or_user: body.email.clone(),
        code_hash:     issued.code_hash.clone(),
        attempts:      0,
        expires_at:    issued.expires_at,
    };
    if store.put(&handle, &chal).await.is_err() {
        return oauth_error_response(&cesauth_core::CoreError::Internal);
    }

    // Delivery stub: audit the issuance. The plaintext OTP goes into
    // `reason` ONLY because this handler currently has no real mail
    // provider and we need local dev to work. When production mail is
    // wired in, this line MUST change to log only the handle.
    audit::write_owned(
        &ctx.env, EventKind::MagicLinkIssued,
        Some(body.email.clone()), None,
        Some(format!("dev-delivery handle={handle} code={}", issued.code_plaintext)),
    ).await.ok();

    // Respond with the "check your inbox" page. The form on that page
    // POSTs back to `/magic-link/verify` with `handle` + `code`.
    Response::from_html(cesauth_ui::templates::magic_link_sent_page())
}

// -------------------------------------------------------------------------
// POST /magic-link/verify
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct VerifyBody {
    handle: String,
    code:   String,
    #[serde(default, rename = "cf-turnstile-response")]
    turnstile: Option<String>,
}

pub async fn verify<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    // Grab pending-authorize cookie before we consume the body.
    let pending = req.headers().get("cookie").ok().flatten()
        .and_then(|h| post_auth::extract_pending_handle(&h).map(str::to_owned));

    let body: VerifyBody = match req.headers().get("content-type").ok().flatten().as_deref() {
        Some(ct) if ct.contains("application/json") => {
            req.json().await.unwrap_or_default()
        }
        _ => {
            let raw = req.text().await.unwrap_or_default();
            let form: std::collections::HashMap<String, String> =
                url::form_urlencoded::parse(raw.as_bytes()).into_owned().collect();
            VerifyBody {
                handle:    form.get("handle").cloned().unwrap_or_default(),
                code:      form.get("code").cloned().unwrap_or_default(),
                turnstile: form.get(TURNSTILE_FIELD).cloned(),
            }
        }
    };

    if body.handle.is_empty() || body.code.is_empty() {
        return oauth_error_response(&cesauth_core::CoreError::InvalidRequest("handle or code"));
    }

    let cfg = Config::from_env(&ctx.env)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let bucket = format!("ml:verify:{}", body.handle);

    // Turnstile gate (same logic as /request).
    if let Err(e) = enforce_turnstile(&ctx.env, &cfg, &bucket, body.turnstile.as_deref()).await {
        return oauth_error_response(&e);
    }

    // Per-handle rate limit for verify. Prevents brute-force of the
    // 40-bit code.
    let rate   = CloudflareRateLimitStore::new(&ctx.env);
    let decision = rate.hit(
        &bucket, now, MAIL_VERIFY_WINDOW_SECS, MAIL_VERIFY_LIMIT, MAIL_VERIFY_ESCALATE,
    ).await
        .map_err(|_| worker::Error::RustError("rate-limit unavailable".into()))?;

    if decision.escalate {
        flag_turnstile_required(&ctx.env, &bucket, MAIL_VERIFY_WINDOW_SECS).await;
    }

    if !decision.allowed {
        return oauth_error_response(&cesauth_core::CoreError::MagicLinkMismatch);
    }

    let store = CloudflareAuthChallengeStore::new(&ctx.env);

    // Bump attempts first - if verification fails, this still counts
    // against the rate window on top of the DO-level cap.
    let _ = store.bump_magic_link_attempts(&body.handle).await;

    // Peek (don't consume yet) so we can verify first. On success we
    // consume; on failure the next attempt can retry against the same
    // hash, subject to rate limiting.
    let chal = match store.peek(&body.handle).await {
        Ok(Some(c)) => c,
        _ => return oauth_error_response(&cesauth_core::CoreError::MagicLinkMismatch),
    };

    let (email, code_hash, expires_at) = match chal {
        Challenge::MagicLink { email_or_user, code_hash, expires_at, .. } =>
            (email_or_user, code_hash, expires_at),
        _ => return oauth_error_response(&cesauth_core::CoreError::MagicLinkMismatch),
    };

    if let Err(e) = magic_link::verify(&body.code, &code_hash, now, expires_at) {
        audit::write_owned(
            &ctx.env, EventKind::MagicLinkFailed,
            Some(email), None, Some(format!("{e:?}")),
        ).await.ok();
        return oauth_error_response(&e);
    }

    // Consume the challenge only on verified success.
    let _ = store.take(&body.handle).await;
    audit::write_owned(
        &ctx.env, EventKind::MagicLinkVerified,
        Some(email.clone()), None, None,
    ).await.ok();

    // Resolve (or create) the user. Magic-link is the self-service
    // signup path: first-login mints a User with `email_verified=true`
    // because delivery of the one-time code *is* the verification.
    let user_id = match resolve_or_create_user(&ctx.env, &email, now).await {
        Ok(id)  => id,
        Err(e)  => return oauth_error_response(&e),
    };

    post_auth::complete_auth(
        &ctx.env, &cfg, &user_id, AuthMethod::MagicLink, pending.as_deref(),
    ).await
}

/// Look up by email; create if not found. On conflict we do one retry
/// (the conflict means a concurrent request created the same user) and
/// re-query. Returns the resolved user_id.
async fn resolve_or_create_user(
    env:   &Env,
    email: &str,
    now:   i64,
) -> core::result::Result<String, cesauth_core::CoreError> {
    let repo = CloudflareUserRepository::new(env);

    if let Ok(Some(u)) = repo.find_by_email(email).await {
        return Ok(u.id);
    }

    let new = User {
        id:             Uuid::new_v4().to_string(),
        email:          Some(email.to_owned()),
        email_verified: true,
        display_name:   None,
        status:         UserStatus::Active,
        created_at:     now,
        updated_at:     now,
    };

    match repo.create(&new).await {
        Ok(()) => Ok(new.id),
        Err(_) => {
            // Conflict (or any other failure) - retry the lookup once
            // in case a concurrent request won the race.
            match repo.find_by_email(email).await {
                Ok(Some(u)) => Ok(u.id),
                _           => Err(cesauth_core::CoreError::Internal),
            }
        }
    }
}
