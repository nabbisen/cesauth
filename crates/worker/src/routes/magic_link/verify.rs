//! `POST /magic-link/verify` handler.

use cesauth_cf::ports::repo::CloudflareUserRepository;
use cesauth_cf::ports::store::{CloudflareAuthChallengeStore, CloudflareRateLimitStore};
use cesauth_core::magic_link;
use cesauth_core::ports::repo::UserRepository;
use cesauth_core::ports::store::{AuthChallengeStore, AuthMethod, Challenge, RateLimitStore};
use cesauth_core::types::{User, UserStatus};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Env, Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::config::Config;
use crate::error::oauth_error_response;
use crate::post_auth;

use super::{
    enforce_turnstile, flag_turnstile_required, MAIL_VERIFY_ESCALATE, MAIL_VERIFY_LIMIT,
    MAIL_VERIFY_WINDOW_SECS, TURNSTILE_FIELD,
};


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
        // Magic-link self-signup goes into the bootstrap tenant in
        // 0.4.x. Multi-tenant signup (where the user picks/lands on
        // a tenant first) is a 0.7.0+ design pass.
        tenant_id:      cesauth_core::tenancy::DEFAULT_TENANT_ID.to_owned(),
        email:          Some(email.to_owned()),
        email_verified: true,
        display_name:   None,
        account_type:   cesauth_core::tenancy::AccountType::HumanUser,
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
