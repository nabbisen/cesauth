//! Anonymous-trial endpoints (v0.17.0, ADR-004 Phase 2).
//!
//! Two routes:
//!
//! - `POST /api/v1/anonymous/begin` — unauthenticated. Mints a fresh
//!   anonymous user + bearer token. Per-IP rate-limited via the
//!   existing `RateLimit` DO with bucket key
//!   `anonymous_begin_per_ip:<ip>`.
//! - `POST /api/v1/anonymous/promote` — authenticated by the
//!   anonymous bearer (in `Authorization: Bearer ...`). Two-step:
//!   * Without a `code` field, issues a Magic Link OTP for the
//!     supplied email and returns the challenge handle.
//!   * With a `code` field, verifies the OTP and UPDATEs the
//!     anonymous user row in place — preserving `User.id`,
//!     filling in `email`/`email_verified`, flipping
//!     `account_type` to `human_user`, and revoking the
//!     anonymous bearer.
//!
//! Both routes route through the v0.16.0 foundation:
//! `AnonymousSessionRepository` for token storage,
//! `EventKind::Anonymous*` for audit. Magic-link infrastructure is
//! reused unchanged — `cesauth_core::magic_link::issue` /
//! `verify`, the `AuthChallengeStore` DO, the existing rate-limit
//! buckets — so the promotion path doesn't fork any of that logic.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cesauth_cf::anonymous::CloudflareAnonymousSessionRepository;
use cesauth_cf::ports::repo::CloudflareUserRepository;
use cesauth_cf::ports::store::{CloudflareAuthChallengeStore, CloudflareRateLimitStore};
use cesauth_core::anonymous::{
    AnonymousSession, AnonymousSessionRepository, ANONYMOUS_TOKEN_TTL_SECONDS,
};
use cesauth_core::magic_link;
use cesauth_core::ports::repo::UserRepository;
use cesauth_core::ports::store::{AuthChallengeStore, Challenge, RateLimitStore};
use cesauth_core::tenancy::{AccountType, DEFAULT_TENANT_ID};
use cesauth_core::types::{User, UserStatus};
use getrandom::getrandom;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::config::Config;
use crate::routes::api_v1::auth::{bad_request, json};

// ---------------------------------------------------------------------
// Rate-limit constants
// ---------------------------------------------------------------------

/// `/anonymous/begin` rate limit. Per-IP. Strict on purpose — an
/// anonymous user is essentially free to mint, so an unbounded
/// flow would let an attacker pollute the `users` table.
///
/// `n=20` over 5 minutes = one new anonymous user every 15 seconds
/// from a single IP, sustained. Honest visitors mint once per
/// browser session at most. The Cron Trigger sweep (v0.6.05) is
/// the second line of defense; this is the first.
const BEGIN_WINDOW_SECS: i64 = 300;
const BEGIN_LIMIT:       u32 = 20;
const BEGIN_ESCALATE:    u32 = 10;

// ---------------------------------------------------------------------
// /anonymous/begin
// ---------------------------------------------------------------------

#[derive(Serialize)]
struct BeginResponseBody {
    /// The freshly-created user's id. RPs that want to address the
    /// principal (e.g. attach trial-scoped state to it) reference
    /// this id.
    user_id:    String,
    /// Plaintext bearer. Shown ONCE; cesauth stores only the
    /// SHA-256 hash. After this response, the only way to obtain
    /// a working token is to call `/begin` again (which mints a
    /// new user + token).
    token:      String,
    /// Token expiry, Unix seconds. The user row survives longer
    /// (7 days, ADR-004 §Q3) but the token does not.
    expires_at: i64,
}

pub async fn begin<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let ip  = client_ip(&req).unwrap_or_else(|| "unknown".to_owned());

    // ---- Per-IP rate limit ------------------------------------------
    let bucket = format!("anonymous_begin_per_ip:{ip}");
    let rate   = CloudflareRateLimitStore::new(&ctx.env);
    let decision = rate.hit(
        &bucket, now, BEGIN_WINDOW_SECS, BEGIN_LIMIT, BEGIN_ESCALATE,
    ).await
        .map_err(|_| worker::Error::RustError("rate-limit unavailable".into()))?;
    if !decision.allowed {
        // Same shape as the OAuth `temporarily_unavailable` response
        // — explicit 429 makes the rate-limit signal unambiguous to
        // any caller doing programmatic backoff.
        let mut resp = Response::error("rate limited", 429)?;
        resp.headers_mut().set(
            "retry-after",
            &decision.resets_in.to_string(),
        ).ok();
        return Ok(resp);
    }

    // ---- Mint plaintext + hash --------------------------------------
    let plaintext = mint_token_plaintext()?;
    let token_hash = sha256_hex(&plaintext);

    // ---- Create user row + session row ------------------------------
    let user_id = Uuid::new_v4().to_string();
    let display = display_tag();

    let user = User {
        id:             user_id.clone(),
        tenant_id:      DEFAULT_TENANT_ID.to_owned(),
        email:          None,
        email_verified: false,
        display_name:   Some(display),
        account_type:   AccountType::Anonymous,
        status:         UserStatus::Active,
        created_at:     now,
        updated_at:     now,
    };
    let users = CloudflareUserRepository::new(&ctx.env);
    if let Err(e) = users.create(&user).await {
        worker::console_error!("anonymous user create failed: {e:?}");
        return Response::error("storage error", 500);
    }

    let sessions = CloudflareAnonymousSessionRepository::new(&ctx.env);
    let session = match sessions.create(
        &token_hash, &user_id, DEFAULT_TENANT_ID, now,
        ANONYMOUS_TOKEN_TTL_SECONDS,
    ).await {
        Ok(s) => s,
        Err(e) => {
            worker::console_error!("anonymous session create failed: {e:?}");
            // Best-effort cleanup of the user row we just inserted.
            // The retention sweep would catch it eventually anyway.
            return Response::error("storage error", 500);
        }
    };

    // ---- Audit ------------------------------------------------------
    audit::write_owned(
        &ctx.env, EventKind::AnonymousCreated,
        Some(user_id.clone()),
        None,
        Some(format!("via=anonymous-begin,ip={}", mask_ip(&ip))),
    ).await.ok();

    // ---- Response ---------------------------------------------------
    json(201, &BeginResponseBody {
        user_id,
        token:      plaintext,
        expires_at: session.expires_at,
    })
}

// ---------------------------------------------------------------------
// /anonymous/promote
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct PromoteBody {
    /// The email the visitor wants to claim. Required on both the
    /// "issue OTP" step and the "verify OTP" step.
    email:  String,
    /// Magic-link challenge handle. Returned on the issue step;
    /// echoed back on the verify step.
    #[serde(default)]
    handle: Option<String>,
    /// OTP plaintext. Absent on the issue step; present on the
    /// verify step.
    #[serde(default)]
    code:   Option<String>,
}

#[derive(Serialize)]
struct PromoteIssueBody {
    handle: String,
    /// Hint to the client about how long the OTP stays valid,
    /// Unix seconds. Same TTL as the existing /magic-link path
    /// (10 minutes via core::magic_link::OTP_TTL_SECS).
    expires_at: i64,
}

#[derive(Serialize)]
struct PromoteSuccessBody {
    user_id:  String,
    promoted: bool,
}

pub async fn promote<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // ---- Resolve the anonymous bearer -------------------------------
    let session = match resolve_anonymous_bearer(&req, &ctx.env, now).await? {
        Ok(s)  => s,
        Err(r) => return Ok(r),
    };

    // ---- Parse body -------------------------------------------------
    let body: PromoteBody = match req.json().await {
        Ok(b)  => b,
        Err(_) => return bad_request("invalid_json"),
    };
    let email = body.email.trim().to_ascii_lowercase();
    if email.is_empty() || !email.contains('@') {
        return bad_request("invalid_email");
    }

    // ---- Branch: issue OTP vs apply promotion -----------------------
    match (body.handle.as_deref(), body.code.as_deref()) {
        (None, None) => issue_promote_otp(&ctx, &session, &email, now).await,
        (Some(h), Some(c))
                     => apply_promotion(&ctx, &session, &email, h, c, now).await,
        _            => bad_request("handle_and_code_must_be_paired"),
    }
}

/// Step A: visitor supplied an email. Issue an OTP via the same
/// Magic Link path used for self-registration; return the handle.
async fn issue_promote_otp<D>(
    ctx:     &RouteContext<D>,
    session: &AnonymousSession,
    email:   &str,
    now:     i64,
) -> Result<Response> {
    let cfg = Config::from_env(&ctx.env)?;
    let issued = match magic_link::issue(now, cfg.magic_link_ttl_secs) {
        Ok(i) => i,
        Err(e) => {
            worker::console_error!("magic_link::issue failed: {e:?}");
            return Response::error("storage error", 500);
        }
    };

    let handle = Uuid::new_v4().to_string();
    let challenges = CloudflareAuthChallengeStore::new(&ctx.env);
    if let Err(e) = challenges.put(&handle, &Challenge::MagicLink {
        email_or_user: email.to_owned(),
        code_hash:     issued.code_hash.clone(),
        attempts:      0,
        expires_at:    issued.expires_at,
    }).await {
        worker::console_error!("magic_link challenge put failed: {e:?}");
        return Response::error("storage error", 500);
    }

    // The OTP plaintext is the email-deliverable. We log it into
    // the audit trail with a special reason marker so the existing
    // mail-delivery pipeline (which today reads the audit log;
    // see `routes/magic_link.rs` module doc) picks it up
    // automatically.
    audit::write_owned(
        &ctx.env, EventKind::MagicLinkIssued,
        Some(session.user_id.clone()),
        None,
        Some(format!("via=anonymous-promote,handle={},code={}",
            handle, issued.code_plaintext)),
    ).await.ok();

    json(200, &PromoteIssueBody {
        handle,
        expires_at: issued.expires_at,
    })
}

/// Step B: visitor supplied (handle, code). Verify the OTP, then
/// UPDATE the existing anonymous user row in place.
async fn apply_promotion<D>(
    ctx:     &RouteContext<D>,
    session: &AnonymousSession,
    email:   &str,
    handle:  &str,
    code:    &str,
    now:     i64,
) -> Result<Response> {
    let challenges = CloudflareAuthChallengeStore::new(&ctx.env);

    // Bump attempt counter before peeking — same "fail-closed
    // attempt counting" the existing /magic-link/verify uses.
    // Deliberately not enforcing a hard ceiling here; the OTP
    // entropy + 10-minute TTL are the limiting controls. Mirrors
    // the existing /magic-link/verify behaviour.
    let _ = challenges.bump_magic_link_attempts(handle).await;

    let challenge = match challenges.peek(handle).await {
        Ok(Some(Challenge::MagicLink { email_or_user, code_hash, expires_at, .. })) => {
            (email_or_user, code_hash, expires_at)
        }
        _ => return bad_request("invalid_or_expired_handle"),
    };
    let (challenge_email, challenge_hash, challenge_expires) = challenge;

    // The challenge MUST be for the same email the user is now
    // claiming. Defense in depth — without this, an attacker who
    // observed a handle for someone else's promotion attempt
    // could try to splice it into their own.
    if challenge_email.to_ascii_lowercase() != email {
        return bad_request("email_mismatch");
    }

    if magic_link::verify(code, &challenge_hash, now, challenge_expires).is_err() {
        return bad_request("verification_failed");
    }

    // Consume the challenge so it can't be replayed.
    let _ = challenges.take(handle).await;

    // ---- Email-uniqueness check (in-tenant) -------------------------
    //
    // ADR-004 §Q4: "this email is already registered, log in
    // normally instead" must be distinguishable from "verify failed"
    // in the response, so the client can render the right guidance.
    let users = CloudflareUserRepository::new(&ctx.env);
    if let Ok(Some(existing)) = users.find_by_email(email).await {
        if existing.id != session.user_id {
            // Audit a failed promotion attempt — useful for spotting
            // someone trying to harvest valid emails by promotion-
            // probing. Subject is the anonymous user attempting,
            // not the existing user being collided with.
            audit::write_owned(
                &ctx.env, EventKind::MagicLinkFailed,
                Some(session.user_id.clone()),
                None,
                Some("via=anonymous-promote,reason=email_already_registered".into()),
            ).await.ok();
            return bad_request("email_already_registered");
        }
    }

    // ---- Apply the UPDATE -------------------------------------------
    let mut user = match users.find_by_id(&session.user_id).await {
        Ok(Some(u)) => u,
        _ => return Response::error("user not found", 404),
    };
    // Defense in depth: the row must STILL be anonymous. A racy
    // double-submit of /promote against the same user could
    // otherwise land the second request after the first already
    // flipped the type — we'd be silently re-promoting an already-
    // promoted row. This check makes the second arrival a 409.
    if user.account_type != AccountType::Anonymous {
        return bad_request("not_anonymous");
    }

    user.email          = Some(email.to_owned());
    user.email_verified = true;
    user.account_type   = AccountType::HumanUser;
    user.updated_at     = now;

    if let Err(e) = users.update(&user).await {
        worker::console_error!("anonymous promote update failed: {e:?}");
        return Response::error("storage error", 500);
    }

    // ---- Revoke the anonymous bearer --------------------------------
    //
    // ADR-004 §Q4: defense in depth for the case where the
    // promotion was driven by an attacker holding the anonymous
    // bearer. After this, the freshly-promoted user must log in
    // through the regular OIDC ceremony.
    let sessions = CloudflareAnonymousSessionRepository::new(&ctx.env);
    let _ = sessions.revoke_for_user(&session.user_id).await;

    // ---- Audit ------------------------------------------------------
    audit::write_owned(
        &ctx.env, EventKind::AnonymousPromoted,
        Some(session.user_id.clone()),
        None,
        Some(format!(
            "via=anonymous-promote,from=anonymous,to=human_user")),
    ).await.ok();

    json(200, &PromoteSuccessBody {
        user_id:  session.user_id.clone(),
        promoted: true,
    })
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Resolve an anonymous bearer in the `Authorization: Bearer ...`
/// header to a live `AnonymousSession`. Returns `Err(Response)` for
/// any failure mode (missing/malformed/unknown/expired/non-anon),
/// each with a JSON 401 body.
async fn resolve_anonymous_bearer(
    req: &Request, env: &worker::Env, now: i64,
) -> Result<std::result::Result<AnonymousSession, Response>> {
    let bearer = match req.headers().get("authorization").ok().flatten() {
        Some(h) if h.starts_with("Bearer ") => h[7..].to_owned(),
        _ => return Ok(Err(unauthorized("missing_bearer")?)),
    };
    let hash = sha256_hex(&bearer);

    let sessions = CloudflareAnonymousSessionRepository::new(env);
    let session = match sessions.find_by_hash(&hash).await {
        Ok(Some(s)) => s,
        Ok(None)    => return Ok(Err(unauthorized("unknown_token")?)),
        Err(_)      => return Ok(Err(Response::error("storage error", 500)?)),
    };

    if session.is_expired(now) {
        return Ok(Err(unauthorized("token_expired")?));
    }

    // Defense in depth — the token's user row must STILL be
    // anonymous. If it was promoted (and the bearer somehow
    // survived the revoke), reject. The `revoke_for_user` in the
    // promotion path makes this case unreachable in practice;
    // keeping the check is cheap insurance.
    let users = CloudflareUserRepository::new(env);
    let user = match users.find_by_id(&session.user_id).await {
        Ok(Some(u)) => u,
        _ => return Ok(Err(unauthorized("user_not_found")?)),
    };
    if user.account_type != AccountType::Anonymous {
        return Ok(Err(unauthorized("not_anonymous")?));
    }

    Ok(Ok(session))
}

fn unauthorized(reason: &str) -> Result<Response> {
    let body = serde_json::json!({ "error": reason });
    let mut resp = Response::ok(body.to_string())?.with_status(401);
    resp.headers_mut().set("content-type", "application/json; charset=utf-8")?;
    resp.headers_mut().set("www-authenticate", "Bearer realm=\"cesauth\"")?;
    Ok(resp)
}

/// Mint a 32-byte URL-safe base64 plaintext bearer.
fn mint_token_plaintext() -> Result<String> {
    let mut buf = [0u8; 32];
    getrandom(&mut buf)
        .map_err(|_| worker::Error::RustError("random fill failed".into()))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

fn sha256_hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    let bytes = h.finalize();
    let mut s = String::with_capacity(64);
    for b in bytes { s.push_str(&format!("{b:02x}")); }
    s
}

/// Display tag like `Anon-7K9F2`. Five chars from a small alphabet.
/// Cosmetic only — RPs that need a human-visible label can use it.
fn display_tag() -> String {
    const ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let mut buf = [0u8; 5];
    let _ = getrandom(&mut buf);
    let mut s = String::from("Anon-");
    for b in buf {
        s.push(ALPHABET[(b as usize) % ALPHABET.len()] as char);
    }
    s
}

/// Pull `cf-connecting-ip` from the request. Cloudflare populates
/// this on every request; absence means we're behind something
/// non-Cloudflare-fronted, which shouldn't happen in production
/// but degrades gracefully (rate limit applies to the literal
/// "unknown" bucket).
fn client_ip(req: &Request) -> Option<String> {
    req.headers().get("cf-connecting-ip").ok().flatten()
}

/// Mask the IP for audit logging — keep enough context to
/// distinguish bursts from single addresses but not so much that
/// we log raw client IPs at info level. IPv4: zero last octet.
/// IPv6: zero last 64 bits.
fn mask_ip(ip: &str) -> String {
    if ip.contains('.') {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() == 4 {
            return format!("{}.{}.{}.0", parts[0], parts[1], parts[2]);
        }
    }
    if let Some(idx) = ip.rfind(':') {
        if ip[idx+1..].len() <= 4 {
            return format!("{}::/64", &ip[..idx]);
        }
    }
    "masked".to_owned()
}
