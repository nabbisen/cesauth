//! WebAuthn authentication ceremony (`/webauthn/authenticate/{start,finish}`).
//!
//! **CSRF (RFC 152 half D, 2026-11-03; corrected stage 1b, same day).**
//! Only `authenticate_finish` carries a real control. Stage 1 gave both
//! routes `required (Content-Type)` on the wrong test — "does a live
//! caller send this header" rather than "does this handler read an
//! ambient credential" — and the two routes are not alike by the second
//! question:
//!
//! - **`authenticate_finish` reads `cookie_header` before consuming the
//!   body**, for `post_auth::extract_pending_handle` → `complete_auth`,
//!   which reads `login_next` and steers where the resulting session
//!   lands. That is an ambient credential, so `Content-Type: application/
//!   json` (`crate::csrf::require_json_content_type`) stays required —
//!   confirmed against the real caller, `static/webauthn.js`'s
//!   `cesauthPasskeyAuthenticate`, which already sends it.
//! - **`authenticate_start` reads no cookie at all.** It has nothing
//!   ambient for a forged cross-site request to ride on, so it is `N/A
//!   (no ambient credential)` — the same value and the same reasoning
//!   `webauthn/register.rs` and `api_v1/anonymous::begin` already carry,
//!   not a new one. Its `Content-Type` check is removed, not weakened:
//!   the route needed no control in the first place.
//!
//! `/webauthn/register/{start,finish}` are untouched by this correction —
//! see `route-contracts.md`'s own cells and RFC 172 for `register_finish`,
//! which this same stage 1b review found carries the identical ambient-
//! credential shape `authenticate_finish` does, left for that RFC rather
//! than edited here (RFC 172 rewrites `register.rs` and must touch those
//! rows anyway).

use cesauth_cf::ports::repo::CloudflareAuthenticatorRepository;
use cesauth_cf::ports::store::CloudflareAuthChallengeStore;
use cesauth_core::ports::repo::AuthenticatorRepository;
use cesauth_core::ports::store::{AuthChallengeStore, AuthMethod, Challenge};
use cesauth_core::webauthn::authentication;
use serde::Deserialize;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::config::Config;
use crate::csrf;
use crate::error::oauth_error_response;
use crate::post_auth;

use super::rp_from_config;

// -------------------------------------------------------------------------
// POST /webauthn/authenticate/start
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct AuthenticateStartBody {
    /// If the caller knows which user this is (e.g. post-Magic-Link),
    /// they pin. Otherwise we run discoverable-credential mode.
    pinned_user_id: Option<String>,
}

pub async fn authenticate_start<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let cfg  = Config::from_env(&ctx.env)?;
    let rp   = rp_from_config(&cfg);
    let body: AuthenticateStartBody = req.json().await.unwrap_or_default();

    let (challenge, state) = match authentication::start(&rp, &[], body.pinned_user_id) {
        Ok(v)  => v,
        Err(e) => return oauth_error_response(&e),
    };

    let handle = cesauth_core::types::ChallengeHandle::mint();
    let now    = OffsetDateTime::now_utc().unix_timestamp();
    let store  = CloudflareAuthChallengeStore::new(&ctx.env);
    let chal   = Challenge::WebauthnAuthenticate {
        pinned_user_id: state.pinned_user_id,
        challenge:      state.challenge,
        expires_at:     now + 60,
    };
    if store.put(&handle, &chal).await.is_err() {
        return oauth_error_response(&cesauth_core::CoreError::Internal);
    }

    #[derive(serde::Serialize)]
    struct Reply {
        handle:     String,
        public_key: serde_json::Value,
    }
    Response::from_json(&Reply { handle: handle.to_string(), public_key: challenge.public_key })
}

// -------------------------------------------------------------------------
// POST /webauthn/authenticate/finish
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AuthenticateFinishBody {
    handle:   String,
    response: authentication::AuthenticationResponse,
}

pub async fn authenticate_finish<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if let Some(resp) = csrf::require_json_content_type(&req)? {
        return Ok(resp);
    }
    let cfg  = Config::from_env(&ctx.env)?;
    let rp   = rp_from_config(&cfg);

    // Grab the cookie header up front, before we consume the body
    // (`req.json()` moves out of `req`). We need both the parked-AR
    // pending handle (for the OAuth flow) AND the full header (so
    // complete_auth can read the `__Host-cesauth_login_next` cookie
    // for the no-AR landing case).
    let cookie_header = req.headers().get("cookie").ok().flatten();
    let pending = cookie_header.as_deref()
        .and_then(|h| post_auth::extract_pending_handle(h).map(str::to_owned));

    let body: AuthenticateFinishBody = match req.json().await {
        Ok(b)  => b,
        Err(_) => return oauth_error_response(&cesauth_core::CoreError::InvalidRequest("body")),
    };

    // Consume the single-use challenge.
    let store = CloudflareAuthChallengeStore::new(&ctx.env);
    // RFC 140: one clock for the request, read before the challenge is
    // taken so the store can enforce its expiry.
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let chal  = match store.take(&cesauth_core::types::ChallengeHandle::from_storage(&body.handle), now).await {
        Ok(Some(c)) => c,
        _ => return oauth_error_response(&cesauth_core::CoreError::InvalidRequest("handle")),
    };

    let state = match chal {
        Challenge::WebauthnAuthenticate { pinned_user_id, challenge, .. } =>
            authentication::AuthenticationState { challenge, pinned_user_id },
        _ => return oauth_error_response(&cesauth_core::CoreError::InvalidRequest("handle not authenticate")),
    };

    // Look up the authenticator by the credential ID the browser sent.
    // We store `credential_id` in base64url-no-pad form; strip trailing
    // '=' defensively in case a client library tags them on.
    let repo = CloudflareAuthenticatorRepository::new(&ctx.env);
    let stored = match repo
        .find_by_credential_id(body.response.raw_id.trim_end_matches('='))
        .await
    {
        Ok(Some(a)) => a,
        Ok(None)    => return oauth_error_response(&cesauth_core::CoreError::WebAuthn("credential not registered")),
        Err(_)      => return oauth_error_response(&cesauth_core::CoreError::Internal),
    };

    let outcome = match authentication::finish(&rp, &state, &body.response, &stored) {
        Ok(o)  => o,
        Err(e) => {
            audit::write_owned(
                &ctx.env, EventKind::AuthFailed,
                Some(stored.user_id.clone()), None,
                Some(format!("webauthn auth finish: {e:?}")),
            ).await.ok();
            return oauth_error_response(&e);
        }
    };

    // Persist the new sign_count BEFORE we issue anything the client
    // can hold on to. A failure here must rewind: without the counter
    // bump, a replayed assertion would pass.
    if let Err(e) = repo.touch(&stored.credential_id, outcome.new_sign_count, now).await {
        audit::write_owned(
            &ctx.env, EventKind::AuthFailed,
            Some(outcome.user_id.clone()), None,
            Some(format!("sign_count persist: {e:?}")),
        ).await.ok();
        return oauth_error_response(&cesauth_core::CoreError::Internal);
    }

    audit::write_owned(
        &ctx.env, EventKind::WebauthnVerified,
        Some(outcome.user_id.clone()), None, None,
    ).await.ok();

    post_auth::complete_auth(
        &ctx.env, &cfg, &outcome.user_id, AuthMethod::Passkey,
        pending.as_deref(), cookie_header.as_deref(),
    ).await
}
