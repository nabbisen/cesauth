//! WebAuthn authentication ceremony (`/webauthn/authenticate/{start,finish}`).

use cesauth_cf::ports::repo::CloudflareAuthenticatorRepository;
use cesauth_cf::ports::store::CloudflareAuthChallengeStore;
use cesauth_core::ports::repo::AuthenticatorRepository;
use cesauth_core::ports::store::{AuthChallengeStore, AuthMethod, Challenge};
use cesauth_core::webauthn::authentication;
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::config::Config;
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

    let handle = Uuid::new_v4().to_string();
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
    Response::from_json(&Reply { handle, public_key: challenge.public_key })
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
    let cfg  = Config::from_env(&ctx.env)?;
    let rp   = rp_from_config(&cfg);

    // Grab the pending-authorize cookie up front, before we consume
    // the body (`req.json()` moves out of `req`).
    let pending = req.headers().get("cookie").ok().flatten()
        .and_then(|h| post_auth::extract_pending_handle(&h).map(str::to_owned));

    let body: AuthenticateFinishBody = match req.json().await {
        Ok(b)  => b,
        Err(_) => return oauth_error_response(&cesauth_core::CoreError::InvalidRequest("body")),
    };

    // Consume the single-use challenge.
    let store = CloudflareAuthChallengeStore::new(&ctx.env);
    let chal  = match store.take(&body.handle).await {
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
    let now = OffsetDateTime::now_utc().unix_timestamp();
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
        &ctx.env, &cfg, &outcome.user_id, AuthMethod::Passkey, pending.as_deref(),
    ).await
}
