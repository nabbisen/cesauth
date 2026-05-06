//! WebAuthn registration ceremony (`/webauthn/register/{start,finish}`).

use cesauth_cf::ports::repo::CloudflareAuthenticatorRepository;
use cesauth_cf::ports::store::CloudflareAuthChallengeStore;
use cesauth_core::ports::repo::AuthenticatorRepository;
use cesauth_core::ports::store::{AuthChallengeStore, AuthMethod, Challenge};
use cesauth_core::webauthn::registration;
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
// POST /webauthn/register/start
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct RegisterStartBody {
    user_id:        Option<String>,
    preferred_name: Option<String>,
}

pub async fn register_start<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let cfg  = Config::from_env(&ctx.env)?;
    let rp   = rp_from_config(&cfg);
    let body: RegisterStartBody = req.json().await.unwrap_or_default();

    let (challenge, state) = match registration::start(&rp, body.user_id, body.preferred_name.as_deref()) {
        Ok(v)  => v,
        Err(e) => return oauth_error_response(&e),
    };

    let handle = Uuid::new_v4().to_string();
    let now    = OffsetDateTime::now_utc().unix_timestamp();

    let store = CloudflareAuthChallengeStore::new(&ctx.env);
    let chal  = Challenge::WebauthnRegister {
        user_id:    state.user_id.clone(),
        challenge:  state.inner["challenge"].as_str().unwrap_or_default().to_owned(),
        expires_at: now + 60,
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
// POST /webauthn/register/finish
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RegisterFinishBody {
    handle:   String,
    response: registration::RegistrationResponse,
}

pub async fn register_finish<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let cfg  = Config::from_env(&ctx.env)?;
    let rp   = rp_from_config(&cfg);

    // Capture the cookie header before consuming the body. We need
    // the pending handle for OAuth flow continuation AND the full
    // header so complete_auth can read the login_next cookie.
    let cookie_header = req.headers().get("cookie").ok().flatten();
    let pending = cookie_header.as_deref()
        .and_then(|h| post_auth::extract_pending_handle(h).map(str::to_owned));

    let body: RegisterFinishBody = match req.json().await {
        Ok(b)  => b,
        Err(_) => return oauth_error_response(&cesauth_core::CoreError::InvalidRequest("body")),
    };

    // Consume the challenge. After this call, a replay of the same
    // handle returns None; this is the single-consumption guarantee.
    let store = CloudflareAuthChallengeStore::new(&ctx.env);
    let chal  = match store.take(&body.handle).await {
        Ok(Some(c)) => c,
        _ => return oauth_error_response(&cesauth_core::CoreError::InvalidRequest("handle")),
    };

    let state = match chal {
        Challenge::WebauthnRegister { user_id, challenge, .. } => registration::RegistrationState {
            inner:   serde_json::json!({ "challenge": challenge }),
            user_id,
        },
        _ => return oauth_error_response(&cesauth_core::CoreError::InvalidRequest("handle not register")),
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let authn = match registration::finish(&rp, &state, &body.response, now) {
        Ok(a)  => a,
        Err(e) => {
            audit::write_owned(
                &ctx.env, EventKind::AuthFailed,
                Some(state.user_id.clone()), None,
                Some(format!("webauthn register finish: {e:?}")),
            ).await.ok();
            return oauth_error_response(&e);
        }
    };

    // Persist the authenticator row. On a storage failure we bail
    // without issuing a session - partial registration is worse than
    // asking the user to retry.
    let repo = CloudflareAuthenticatorRepository::new(&ctx.env);
    if let Err(e) = repo.create(&authn).await {
        audit::write_owned(
            &ctx.env, EventKind::AuthFailed,
            Some(authn.user_id.clone()), None,
            Some(format!("authenticator persist: {e:?}")),
        ).await.ok();
        return oauth_error_response(&cesauth_core::CoreError::Internal);
    }

    audit::write_owned(
        &ctx.env, EventKind::WebauthnRegistered,
        Some(authn.user_id.clone()), None, None,
    ).await.ok();

    // Registration doubles as a first-login: issue a session. If a
    // pending `/authorize` handle was carried on the cookie, honor it.
    post_auth::complete_auth(
        &ctx.env, &cfg, &authn.user_id, AuthMethod::Passkey,
        pending.as_deref(), cookie_header.as_deref(),
    ).await
}
