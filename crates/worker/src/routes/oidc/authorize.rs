//! `GET /authorize` - the Authorization Code + PKCE entry point.
//!
//! Three halves (the "two halves" aspiration finally achieved at the
//! cost of a third):
//!   * Already authenticated AND the session is fresh enough AND
//!     `prompt=login` was not asserted: mint an AuthCode immediately,
//!     302 to `redirect_uri?code=...&state=...`.
//!   * Not authenticated (or re-auth required) AND `prompt=none` was
//!     asserted: 302 to `redirect_uri?error=login_required&state=...`
//!     per OIDC §3.1.2.6. No UI is shown.
//!   * Otherwise: validate the AR, park it in the AuthChallenge DO as
//!     a `PendingAuthorize` challenge, drop a short-lived
//!     `__Host-cesauth_pending` cookie carrying the handle, render the
//!     login page. The post-auth handlers (`magic_link::verify`,
//!     `webauthn::authenticate_finish`) consume the pending handle and
//!     complete the code minting via `post_auth::complete_auth`.

use cesauth_cf::ports::{
    repo::CloudflareClientRepository,
    store::{CloudflareActiveSessionStore, CloudflareAuthChallengeStore},
};
use cesauth_core::oidc::authorization::{
    AuthorizationRequest, Prompt, session_satisfies_max_age,
};
use cesauth_core::ports::repo::ClientRepository;
use cesauth_core::ports::store::{
    ActiveSessionStore, AuthChallengeStore, Challenge, SessionStatus,
};
use cesauth_core::session::{self, SessionCookie};
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Request, Response, Result, RouteContext};

use crate::config::{Config, load_session_cookie_key};
use crate::csrf;
use crate::error::oauth_error_response;
use crate::log::{self, Category, Level};
use crate::post_auth;


pub async fn authorize<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let cfg = Config::from_env(&ctx.env)?;
    let url = req.url()?;
    let params: std::collections::HashMap<String, String> =
        url.query_pairs().into_owned().collect();

    let ar = AuthorizationRequest {
        response_type:         params.get("response_type").cloned().unwrap_or_default(),
        client_id:             params.get("client_id").cloned().unwrap_or_default(),
        redirect_uri:          params.get("redirect_uri").cloned().unwrap_or_default(),
        scope:                 params.get("scope").cloned(),
        state:                 params.get("state").cloned(),
        nonce:                 params.get("nonce").cloned(),
        code_challenge:        params.get("code_challenge").cloned().unwrap_or_default(),
        code_challenge_method: params.get("code_challenge_method").cloned().unwrap_or_default(),
        prompt:                params.get("prompt").cloned(),
        max_age:               params.get("max_age").and_then(|s| s.parse::<i64>().ok()),
    };

    log::emit(&cfg.log, Level::Info, Category::Http,
        &format!("/authorize client_id={}", ar.client_id), None);

    // Validate the AR up-front. Any failure here results in an
    // OAuth-style error response; we do NOT park a bad AR.
    let clients = CloudflareClientRepository::new(&ctx.env);
    let client = match clients.find(&ar.client_id).await {
        Ok(Some(c)) => c,
        _ => {
            log::emit(&cfg.log, Level::Warn, Category::Http,
                &format!("unknown client_id={}", ar.client_id), None);
            return oauth_error_response(&cesauth_core::CoreError::InvalidClient);
        }
    };
    let policy = match ar.validate(&client) {
        Ok(p)  => p,
        Err(e) => {
            log::emit(&cfg.log, Level::Info, Category::Http,
                &format!("AR validation failed: {e:?}"), Some(&ar.client_id));
            return oauth_error_response(&e);
        }
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();

    // Resolve the current session (if any). `max_age` + `prompt=login`
    // turn a "valid session" into "still must re-authenticate".
    let session = read_active_session(&req, &ctx.env, now).await;
    let session_usable = match (&session, policy.prompt) {
        // prompt=login explicitly forces re-auth.
        (_, Prompt::Login) => {
            log::emit(&cfg.log, Level::Debug, Category::Session,
                "prompt=login - forcing re-auth",
                session.as_ref().map(|s| s.user_id.as_str()));
            None
        }
        // No session at all.
        (None, _) => None,
        // Session exists. Apply max_age freshness rule.
        (Some(s), _) => {
            if session_satisfies_max_age(s.created_at, policy.max_age, now) {
                Some(s)
            } else {
                log::emit(&cfg.log, Level::Debug, Category::Session,
                    &format!("session stale vs max_age={:?}", policy.max_age),
                    Some(&s.user_id));
                None
            }
        }
    };

    // --- Short-circuit: usable session -> mint code & 302. --------
    if let Some(s) = session_usable {
        let code = Uuid::new_v4().to_string();
        let code_chal = Challenge::AuthCode {
            client_id:             ar.client_id.clone(),
            redirect_uri:          ar.redirect_uri.clone(),
            user_id:               s.user_id.clone(),
            scopes:                ar.scope.as_deref()
                .map(cesauth_core::types::Scopes::parse)
                .unwrap_or_default(),
            nonce:                 ar.nonce.clone(),
            code_challenge:        ar.code_challenge.clone(),
            code_challenge_method: ar.code_challenge_method.clone(),
            issued_at:             now,
            expires_at:            now + cfg.auth_code_ttl_secs,
        };
        let store = CloudflareAuthChallengeStore::new(&ctx.env);
        if let Err(e) = store.put(&code, &code_chal).await {
            log::emit(&cfg.log, Level::Error, Category::Storage,
                &format!("auth-code put failed: {e:?}"), None);
            return oauth_error_response(&cesauth_core::CoreError::Internal);
        }
        let location = build_redirect(&ar.redirect_uri, &code, ar.state.as_deref());
        let mut resp = Response::empty()?.with_status(302);
        resp.headers_mut().set("location", &location).ok();
        log::emit(&cfg.log, Level::Info, Category::Auth,
            "authorize short-circuit - code issued", Some(&s.user_id));
        return Ok(resp);
    }

    // --- prompt=none + no usable session: login_required redirect. ----
    if policy.prompt == Prompt::None {
        log::emit(&cfg.log, Level::Info, Category::Auth,
            "prompt=none with no usable session - login_required",
            Some(&ar.client_id));
        let location = build_error_redirect(
            &ar.redirect_uri, "login_required", ar.state.as_deref(),
        );
        let mut resp = Response::empty()?.with_status(302);
        resp.headers_mut().set("location", &location).ok();
        return Ok(resp);
    }

    // --- Cold path: park the AR and render the login page. --------
    let handle = Uuid::new_v4().to_string();
    let pending = Challenge::PendingAuthorize {
        client_id:             ar.client_id.clone(),
        redirect_uri:          ar.redirect_uri.clone(),
        scope:                 ar.scope.clone(),
        state:                 ar.state.clone(),
        nonce:                 ar.nonce.clone(),
        code_challenge:        ar.code_challenge.clone(),
        code_challenge_method: ar.code_challenge_method.clone(),
        expires_at:            now + cfg.pending_authorize_ttl_secs,
    };
    let store = CloudflareAuthChallengeStore::new(&ctx.env);
    if let Err(e) = store.put(&handle, &pending).await {
        log::emit(&cfg.log, Level::Error, Category::Storage,
            &format!("pending-authorize put failed: {e:?}"), None);
        return oauth_error_response(&cesauth_core::CoreError::Internal);
    }

    let csrf_token = csrf::mint();
    let sitekey = Some(cfg.turnstile_sitekey.as_str()).filter(|s| !s.is_empty());
    // v0.39.0: negotiate locale for the login page rendering.
    let locale = crate::i18n::resolve_locale(&req);
    let html = cesauth_ui::templates::login_page_for(&csrf_token, None, sitekey, locale);
    let mut resp = Response::from_html(html)?;
    // Login page inlines a small script; set an appropriately tight CSP.
    let csp = if sitekey.is_some() {
        "default-src 'self'; \
         script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; \
         frame-src https://challenges.cloudflare.com; \
         connect-src 'self'; \
         style-src 'self' 'unsafe-inline'; \
         base-uri 'none'; frame-ancestors 'none'"
    } else {
        "default-src 'self'; \
         script-src 'self' 'unsafe-inline'; \
         style-src 'self' 'unsafe-inline'; \
         base-uri 'none'; frame-ancestors 'none'"
    };
    let _ = resp.headers_mut().set("content-security-policy", csp);
    // Attach the pending-authorize cookie + CSRF cookie. Multiple
    // Set-Cookie headers must each be appended (worker::Headers supports
    // this via `append`).
    resp.headers_mut().append(
        "set-cookie",
        &post_auth::set_pending_cookie_header(&handle, cfg.pending_authorize_ttl_secs),
    ).ok();
    resp.headers_mut().append("set-cookie", &csrf::set_cookie_header(&csrf_token)).ok();
    log::emit(&cfg.log, Level::Debug, Category::Auth,
        "authorize cold path - AR parked", Some(&ar.client_id));
    Ok(resp)
}

/// If the request carries a valid, non-revoked session cookie, return
/// the session state. On any failure (missing cookie, bad MAC, expired,
/// revoked at the DO), return `None` so the caller falls back to the
/// login flow - we do NOT want a stale cookie to surface as an HTTP
/// error on `/authorize`.
async fn read_active_session(
    req:      &Request,
    env:      &worker::Env,
    now_unix: i64,
) -> Option<cesauth_core::ports::store::SessionState> {
    let cookie_header = req.headers().get("cookie").ok().flatten()?;
    let wire = session::extract_from_cookie_header(&cookie_header)?;

    let key = load_session_cookie_key(env).ok()?;
    let cookie = SessionCookie::verify(wire, &key, now_unix).ok()?;

    let sessions = CloudflareActiveSessionStore::new(env);
    match sessions.status(&cookie.session_id).await {
        Ok(SessionStatus::Active(state)) => Some(state),
        _ => None,
    }
}

/// Build the 302 `Location` URL for a successful authorize. Preserves
/// any existing query in `redirect_uri` by picking `?` vs `&` correctly,
/// and percent-encodes `state` (clients pass arbitrary strings).
fn build_redirect(redirect_uri: &str, code: &str, state: Option<&str>) -> String {
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut out = format!("{redirect_uri}{sep}code={code}");
    if let Some(s) = state {
        out.push_str("&state=");
        out.push_str(&url_encode_component(s));
    }
    out
}

/// Build the 302 `Location` URL for an error response. Per OIDC
/// §3.1.2.6, errors encountered after `redirect_uri` is validated are
/// returned by redirecting to the client, NOT by rendering them to the
/// user directly. Shape: `?error=<code>&state=<state>`.
fn build_error_redirect(redirect_uri: &str, error_code: &str, state: Option<&str>) -> String {
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut out = format!("{redirect_uri}{sep}error={error_code}");
    if let Some(s) = state {
        out.push_str("&state=");
        out.push_str(&url_encode_component(s));
    }
    out
}

fn url_encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
