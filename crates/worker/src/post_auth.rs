//! Post-authentication completion.
//!
//! The magic-link verify, webauthn authenticate, and (eventually)
//! any other "user successfully proved who they are" path all need to
//! do the same three things:
//!
//! 1. Start an `ActiveSession` DO and set a signed session cookie.
//! 2. If there was a parked `/authorize` request (a "PendingAuthorize"
//!    challenge in the DO referenced by a short-lived handle on the
//!    client), mint an `AuthCode` and 302 to `redirect_uri`.
//! 3. Otherwise, land the user on the home page.
//!
//! Keeping this in one place means the three auth paths are guaranteed
//! to give the same browser experience on success.
//!
//! The handler also manages a **`cesauth_pending`** cookie - a short-
//! lived unsigned breadcrumb that carries the handle of the parked AR.
//! It's not security-critical: the parked AR itself is behind the DO,
//! and the cookie is only a pointer. The attacker-controlled value of
//! this pointer bounds what mischief they can do to "redirect back to
//! whatever redirect_uri was registered for whatever client they
//! guessed a handle for", which is no worse than they could do by
//! guessing the handle directly.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cesauth_cf::ports::store::CloudflareAuthChallengeStore;
use cesauth_core::ports::store::{
    ActiveSessionStore, AuthChallengeStore, AuthMethod, Challenge, SessionState,
};
use cesauth_core::session::{self, SessionCookie};
use cesauth_core::totp::storage::TotpAuthenticatorRepository;
use cesauth_core::types::Scopes;
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Env, Response, Result};

use crate::config::{Config, load_session_cookie_key};

/// Short-lived pending-authorize cookie. Unsigned: see module docs.
pub const PENDING_COOKIE_NAME: &str = "__Host-cesauth_pending";

/// Build a `Set-Cookie` for the pending-authorize breadcrumb. We reuse
/// the same attribute set as the real session cookie - `__Host-` etc.
pub fn set_pending_cookie_header(handle: &str, ttl_secs: i64) -> String {
    let max_age = ttl_secs.max(0);
    format!(
        "{PENDING_COOKIE_NAME}={handle}; Max-Age={max_age}; Path=/; HttpOnly; Secure; SameSite=Lax"
    )
}

/// Zero-out the pending-authorize cookie.
pub fn clear_pending_cookie_header() -> String {
    format!("{PENDING_COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax")
}

/// Extract the pending-authorize handle from a raw `Cookie:` header.
pub fn extract_pending_handle(cookie_header: &str) -> Option<&str> {
    for piece in cookie_header.split(';') {
        let piece = piece.trim();
        if let Some(rest) = piece.strip_prefix(PENDING_COOKIE_NAME) {
            if let Some(v) = rest.strip_prefix('=') {
                return Some(v);
            }
        }
    }
    None
}

// =====================================================================
// TOTP gate cookie (__Host-cesauth_totp). v0.29.0+.
// =====================================================================

/// Short-lived TOTP-gate cookie. Unsigned. Carries the handle of a
/// `Challenge::PendingTotp` parked by `complete_auth` when the
/// post-MagicLink gate fires.
///
/// SameSite=Strict because the TOTP prompt is the user's
/// authenticated state; cross-site requests should never carry this
/// cookie. (The session cookie uses Lax to support OAuth redirect
/// flows, but the TOTP cookie is purely an internal-route
/// breadcrumb between gate-park and verify-resume — no cross-site
/// flow is involved.)
pub const TOTP_COOKIE_NAME: &str = "__Host-cesauth_totp";

/// Build a `Set-Cookie` for the TOTP-gate breadcrumb.
pub fn set_totp_cookie_header(handle: &str, ttl_secs: i64) -> String {
    let max_age = ttl_secs.max(0);
    format!(
        "{TOTP_COOKIE_NAME}={handle}; Max-Age={max_age}; Path=/; HttpOnly; Secure; SameSite=Strict"
    )
}

/// Zero-out the TOTP-gate cookie.
pub fn clear_totp_cookie_header() -> String {
    format!("{TOTP_COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict")
}

/// Extract the TOTP-gate handle from a raw `Cookie:` header.
pub fn extract_totp_handle(cookie_header: &str) -> Option<&str> {
    for piece in cookie_header.split(';') {
        let piece = piece.trim();
        if let Some(rest) = piece.strip_prefix(TOTP_COOKIE_NAME) {
            if let Some(v) = rest.strip_prefix('=') {
                return Some(v);
            }
        }
    }
    None
}

/// TTL for a parked `PendingTotp` challenge. Long enough that a
/// user fumbling with their authenticator app has time to read the
/// code; short enough that an abandoned TOTP prompt doesn't tie up
/// AR state forever. 5 minutes matches the typical TOTP step
/// tolerance window of a few minutes plus generous user-fumble
/// time.
pub const TOTP_GATE_TTL_SECS: i64 = 300;

// =====================================================================
// TOTP enrollment cookie (__Host-cesauth_totp_enroll). v0.29.0+.
// =====================================================================

/// Short-lived enrollment cookie. Carries the id of the unconfirmed
/// `totp_authenticators` row created at GET /me/security/totp/enroll
/// so the POST /confirm handler knows which row to flip.
///
/// Unsigned: the id is a UUID and the row is per-user (the confirm
/// handler additionally verifies the row belongs to the calling
/// session's user_id, so a forged cookie pointing at someone else's
/// row would fail the user_id ownership check).
///
/// SameSite=Strict for the same reason as the gate cookie — purely
/// internal-route breadcrumb, no cross-site flow.
pub const TOTP_ENROLL_COOKIE_NAME: &str = "__Host-cesauth_totp_enroll";

pub fn set_totp_enroll_cookie_header(authenticator_id: &str, ttl_secs: i64) -> String {
    let max_age = ttl_secs.max(0);
    format!(
        "{TOTP_ENROLL_COOKIE_NAME}={authenticator_id}; Max-Age={max_age}; Path=/; HttpOnly; Secure; SameSite=Strict"
    )
}

pub fn clear_totp_enroll_cookie_header() -> String {
    format!("{TOTP_ENROLL_COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict")
}

pub fn extract_totp_enroll_id(cookie_header: &str) -> Option<&str> {
    for piece in cookie_header.split(';') {
        let piece = piece.trim();
        if let Some(rest) = piece.strip_prefix(TOTP_ENROLL_COOKIE_NAME) {
            if let Some(v) = rest.strip_prefix('=') {
                return Some(v);
            }
        }
    }
    None
}

/// TTL for the enrollment cookie. Generous (15 minutes) since
/// enrollment is a one-time interactive flow where the user
/// switches to their authenticator app, scans, and returns —
/// app-switch context cost can be substantial.
pub const TOTP_ENROLL_TTL_SECS: i64 = 900;

/// Finalize authentication. Issues the session cookie and, if there is
/// a parked `PendingAuthorize`, mints an AuthCode and redirects to the
/// client's `redirect_uri`.
///
/// Returns a `Response` that the caller should return verbatim.
///
/// Arguments:
///
/// * `env`: the Workers `Env`.
/// * `cfg`: pre-loaded config.
/// * `user_id`: authenticated user.
/// * `auth_method`: how they authenticated (for session record + audit).
/// * `pending_handle`: value of the `__Host-cesauth_pending` cookie if
///   the request carried one. Pass `None` if there was no AR parked.
/// * `cookie_header`: full incoming `Cookie` header (or `None`). Used
///   by the no-AR landing path to read `__Host-cesauth_login_next`
///   set by the login GET handler — see plan v2 §3.2 P1-A.
pub async fn complete_auth(
    env:            &Env,
    cfg:            &Config,
    user_id:        &str,
    auth_method:    AuthMethod,
    pending_handle: Option<&str>,
    cookie_header:  Option<&str>,
) -> Result<Response> {
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // 1. Resolve the parked AR, if any.
    let pending = match pending_handle {
        Some(h) if !h.is_empty() => {
            let store = CloudflareAuthChallengeStore::new(env);
            match store.take(h).await {
                Ok(Some(Challenge::PendingAuthorize {
                    client_id, redirect_uri, scope, state, nonce,
                    code_challenge, code_challenge_method, ..
                })) => Some(PendingAr {
                    client_id, redirect_uri, scope, state, nonce,
                    code_challenge, code_challenge_method,
                }),
                _ => None,
            }
        }
        _ => None,
    };

    // 1.5. TOTP gate (v0.29.0+, ADR-009 §Q7). Per ADR-009 §Q7,
    // TOTP is always a 2nd factor on top of MagicLink. WebAuthn
    // alone is itself MFA-strong (device possession + on-device
    // user verification) so we don't double-prompt; admin auth
    // is bearer-token only and doesn't go through `complete_auth`
    // anyway. Anonymous never has TOTP enrolled.
    if matches!(auth_method, AuthMethod::MagicLink) {
        let totp_repo = cesauth_cf::ports::repo::CloudflareTotpAuthenticatorRepository::new(env);
        match totp_repo.find_active_for_user(user_id).await {
            Ok(Some(_)) => {
                // The user has a confirmed TOTP authenticator.
                // Park `PendingTotp` carrying the resolved AR
                // fields, set the gate cookie, redirect to the
                // prompt page. The original AR has already been
                // taken (consumed) above; carrying its fields
                // inline rather than referencing the original
                // handle avoids a race where the AR could expire
                // between gate-park and verify-resume.
                return park_totp_gate_and_redirect(env, user_id, auth_method, pending, now).await;
            }
            Ok(None) => {
                // User has no confirmed TOTP authenticator. Fall
                // through to the standard post-gate flow.
            }
            Err(_) => {
                // Storage failure on the TOTP lookup. Fail
                // closed: refuse to proceed without knowing
                // whether TOTP was required. The user sees a
                // 500-style page and the next attempt either
                // succeeds (transient) or stays broken (operator
                // attention).
                return Err(worker::Error::RustError(
                    "totp authenticator lookup failed".into()
                ));
            }
        }
    }

    // 2+3 — post-gate session start and AR resolution.
    complete_auth_post_gate(env, cfg, user_id, auth_method, pending, cookie_header).await
}

/// Park a `Challenge::PendingTotp` containing the resolved AR
/// fields, set the `__Host-cesauth_totp` cookie, and 302-redirect
/// to the verify prompt page. Called by `complete_auth` when the
/// post-MagicLink gate fires.
///
/// Critically, this does NOT call `complete_auth_post_gate` — no
/// session is started yet. The session start happens in the
/// verify route's POST handler, after the user proves possession
/// of the TOTP secret.
async fn park_totp_gate_and_redirect(
    env:         &Env,
    user_id:     &str,
    auth_method: AuthMethod,
    pending:     Option<PendingAr>,
    now:         i64,
) -> Result<Response> {
    let totp_handle = Uuid::new_v4().to_string();
    let challenge = Challenge::PendingTotp {
        user_id:                  user_id.to_owned(),
        auth_method,
        ar_client_id:             pending.as_ref().map(|p| p.client_id.clone()),
        ar_redirect_uri:          pending.as_ref().map(|p| p.redirect_uri.clone()),
        ar_scope:                 pending.as_ref().and_then(|p| p.scope.clone()),
        ar_state:                 pending.as_ref().and_then(|p| p.state.clone()),
        ar_nonce:                 pending.as_ref().and_then(|p| p.nonce.clone()),
        ar_code_challenge:        pending.as_ref().map(|p| p.code_challenge.clone()),
        ar_code_challenge_method: pending.as_ref().map(|p| p.code_challenge_method.clone()),
        attempts:                 0,
        expires_at:               now + TOTP_GATE_TTL_SECS,
    };

    let store = CloudflareAuthChallengeStore::new(env);
    store.put(&totp_handle, &challenge).await
        .map_err(|_| worker::Error::RustError("totp challenge store failed".into()))?;

    let totp_cookie    = set_totp_cookie_header(&totp_handle, TOTP_GATE_TTL_SECS);
    let clear_pending  = clear_pending_cookie_header();

    let mut resp = Response::empty()?.with_status(302);
    let h = resp.headers_mut();
    h.set("location", "/me/security/totp/verify").ok();
    h.append("set-cookie", &totp_cookie).ok();
    // Clear the original pending cookie because the AR fields
    // are now carried inside the PendingTotp challenge; the
    // pending handle no longer needs to round-trip.
    h.append("set-cookie", &clear_pending).ok();
    Ok(resp)
}

/// Post-gate completion. Called by `complete_auth` directly when
/// no TOTP gate fires, OR by the TOTP verify route after the user
/// proves possession of their secret. Identical behavior in both
/// cases: start the session, mint AuthCode if AR present, redirect.
///
/// This is the original body of `complete_auth` from before v0.29.0,
/// extracted unchanged so the verify route can call it as a
/// continuation. The `pending` argument is the resolved
/// PendingAuthorize fields (already taken from the challenge store
/// in `complete_auth`'s step 1, or reconstructed from the
/// `PendingTotp` challenge in the verify route).
pub(crate) async fn complete_auth_post_gate(
    env:           &Env,
    cfg:           &Config,
    user_id:       &str,
    auth_method:   AuthMethod,
    pending:       Option<PendingAr>,
    cookie_header: Option<&str>,
) -> Result<Response> {
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // 2. Start the session.
    let session_id = Uuid::new_v4().to_string();
    let session = SessionState {
        session_id:   session_id.clone(),
        user_id:      user_id.to_owned(),
        client_id:    pending.as_ref().map(|p| p.client_id.clone()).unwrap_or_default(),
        scopes:       pending.as_ref().and_then(|p| p.scope.clone())
                          .map(|s| Scopes::parse(&s).0).unwrap_or_default(),
        auth_method,
        created_at:   now,
        last_seen_at: now,
        revoked_at:   None,
    };
    let session_store = cesauth_cf::ports::store::CloudflareActiveSessionStore::new(env);
    session_store.start(&session).await
        .map_err(|_| worker::Error::RustError("active session store unavailable".into()))?;

    let cookie = SessionCookie {
        session_id:  session_id.clone(),
        user_id:     user_id.to_owned(),
        auth_method,
        issued_at:   now,
        expires_at:  now + cfg.session_ttl_secs,
    };
    let cookie_key = load_session_cookie_key(env)?;
    let cookie_value = cookie.sign(&cookie_key)
        .map_err(|_| worker::Error::RustError("session cookie sign failed".into()))?;

    let set_session   = session::set_cookie_header(&cookie_value, cfg.session_ttl_secs);
    let clear_pending = clear_pending_cookie_header();
    let clear_totp    = clear_totp_cookie_header();

    // 3. Either mint a code and redirect, or land on "/".
    match pending {
        Some(ar) => {
            // Mint the AuthCode handle and park the real Challenge.
            let code = Uuid::new_v4().to_string();
            let code_chal = Challenge::AuthCode {
                client_id:             ar.client_id.clone(),
                redirect_uri:          ar.redirect_uri.clone(),
                user_id:               user_id.to_owned(),
                scopes:                ar.scope.as_deref().map(Scopes::parse).unwrap_or_default(),
                nonce:                 ar.nonce,
                code_challenge:        ar.code_challenge,
                code_challenge_method: ar.code_challenge_method,
                issued_at:             now,
                expires_at:            now + cfg.auth_code_ttl_secs,
            };
            let store = CloudflareAuthChallengeStore::new(env);
            store.put(&code, &code_chal).await
                .map_err(|_| worker::Error::RustError("auth-code store failed".into()))?;

            // Build redirect URL. We append `code` and `state`;
            // anything already in the client's `redirect_uri` is
            // preserved because we use `?` / `&` correctly.
            let sep = if ar.redirect_uri.contains('?') { '&' } else { '?' };
            let mut location = format!(
                "{}{}code={}",
                ar.redirect_uri,
                sep,
                URL_SAFE_NO_PAD.encode(code.as_bytes())
            );
            // We URL-encode `state` since clients are known to pass
            // strings that contain '&' or '#'.
            if let Some(s) = ar.state.as_deref() {
                location.push('&');
                location.push_str("state=");
                location.push_str(&url_encode_component(s));
            }

            // 302 with both Set-Cookie headers. Multiple Set-Cookie is
            // required to be sent as separate headers; worker::Headers
            // supports `append`.
            let mut resp = Response::empty()?
                .with_status(302);
            let h = resp.headers_mut();
            h.set("location", &location).ok();
            h.append("set-cookie", &set_session).ok();
            h.append("set-cookie", &clear_pending).ok();
            h.append("set-cookie", &clear_totp).ok();
            Ok(resp)
        }

        None => {
            // No AR was parked. Land at the validated next-target
            // if one was stashed by the login GET handler, else
            // at `/`. Either way, clear the login_next cookie so
            // it's a one-shot — a stale next from a prior session
            // shouldn't redirect a fresh login.
            let landing = cookie_header
                .and_then(|h| crate::routes::me::auth::extract_login_next(h)
                    .map(str::to_owned))
                .and_then(|encoded| crate::routes::me::auth::decode_and_validate_next(&encoded))
                .unwrap_or_else(|| "/".to_owned());
            let mut resp = Response::empty()?
                .with_status(302);
            let h = resp.headers_mut();
            h.set("location", &landing).ok();
            h.append("set-cookie", &set_session).ok();
            h.append("set-cookie", &clear_pending).ok();
            h.append("set-cookie", &clear_totp).ok();
            // Always clear the login_next cookie — even if it
            // wasn't present we emit the clear header (idempotent).
            h.append("set-cookie",
                &crate::routes::me::auth::clear_login_next_cookie_header()).ok();
            Ok(resp)
        }
    }
}

/// Minimal percent-encoding for the fragment of a URL's query we
/// build. We do NOT use `url::form_urlencoded::byte_serialize`
/// directly because it uses `+` for spaces, which some clients parse
/// strictly - RFC 3986 `%20` is safer in a query string component.
fn url_encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => out.push(*b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub(crate) struct PendingAr {
    pub(crate) client_id:             String,
    pub(crate) redirect_uri:          String,
    pub(crate) scope:                 Option<String>,
    pub(crate) state:                 Option<String>,
    pub(crate) nonce:                 Option<String>,
    pub(crate) code_challenge:        String,
    pub(crate) code_challenge_method: String,
}

#[cfg(test)]
mod tests;
