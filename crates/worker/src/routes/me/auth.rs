//! Authentication helper for `/me/*` routes.
//!
//! All `/me/*` routes are user-cookie-authenticated via the
//! `__Host-cesauth_session` cookie. Unlike `/admin/*` (bearer
//! token only) and `/oauth/*` (RP credentials), `/me/*` is the
//! end-user's self-service surface and must accept exactly the
//! session cookie shape the rest of the user-facing flow uses.
//!
//! This helper centralizes the read-and-verify path so each
//! route handler just gets back a `SessionState` (or a 302
//! response to forward).

use cesauth_core::ports::store::{ActiveSessionStore, SessionState, SessionStatus};
use cesauth_core::session::{self, SessionCookie};
use time::OffsetDateTime;
use worker::{Request, Response, Result};

use crate::config::load_session_cookie_key;


/// Build a 302 response redirecting to `/login`. Used as the
/// "not signed in" outcome for `/me/*` GETs. POSTs that hit an
/// unauthenticated state should also use this — the user's
/// browser was carrying a stale or absent cookie, and sending
/// them back to `/login` is the right rescue.
pub fn redirect_to_login() -> Result<Response> {
    let mut resp = Response::empty()?;
    resp.headers_mut().set("location", "/login")?;
    Ok(resp.with_status(302))
}


/// Resolve the active session for an incoming `/me/*` request.
///
/// Returns:
/// - `Ok(Ok(SessionState))` when the cookie verifies and the
///   session is `Active`.
/// - `Ok(Err(Response))` when the request is unauthenticated.
///   The Response is a 302 redirect to `/login`. The route
///   handler returns this directly.
/// - `Err(worker::Error)` only for genuine infrastructure
///   failures (cookie key missing — operator misconfig).
///
/// This shape (Result<Result>) matches what
/// `crate::admin::auth::resolve_or_respond` does for admin
/// routes — it lets the caller distinguish "user not signed
/// in, here's the response to send" from "something really
/// went wrong".
///
/// Note: this checks the session is `Active` server-side. A
/// session that's been revoked (logout, admin-kicked, store
/// cleared) returns `Ok(Err(redirect))` even if the cookie
/// itself signs cleanly. The `/me/*` surface MUST gate on
/// server-side liveness, not just cookie integrity.
pub async fn resolve_or_redirect(
    req: &Request,
    env: &worker::Env,
) -> Result<core::result::Result<SessionState, Response>> {
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // Cookie header missing → not signed in.
    let cookie_header = match req.headers().get("cookie")? {
        Some(h) => h,
        None    => return Ok(Err(redirect_to_login()?)),
    };

    // No session cookie among the headers → not signed in.
    let wire = match session::extract_from_cookie_header(&cookie_header) {
        Some(w) => w,
        None    => return Ok(Err(redirect_to_login()?)),
    };

    // Bad signature / expired → not signed in. We don't
    // distinguish in the redirect — the user lands at /login
    // either way. Avoiding distinction also avoids surfacing
    // detail an attacker could probe.
    let key = load_session_cookie_key(env)?;
    let cookie = match SessionCookie::verify(wire, &key, now) {
        Ok(c)  => c,
        Err(_) => return Ok(Err(redirect_to_login()?)),
    };

    // Server-side liveness: even a clean-signing cookie may
    // refer to a revoked session.
    let sessions = cesauth_cf::ports::store::CloudflareActiveSessionStore::new(env);
    match sessions.status(&cookie.session_id).await {
        Ok(SessionStatus::Active(state)) => Ok(Ok(state)),
        Ok(_) | Err(_) => Ok(Err(redirect_to_login()?)),
    }
}
