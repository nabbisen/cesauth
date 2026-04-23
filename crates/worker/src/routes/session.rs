//! Session management endpoints.
//!
//! Currently exactly one: `POST /logout`. It revokes the caller's
//! `ActiveSession` (so any `/authorize` hit from the same browser
//! hereafter falls through to the login page) and clears both the
//! session and pending-authorize cookies.
//!
//! The revocation is authoritative: subsequent `/authorize` hits
//! consult `ActiveSessionStore::status` and see `Revoked`. Refresh
//! tokens tied to the same session are NOT revoked automatically here;
//! that is the job of `/revoke` (RFC 7009). Wire-up between the two is
//! on the roadmap.

use cesauth_cf::ports::store::CloudflareActiveSessionStore;
use cesauth_core::ports::store::ActiveSessionStore;
use cesauth_core::session::{self, SessionCookie};
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::config::load_session_cookie_key;
use crate::post_auth;

/// `POST /logout`. Always returns 302 `/` with clearing Set-Cookie
/// headers, even if the user had no session. Logging out when you're
/// already logged out is not an error.
pub async fn logout<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // Best-effort: pull the cookie, verify MAC, revoke at the DO.
    // Every failure mode (no cookie, bad MAC, expired, DO unavailable)
    // is silently tolerated - we still want to clear the browser's
    // cookies on the way out.
    let mut subject: Option<String> = None;
    if let Some(cookie_header) = req.headers().get("cookie").ok().flatten() {
        if let Some(wire) = session::extract_from_cookie_header(&cookie_header) {
            if let Ok(key) = load_session_cookie_key(&ctx.env) {
                if let Ok(cookie) = SessionCookie::verify(wire, &key, now) {
                    let sessions = CloudflareActiveSessionStore::new(&ctx.env);
                    let _ = sessions.revoke(&cookie.session_id, now).await;
                    subject = Some(cookie.user_id);
                }
            }
        }
    }

    audit::write_owned(
        &ctx.env, EventKind::SessionRevoked,
        subject, None, None,
    ).await.ok();

    let mut resp = Response::empty()?.with_status(302);
    let h = resp.headers_mut();
    h.set("location", "/").ok();
    h.append("set-cookie", &session::clear_cookie_header()).ok();
    h.append("set-cookie", &post_auth::clear_pending_cookie_header()).ok();
    Ok(resp)
}
