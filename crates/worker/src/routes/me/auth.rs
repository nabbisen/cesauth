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
//!
//! ## `next` parameter (v0.31.0 P1-A)
//!
//! When a user hits `/me/security` directly without a session,
//! we 302 them to `/login?next=<base64url(/me/security)>`. The
//! login GET handler stores the validated path in
//! `__Host-cesauth_login_next` so it survives the
//! sign-in flow. After successful auth, `complete_auth_post_gate`
//! consults the cookie when no `PendingAuthorize` is in scope
//! and redirects the user there.
//!
//! ### Validation policy
//!
//! [`validate_next_path`] is a pure function with the
//! `/me/*` + `/` allowlist policy from plan v2 §3.2 P1-A. It
//! intentionally rejects:
//!
//! - any URL with a scheme (`https://...`, `javascript:`, `data:`)
//! - protocol-relative URLs (`//evil.com`)
//! - Windows UNC paths (`\\evil`)
//! - paths outside the allowlist (`/admin/*`, `/api/*`, `/login`,
//!   `/__dev/*`, etc.)
//!
//! The fallback for any rejection is `/`, which is always safe.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cesauth_core::ports::store::{ActiveSessionStore, SessionState, SessionStatus};
use cesauth_core::session::{self, SessionCookie};
use time::OffsetDateTime;
use worker::{Request, Response, Result};

use crate::config::{Config, load_session_cookie_key};


/// Cookie name carrying the post-login `next` target. Short TTL
/// because the user must complete sign-in within that window;
/// otherwise they fall back to the default landing.
pub const LOGIN_NEXT_COOKIE: &str = "__Host-cesauth_login_next";
/// 5 minutes. Same shape as the OAuth pending cookie's TTL.
pub const LOGIN_NEXT_TTL_SECS: i64 = 300;


/// Build a 302 response redirecting to `/login` with no `next`
/// hint. Used when there's no meaningful "back to" target —
/// e.g., a TOTP gate cookie that's already expired (the user
/// is mid-MFA, not navigating to a `/me/*` page).
pub fn redirect_to_login() -> Result<Response> {
    let mut resp = Response::empty()?;
    resp.headers_mut().set("location", "/login")?;
    Ok(resp.with_status(302))
}


/// Build a 302 response redirecting to `/login?next=<encoded>`,
/// where `<encoded>` is a base64url of the current path + query
/// (validated against [`validate_next_path`] before encoding;
/// invalid → no `next` parameter, plain `/login`).
///
/// Used by [`resolve_or_redirect`] when an unauthenticated
/// request arrives at a `/me/*` page that the user is trying
/// to reach. After they sign in, `complete_auth_post_gate`
/// honors the `next` cookie set by the login GET handler.
pub fn redirect_to_login_with_next(req: &Request) -> Result<Response> {
    let mut resp = Response::empty()?;
    let target = match build_next_query(req) {
        Some(q) => format!("/login?{q}"),
        None    => "/login".to_owned(),
    };
    resp.headers_mut().set("location", &target)?;
    Ok(resp.with_status(302))
}

/// Extract the path + query from a request. Returns `None` if
/// the URL parses oddly or the path isn't allowlisted (no
/// fallback URL to encode).
fn build_next_query(req: &Request) -> Option<String> {
    let url = req.url().ok()?;
    // Reconstruct path + (optional) query. Origin is intentionally
    // dropped — `next` is a same-origin path-relative target by
    // design.
    let mut s = String::with_capacity(url.path().len() + 64);
    s.push_str(url.path());
    if let Some(q) = url.query() {
        if !q.is_empty() {
            s.push('?');
            s.push_str(q);
        }
    }
    // Validate before encoding. If the path isn't allowlisted,
    // don't bother round-tripping it — the post-login resolver
    // would reject it anyway and we'd just be carrying garbage.
    validate_next_path(&s)?;
    Some(format!("next={}", URL_SAFE_NO_PAD.encode(s.as_bytes())))
}

/// Validate a `next` path string. Returns `Some(raw)` when the
/// path is safe to use as a same-origin redirect target, else
/// `None` (caller should fall back to `/`).
///
/// Allowlist (plan v2 §3.2 P1-A):
///
/// - exactly `/`
/// - exactly `/me`
/// - any path starting with `/me/`
///
/// Reject reasons:
///
/// - **Scheme present** (`https:`, `javascript:`, `data:`,
///   `mailto:`, etc.) — `:` anywhere fails. (A path-only string
///   like `/me/security` never contains `:` since query strings
///   are checked separately by the URL parser.)
/// - **Protocol-relative** (`//evil.com/foo`).
/// - **Windows UNC** (`\\evil\share`) — pin so a Windows-only
///   parser quirk can't be smuggled past us.
/// - **Path outside the allowlist** — `/admin/*`, `/api/*`,
///   `/login`, `/__dev/*`, etc. — admin and API surfaces aren't
///   meaningful as a browser landing target after sign-in, and
///   bouncing to admin would mix a session-cookie context with
///   bearer-token auth.
///
/// The function operates on the raw path portion. Query string
/// is allowed (e.g., `/me/security?foo=bar`). Fragments aren't
/// expected — browsers don't transmit them — but if present in
/// the path they're treated as part of the path string.
pub fn validate_next_path(raw: &str) -> Option<&str> {
    // Empty input is not a path. (`""` would also pass the
    // `!starts_with('/')` check below, but pinning the empty
    // case explicitly makes the failure mode explicit.)
    if raw.is_empty() {
        return None;
    }
    // Protocol-relative URL — `//evil.com/foo`. Must come BEFORE
    // the `starts_with('/')` check.
    if raw.starts_with("//") {
        return None;
    }
    // Windows UNC paths.
    if raw.starts_with("\\\\") {
        return None;
    }
    // Any scheme — `https:`, `javascript:`, `data:`, `file:`,
    // `mailto:`. A path that legitimately needs a colon would
    // be a strange case (`/me/x:y`) — we'd rather fail-safe.
    if raw.contains(':') {
        return None;
    }
    // Must be a path-relative target.
    if !raw.starts_with('/') {
        return None;
    }
    // Allowlist: split on `?` to inspect path only.
    let path = raw.split('?').next().unwrap_or(raw);
    if path == "/" || path == "/me" || path.starts_with("/me/") {
        return Some(raw);
    }
    None
}

/// Decode a `next` value (base64url-encoded path) and validate
/// it. Used by `complete_auth_post_gate` when consuming the
/// login_next cookie. Returns `None` on any decoding or
/// validation failure — caller falls back to `/`.
pub fn decode_and_validate_next(encoded: &str) -> Option<String> {
    let raw_bytes = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).ok()?;
    let raw = String::from_utf8(raw_bytes).ok()?;
    validate_next_path(&raw)?;
    Some(raw)
}

/// `Set-Cookie` value that stores the validated `next` path for
/// the duration of the sign-in flow.
pub fn set_login_next_cookie_header(value: &str) -> String {
    format!(
        "{LOGIN_NEXT_COOKIE}={value}; Max-Age={LOGIN_NEXT_TTL_SECS}; \
         Path=/; HttpOnly; Secure; SameSite=Lax"
    )
}

/// `Set-Cookie` value that clears the login_next cookie.
pub fn clear_login_next_cookie_header() -> String {
    format!(
        "{LOGIN_NEXT_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax"
    )
}

/// Find the value of the login_next cookie in a `Cookie:` header.
pub fn extract_login_next<'a>(cookie_header: &'a str) -> Option<&'a str> {
    for piece in cookie_header.split(';') {
        let piece = piece.trim();
        if let Some(rest) = piece.strip_prefix(LOGIN_NEXT_COOKIE) {
            if let Some(v) = rest.strip_prefix('=') {
                return Some(v);
            }
        }
    }
    None
}


/// Resolve the active session for an incoming `/me/*` request.
///
/// Returns:
/// - `Ok(Ok(SessionState))` when the cookie verifies and the
///   session is `Active`.
/// - `Ok(Err(Response))` when the request is unauthenticated.
///   The Response is a 302 redirect to `/login?next=...`. The
///   route handler returns this directly. As of v0.31.0 the
///   `next` query parameter carries the user's original target
///   so they land back on the page they tried to visit.
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
        None    => return Ok(Err(redirect_to_login_with_next(req)?)),
    };

    // No session cookie among the headers → not signed in.
    let wire = match session::extract_from_cookie_header(&cookie_header) {
        Some(w) => w,
        None    => return Ok(Err(redirect_to_login_with_next(req)?)),
    };

    // Bad signature / expired → not signed in. We don't
    // distinguish in the redirect — the user lands at /login
    // either way. Avoiding distinction also avoids surfacing
    // detail an attacker could probe.
    let key = load_session_cookie_key(env)?;
    let cookie = match SessionCookie::verify(wire, &key, now) {
        Ok(c)  => c,
        Err(_) => return Ok(Err(redirect_to_login_with_next(req)?)),
    };

    // Server-side liveness: even a clean-signing cookie may
    // refer to a revoked session.
    //
    // **v0.35.0** — Switched from `status()` to `touch()` so
    // the idle and absolute timeouts are consulted on every
    // authenticated request. The DO-side check is atomic with
    // the touch update; on idle/absolute expiry the DO sets
    // revoked_at and returns the new variant.
    //
    // We bounce ALL non-Active outcomes (Revoked, IdleExpired,
    // AbsoluteExpired, NotStarted) to /login. The variants are
    // distinct so a follow-up audit-write in the worker can
    // emit a different `EventKind` per cause; the user
    // experience is the same redirect.
    let cfg      = Config::from_env(env)?;
    let sessions = cesauth_cf::ports::store::CloudflareActiveSessionStore::new(env);
    let outcome = sessions.touch(
        &cookie.session_id,
        now,
        cfg.session_idle_timeout_secs,
        cfg.session_ttl_secs,
    ).await;

    match outcome {
        Ok(SessionStatus::Active(state)) => Ok(Ok(state)),
        Ok(SessionStatus::IdleExpired(state)) => {
            // v0.35.0: emit audit so operators can monitor the
            // idle-timeout signal separately from explicit
            // revocation. Best-effort — auth must still bounce
            // the user to /login regardless of audit success.
            let payload = serde_json::json!({
                "session_id":   state.session_id,
                "idle_secs":    cfg.session_idle_timeout_secs,
                "last_seen_at": state.last_seen_at,
                "now":          now,
            }).to_string();
            crate::audit::write_owned(
                env, crate::audit::EventKind::SessionIdleTimeout,
                Some(state.user_id), Some(state.client_id),
                Some(payload),
            ).await.ok();
            Ok(Err(redirect_to_login_with_next(req)?))
        }
        Ok(SessionStatus::AbsoluteExpired(state)) => {
            let payload = serde_json::json!({
                "session_id":  state.session_id,
                "ttl_secs":    cfg.session_ttl_secs,
                "created_at":  state.created_at,
                "now":         now,
            }).to_string();
            crate::audit::write_owned(
                env, crate::audit::EventKind::SessionAbsoluteTimeout,
                Some(state.user_id), Some(state.client_id),
                Some(payload),
            ).await.ok();
            Ok(Err(redirect_to_login_with_next(req)?))
        }
        Ok(SessionStatus::Revoked(_) | SessionStatus::NotStarted) | Err(_) => {
            Ok(Err(redirect_to_login_with_next(req)?))
        }
    }
}

#[cfg(test)]
mod tests;
