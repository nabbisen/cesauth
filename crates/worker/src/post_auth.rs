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
pub async fn complete_auth(
    env:            &Env,
    cfg:            &Config,
    user_id:        &str,
    auth_method:    AuthMethod,
    pending_handle: Option<&str>,
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

    let set_session = session::set_cookie_header(&cookie_value, cfg.session_ttl_secs);
    let clear_pending = clear_pending_cookie_header();

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
            Ok(resp)
        }

        None => {
            // No AR was parked. Land on `/` with a session cookie set.
            // This is the flow for a user who hit `/login` directly.
            let mut resp = Response::empty()?
                .with_status(302);
            let h = resp.headers_mut();
            h.set("location", "/").ok();
            h.append("set-cookie", &set_session).ok();
            h.append("set-cookie", &clear_pending).ok();
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

struct PendingAr {
    client_id:             String,
    redirect_uri:          String,
    scope:                 Option<String>,
    state:                 Option<String>,
    nonce:                 Option<String>,
    code_challenge:        String,
    code_challenge_method: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_cookie_header_shape() {
        let h = set_pending_cookie_header("abc-123", 600);
        assert!(h.starts_with(&format!("{PENDING_COOKIE_NAME}=abc-123")));
        assert!(h.contains("HttpOnly"));
        assert!(h.contains("Secure"));
    }

    #[test]
    fn extract_pending_handle_present() {
        let h = format!("other=1; {PENDING_COOKIE_NAME}=my-handle; more=2");
        assert_eq!(extract_pending_handle(&h), Some("my-handle"));
    }

    #[test]
    fn url_encode_component_encodes_reserved() {
        assert_eq!(url_encode_component("a b"), "a%20b");
        assert_eq!(url_encode_component("a&b"), "a%26b");
        assert_eq!(url_encode_component("ABCxyz-._~0"), "ABCxyz-._~0");
    }
}
