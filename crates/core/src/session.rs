//! Session cookies.
//!
//! A session cookie is the bearer marker that proves the current browser
//! has authenticated, so that the next `/authorize` call can skip the
//! login UI. The cookie body is opaque to the client and integrity-
//! protected by an HMAC-SHA256 tag over the payload. The payload itself
//! is a tiny JSON blob:
//!
//! ```json
//! {"session_id":"...","user_id":"...","issued_at":1700000000,"expires_at":1700003600}
//! ```
//!
//! Format: `b64url(payload_json) "." b64url(hmac)`. No Base32, no CBOR -
//! this is intentionally the most boring format we could pick.
//!
//! ## Why HMAC and not a signed JWT?
//!
//! Cookies are a *server-internal* integrity concern. Nothing outside
//! the worker needs to verify them, so a symmetric MAC is the right
//! primitive: it's cheaper per request, and it keeps the JWT signing
//! key (which is published through `/jwks.json` and consumed by
//! resource servers) scoped to the thing it actually signs. The
//! `SESSION_COOKIE_KEY` secret lives next to the JWT key in
//! `wrangler secret` but is never exposed outside the worker.
//!
//! ## Revocation
//!
//! The cookie by itself carries a self-asserted `expires_at`. Actual
//! revocation is authoritative in the `ActiveSession` DO: on every
//! privileged request that cares, the worker calls
//! `ActiveSessionStore::status(session_id)` and refuses if the DO
//! reports `Revoked`. This module does not talk to the DO; it just
//! proves the cookie is an *authentic* claim by cesauth that a given
//! session started. Whether it's still valid is a separate check.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::{CoreError, CoreResult};
use crate::ports::store::AuthMethod;

/// The canonical cookie name. The `__Host-` prefix forces `Secure`,
/// `Path=/`, and disallows a `Domain` attribute, which is what we want
/// for a cross-origin-unsafe first-party session cookie.
pub const COOKIE_NAME: &str = "__Host-cesauth_session";

/// What we pack into the cookie. Keep this small: every private
/// request carries it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionCookie {
    pub session_id:  String,
    pub user_id:     String,
    pub auth_method: AuthMethod,
    pub issued_at:   i64,
    pub expires_at:  i64,
}

impl SessionCookie {
    /// Sign the payload and emit the wire form: `b64url(json).b64url(mac)`.
    ///
    /// `key` is the raw HMAC secret (at least 32 bytes, ideally 64).
    /// Callers load this from `SESSION_COOKIE_KEY`.
    pub fn sign(&self, key: &[u8]) -> CoreResult<String> {
        if key.len() < 16 {
            // Refuse to sign with a trivially weak key. 16 bytes is a
            // sanity floor; deployments should provision 32 or 64.
            return Err(CoreError::Internal);
        }
        let payload = serde_json::to_vec(self)?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
            .map_err(|_| CoreError::Internal)?;
        mac.update(&payload);
        let tag = mac.finalize().into_bytes();

        let p_b64 = URL_SAFE_NO_PAD.encode(&payload);
        let t_b64 = URL_SAFE_NO_PAD.encode(tag);
        Ok(format!("{p_b64}.{t_b64}"))
    }

    /// Parse and verify the wire form. Returns the payload on success.
    ///
    /// `now_unix` is used only for the `expires_at` check. `verify`
    /// does *not* consult the ActiveSession DO - the caller must do
    /// that separately before trusting the session for anything.
    pub fn verify(wire: &str, key: &[u8], now_unix: i64) -> CoreResult<Self> {
        let (p_b64, t_b64) = wire.split_once('.')
            .ok_or(CoreError::InvalidRequest("session cookie shape"))?;

        let payload = URL_SAFE_NO_PAD.decode(p_b64)
            .map_err(|_| CoreError::InvalidRequest("session cookie b64"))?;
        let tag = URL_SAFE_NO_PAD.decode(t_b64)
            .map_err(|_| CoreError::InvalidRequest("session cookie b64"))?;

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
            .map_err(|_| CoreError::Internal)?;
        mac.update(&payload);
        // Constant-time comparison is done by `verify_slice` itself.
        mac.verify_slice(&tag)
            .map_err(|_| CoreError::InvalidRequest("session cookie hmac"))?;

        let this: Self = serde_json::from_slice(&payload)?;
        if now_unix >= this.expires_at {
            return Err(CoreError::InvalidRequest("session cookie expired"));
        }
        Ok(this)
    }
}

/// Emit the `Set-Cookie` value for this cookie, with the defensive
/// attribute set appropriate for a first-party session cookie. Keep
/// this centralized so every endpoint uses the same flags:
///
/// * `HttpOnly`: no JS access.
/// * `Secure`: forced by the `__Host-` prefix, re-stated for clarity.
/// * `SameSite=Lax`: Strict would break the `/authorize` redirect back
///   from the IdP's own login page; Lax is sufficient because cookies
///   are only used on navigation from the same origin.
/// * `Path=/`: forced by the `__Host-` prefix.
/// * `Max-Age`: explicit so the browser drops the cookie at our
///   expiry, not just when the tab closes.
pub fn set_cookie_header(cookie_value: &str, ttl_secs: i64) -> String {
    // Clamp negative TTLs to 0 (delete-ish). Callers shouldn't pass
    // negative, but defense in depth.
    let max_age = ttl_secs.max(0);
    format!(
        "{COOKIE_NAME}={cookie_value}; Max-Age={max_age}; Path=/; HttpOnly; Secure; SameSite=Lax"
    )
}

/// Emit a `Set-Cookie` that instructs the browser to forget the
/// session cookie immediately. Used by `POST /logout`.
pub fn clear_cookie_header() -> String {
    format!("{COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax")
}

/// Extract the session cookie value from a `Cookie` header string.
/// Returns `None` if the header is missing or the cookie isn't present.
///
/// We do a minimal cookie-jar parse: split on `;`, trim, split on `=`.
/// This is the shape browsers actually send; we do not try to handle
/// quoted values because no sane session-cookie deployment needs them.
pub fn extract_from_cookie_header(header_value: &str) -> Option<&str> {
    for piece in header_value.split(';') {
        let piece = piece.trim();
        if let Some(rest) = piece.strip_prefix(COOKIE_NAME) {
            if let Some(v) = rest.strip_prefix('=') {
                return Some(v);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [0xA5; 32]
    }

    fn sample() -> SessionCookie {
        SessionCookie {
            session_id:  "sess-1".into(),
            user_id:     "user-1".into(),
            auth_method: AuthMethod::MagicLink,
            issued_at:   1_000,
            expires_at:  2_000,
        }
    }

    #[test]
    fn round_trip() {
        let c = sample();
        let wire = c.sign(&key()).unwrap();
        let back = SessionCookie::verify(&wire, &key(), 1_500).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let c = sample();
        let wire = c.sign(&key()).unwrap();
        // Flip a single character in the payload segment. The MAC no
        // longer matches; verify must refuse.
        let (p, t) = wire.split_once('.').unwrap();
        let mut bad_p = p.to_owned();
        bad_p.replace_range(0..1, "Z");
        let tampered = format!("{bad_p}.{t}");
        assert!(SessionCookie::verify(&tampered, &key(), 1_500).is_err());
    }

    #[test]
    fn different_key_is_rejected() {
        let c = sample();
        let wire = c.sign(&key()).unwrap();
        let other = [0x00u8; 32];
        assert!(SessionCookie::verify(&wire, &other, 1_500).is_err());
    }

    #[test]
    fn expired_cookie_is_rejected() {
        let c = sample();
        let wire = c.sign(&key()).unwrap();
        // Exactly at expires_at is expired.
        assert!(SessionCookie::verify(&wire, &key(), 2_000).is_err());
        assert!(SessionCookie::verify(&wire, &key(), 2_001).is_err());
    }

    #[test]
    fn rejects_trivially_short_key() {
        let c = sample();
        assert!(c.sign(&[0u8; 4]).is_err());
    }

    #[test]
    fn set_cookie_header_has_required_flags() {
        let h = set_cookie_header("x.y", 600);
        assert!(h.starts_with(&format!("{COOKIE_NAME}=x.y")));
        assert!(h.contains("HttpOnly"));
        assert!(h.contains("Secure"));
        assert!(h.contains("SameSite=Lax"));
        assert!(h.contains("Path=/"));
        assert!(h.contains("Max-Age=600"));
    }

    #[test]
    fn clear_cookie_header_zeroes_max_age() {
        let h = clear_cookie_header();
        assert!(h.contains("Max-Age=0"));
    }

    #[test]
    fn extract_from_cookie_header_finds_value() {
        let h = format!("foo=bar; {COOKIE_NAME}=abc.def; other=baz");
        assert_eq!(extract_from_cookie_header(&h), Some("abc.def"));
    }

    #[test]
    fn extract_from_cookie_header_missing() {
        assert_eq!(extract_from_cookie_header("foo=bar"), None);
    }
}
