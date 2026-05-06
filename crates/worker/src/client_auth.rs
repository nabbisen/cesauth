//! Client credential extraction (v0.38.0, ADR-014).
//!
//! Per RFC 6749 §2.3 + RFC 7662 §2.1, OAuth endpoints that
//! require client authentication accept credentials in two
//! shapes:
//!
//! 1. **HTTP Basic** (`Authorization: Basic
//!    base64(client_id:client_secret)`). RFC 6749 §2.3.1 names
//!    this `client_secret_basic` and notes it is REQUIRED to
//!    support; per-spec it is the recommended method for
//!    server-to-server use because it keeps secrets out of
//!    request bodies (which are sometimes logged at proxies).
//!
//! 2. **Form body** (`client_id`, `client_secret` fields). RFC
//!    6749 §2.3.1 names this `client_secret_post`; OPTIONAL
//!    per spec but useful for clients that can't easily set
//!    Authorization headers (browser-based PKCE clients
//!    aren't this case — they use no secret at all — but
//!    legacy SDKs sometimes are).
//!
//! cesauth's `/introspect` accepts both. The form fallback
//! exists only when no Authorization header is present, so a
//! malformed Basic header doesn't silently fall through to a
//! form-body bypass.

use base64::{Engine, engine::general_purpose::STANDARD};
use worker::{FormEntry, Headers};

/// Extracted client credentials. Both fields are present-or-
/// missing together; partial credentials (id without secret)
/// are surfaced as `None` so the caller can return 401.
#[derive(Debug)]
pub struct ClientCredentials {
    pub client_id:     String,
    pub client_secret: String,
}

/// Try to extract credentials from an `Authorization: Basic
/// ...` header. Returns `Some(creds)` only on a fully-formed
/// header. Returns `None` if the header is missing OR is
/// present but malformed — the caller may then choose to fall
/// back to the form body (for missing) or refuse (for
/// malformed; but we conflate them here because distinguishing
/// would let an attacker probe header parsing behavior).
///
/// The `client_id` and `client_secret` are **not URL-decoded**
/// here; RFC 6749 §2.3.1 says the values in a Basic header
/// must be `application/x-www-form-urlencoded`-percent-encoded
/// at the byte level before base64. We percent-decode after the
/// base64 decode.
pub fn extract_from_basic(headers: &Headers) -> Option<ClientCredentials> {
    let value = headers.get("authorization").ok().flatten()?;
    let encoded = value.strip_prefix("Basic ").or_else(|| value.strip_prefix("basic "))?;
    let bytes   = STANDARD.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8(bytes).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some(ClientCredentials {
        client_id:     percent_decode(id)?,
        client_secret: percent_decode(secret)?,
    })
}

/// Try to extract credentials from a parsed form body. Returns
/// `Some(creds)` only if BOTH `client_id` and `client_secret`
/// fields are present and non-empty.
pub fn extract_from_form(form: &worker::FormData) -> Option<ClientCredentials> {
    let id  = match form.get("client_id")     { Some(FormEntry::Field(v)) => v, _ => return None };
    let sec = match form.get("client_secret") { Some(FormEntry::Field(v)) => v, _ => return None };
    if id.is_empty() || sec.is_empty() { return None; }
    Some(ClientCredentials {
        client_id:     id,
        client_secret: sec,
    })
}

/// Extract credentials, preferring Basic. Falls through to the
/// form body only when no Authorization header is present at all
/// (a malformed Basic does NOT fall through — the request is
/// already-attempted and we don't want to retry with a different
/// shape).
pub fn extract(headers: &Headers, form: &worker::FormData) -> Option<ClientCredentials> {
    if headers.get("authorization").ok().flatten().is_some() {
        // Header present → Basic-only path (success or fail).
        extract_from_basic(headers)
    } else {
        extract_from_form(form)
    }
}

/// `application/x-www-form-urlencoded`-style percent-decoding,
/// scoped to the bytes that appear in the inner part of a Basic
/// auth header per RFC 6749 §2.3.1. Returns `None` on a
/// truncated `%` escape so the surrounding extraction can
/// surface it as a malformed header.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() { return None; }
                let hi = hex_digit(bytes[i + 1])?;
                let lo = hex_digit(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => { out.push(b' '); i += 1; }
            b    => { out.push(b);    i += 1; }
        }
    }
    String::from_utf8(out).ok()
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_passthrough() {
        assert_eq!(percent_decode("hello").as_deref(), Some("hello"));
    }

    #[test]
    fn percent_decode_escape() {
        assert_eq!(percent_decode("a%20b").as_deref(), Some("a b"));
        assert_eq!(percent_decode("%21%40%23").as_deref(), Some("!@#"));
    }

    #[test]
    fn percent_decode_plus_to_space() {
        assert_eq!(percent_decode("a+b").as_deref(), Some("a b"));
    }

    #[test]
    fn percent_decode_truncated_returns_none() {
        assert_eq!(percent_decode("a%2"), None);
        assert_eq!(percent_decode("a%"),  None);
    }

    #[test]
    fn percent_decode_invalid_hex_returns_none() {
        assert_eq!(percent_decode("a%zz"), None);
    }

    #[test]
    fn hex_digit_recognizes_all_cases() {
        assert_eq!(hex_digit(b'0'), Some(0));
        assert_eq!(hex_digit(b'9'), Some(9));
        assert_eq!(hex_digit(b'a'), Some(10));
        assert_eq!(hex_digit(b'f'), Some(15));
        assert_eq!(hex_digit(b'A'), Some(10));
        assert_eq!(hex_digit(b'F'), Some(15));
        assert_eq!(hex_digit(b'g'), None);
        assert_eq!(hex_digit(b' '), None);
    }
}
