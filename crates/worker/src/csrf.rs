//! CSRF token plumbing for the magic-link form submission.
//!
//! ## Threat
//!
//! A malicious page on a different origin tries to POST to
//! `/magic-link/request` with a form whose `email=victim@...`. Without
//! CSRF protection, the browser sends the user's `__Host-` session
//! cookies along and the worker happily issues a magic link to the
//! attacker-chosen address. The attacker then has to intercept the
//! email, which is usually out of reach, but the request *itself*
//! becomes a side-channel (e.g. spamming the victim's inbox, forcing
//! rate-limit escalation on their account).
//!
//! ## Mitigation
//!
//! The login page (whether rendered from `/login` or from `/authorize`
//! cold path) mints a 24-byte random token and sets it as
//! `__Host-cesauth-csrf` (`HttpOnly; Secure; SameSite=Strict; Path=/`).
//! The same token is embedded in the `<input type="hidden" name="csrf">`
//! of the magic-link form. On POST, the handler reads both, compares
//! them in constant time, and rejects on mismatch.
//!
//! ## Bypass for JSON callers
//!
//! Only `application/x-www-form-urlencoded` posts require CSRF
//! validation. Cross-origin `application/json` submits are gated by
//! CORS preflight by the browser; a malicious page cannot silently
//! forge them. CLI callers (the local-dev tutorial) use JSON and are
//! therefore exempt. This is the standard mitigation pattern
//! (OWASP CSRF Cheat Sheet, "Use of Custom Request Headers").

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use getrandom::getrandom;

/// Cookie name. The `__Host-` prefix guarantees Path=/; Secure; and no
/// Domain attribute, which is what we set below.
pub const CSRF_COOKIE_NAME: &str = "__Host-cesauth-csrf";

/// Build the `Set-Cookie` value for the CSRF token cookie.
///
/// Attributes: `HttpOnly` so JS cannot read it (the token reaches the
/// form body via server-side rendering, not JS); `Secure` because of
/// `__Host-`; `SameSite=Strict` for belt-and-braces on top of origin
/// checks upstream.
pub fn set_cookie_header(token: &str) -> String {
    format!(
        "{CSRF_COOKIE_NAME}={token}; Path=/; Secure; HttpOnly; SameSite=Strict"
    )
}

/// Mint a fresh CSRF token. 24 bytes of CSPRNG base64url-encoded.
pub fn mint() -> String {
    let mut buf = [0u8; 24];
    let _ = getrandom(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Extract the CSRF cookie value from a raw `Cookie:` header. Returns
/// `None` if the header is missing or the cookie is not present.
pub fn extract_from_cookie_header(cookie_header: &str) -> Option<&str> {
    for piece in cookie_header.split(';') {
        let piece = piece.trim();
        if let Some(rest) = piece.strip_prefix(CSRF_COOKIE_NAME) {
            if let Some(v) = rest.strip_prefix('=') {
                return Some(v);
            }
        }
    }
    None
}

/// Constant-time equality for the two byte strings. Returns `true`
/// iff the inputs are the same length and every byte matches. This
/// matters because short-circuit `==` leaks length + common-prefix
/// timing, which a patient attacker could exploit to recover the
/// token one byte at a time.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Verify the submitted token against the cookie. Both must be
/// non-empty and match exactly. Empty strings always fail: a caller
/// that forgot to mint or forgot to send the token should never pass.
pub fn verify(submitted: &str, from_cookie: &str) -> bool {
    if submitted.is_empty() || from_cookie.is_empty() {
        return false;
    }
    constant_time_eq(submitted, from_cookie)
}

/// Verify a request's `Origin` (or fallback `Referer`) header matches
/// `expected_origin`. Returns `true` iff one of the two headers is
/// present and points at our own origin. Returns `false` if neither
/// header is present (browsers send at least one on cross-origin
/// requests, so a complete absence is itself suspicious).
///
/// This is a complementary CSRF defense to the token check, drawn
/// from OWASP's "Verifying Origin Header" pattern. Useful for routes
/// where adding a CSRF token to existing request shapes would break
/// programmatic clients (e.g. `/logout`, which has no UI form yet
/// and is invoked via direct POSTs by integration tooling).
///
/// Why both `Origin` and `Referer`: `Origin` is sent by all modern
/// browsers on POST. `Referer` is sent by older / quirkier browsers
/// or when the user has Origin stripped by a privacy extension.
/// Either one matching the expected origin is sufficient — the
/// attacker cannot forge either from a cross-origin page.
///
/// Comparison is exact-string (scheme + host + optional port). The
/// `expected_origin` string should NOT have a trailing slash; e.g.
/// `https://cesauth.example.com`. For `Referer`, we compare against
/// `expected_origin` as a prefix (since `Referer` is a full URL,
/// not just the origin).
pub fn check_origin_or_referer(
    origin_header:  Option<&str>,
    referer_header: Option<&str>,
    expected_origin: &str,
) -> bool {
    if expected_origin.is_empty() {
        // Mis-configured deployment: refuse rather than silently
        // accept any origin. The Worker layer logs this state.
        return false;
    }

    if let Some(origin) = origin_header {
        // `Origin: null` is what browsers send on opaque-origin
        // contexts (data: URLs, sandboxed iframes). Treat as
        // failed match — we don't accept it.
        if origin == "null" {
            return false;
        }
        // Exact match: scheme://host[:port]
        if origin == expected_origin {
            return true;
        }
        // If Origin is present and doesn't match, the request is
        // cross-origin. Don't fall through to Referer — that
        // would let an attacker who suppresses Origin slip past.
        return false;
    }

    if let Some(referer) = referer_header {
        // Match `Referer` as `<expected_origin>/*`. Be careful
        // about prefix attacks: `https://attacker.com/?fake=https://cesauth.example.com`
        // starts with the expected_origin only if `expected_origin`
        // is a substring of the URL. We require an exact prefix
        // match starting at byte 0, AND the next character (if
        // present) must be `/`, `?`, or `#` — anything else
        // means we matched a longer hostname like
        // `cesauth.example.com.attacker.com`.
        if let Some(rest) = referer.strip_prefix(expected_origin) {
            return rest.is_empty()
                || rest.starts_with('/')
                || rest.starts_with('?')
                || rest.starts_with('#');
        }
        return false;
    }

    // Neither header present — fail closed. A real browser will
    // include at least one on a POST.
    false
}

#[cfg(test)]
mod tests;
