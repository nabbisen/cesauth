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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_header_shape() {
        let h = set_cookie_header("abc");
        assert!(h.starts_with(&format!("{CSRF_COOKIE_NAME}=abc")));
        assert!(h.contains("HttpOnly"));
        assert!(h.contains("Secure"));
        assert!(h.contains("SameSite=Strict"));
    }

    #[test]
    fn extract_present() {
        let h = format!("other=1; {CSRF_COOKIE_NAME}=tok; more=2");
        assert_eq!(extract_from_cookie_header(&h), Some("tok"));
    }

    #[test]
    fn extract_missing() {
        assert_eq!(extract_from_cookie_header("other=1; more=2"), None);
    }

    #[test]
    fn extract_does_not_match_prefix_collision() {
        // A different cookie whose name happens to start the same way
        // must not match. The `strip_prefix` + `=` check guards this.
        let h = format!("{CSRF_COOKIE_NAME}x=bad; other=1");
        assert_eq!(extract_from_cookie_header(&h), None);
    }

    #[test]
    fn constant_time_eq_correctness() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("",    "a"));
        assert!(constant_time_eq("",     ""));
    }

    #[test]
    fn verify_rejects_empty() {
        assert!(!verify("",    "cookie-val"));
        assert!(!verify("sub", ""));
        assert!(!verify("",    ""));
    }

    #[test]
    fn verify_passes_when_equal() {
        assert!(verify("tok", "tok"));
    }

    #[test]
    fn mint_produces_unique_nonempty_tokens() {
        let a = mint();
        let b = mint();
        assert!(!a.is_empty());
        assert_ne!(a, b);
    }
}
