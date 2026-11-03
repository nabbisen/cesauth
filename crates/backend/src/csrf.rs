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

use std::collections::HashMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use getrandom::getrandom;
use worker::Response;

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
///
/// Returns `Err` if the platform CSPRNG fails. Callers MUST fail-closed
/// on `Err` — rendering a form with a zeroed token would let any
/// submitted form bypass CSRF validation (the cookie is also zeroed,
/// so the double-submit check passes trivially). Fail with HTTP 500.
///
/// In practice `getrandom` on Cloudflare Workers' WASM target reliably
/// succeeds via `crypto.getRandomValues`; this is defense-in-depth
/// against a future runtime regression.
pub fn mint() -> Result<String, getrandom::Error> {
    let mut buf = [0u8; 24];
    getrandom(&mut buf)?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
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

/// RFC 152 half B stage 1 standardised this mint/attach/verify triple for
/// the tenancy-console and tenant-admin form handlers, living in
/// `tenancy_console/forms/common.rs`. RFC 152 half C needed the identical
/// triple from the operator-console surface (`console/tokens.rs`,
/// `console/config.rs`) — a module named `tenancy_console` is not a
/// neutral home for code the operator console also depends on, so the
/// three functions live here instead, next to the primitives they
/// already wrap, with `tenancy_console/forms/common.rs` re-exporting
/// them so its 21 existing call sites need no change.

/// Mint a CSRF token and the `set-cookie` header value that must be
/// attached to whatever response renders the form that carries it —
/// [`attach_csrf_cookie`] does that attaching.
pub fn mint_csrf() -> Result<(String, String), worker::Error> {
    let token = mint().map_err(|_| worker::Error::RustError("csrf rng failed".into()))?;
    let cookie = set_cookie_header(&token);
    Ok((token, cookie))
}

/// Attach a `set-cookie` header (from [`mint_csrf`]) to a response that
/// renders a form carrying the matching token. Every GET/preview/
/// error-re-render path that renders a form must call this with a
/// freshly minted cookie — a stale or missing cookie here is what makes
/// a corrected resubmission fail for a reason the page never explains.
pub fn attach_csrf_cookie(resp: &mut Response, cookie: &str) {
    resp.headers_mut().append("set-cookie", cookie).ok();
}

/// Verify a submitted `csrf` form field against the request's CSRF
/// cookie. `cookie_header` is the raw `cookie` request header value,
/// read by the caller before the form body is consumed.
pub fn verify_csrf(form: &HashMap<String, String>, cookie_header: &str) -> bool {
    let submitted = form.get("csrf").map(String::as_str).unwrap_or("");
    let from_cookie = extract_from_cookie_header(cookie_header).unwrap_or("");
    verify(submitted, from_cookie)
}

/// Name of the header a JSON-body endpoint requires, carrying the same
/// token the `__Host-cesauth-csrf` cookie does.
pub const CSRF_HEADER_NAME: &str = "x-csrf-token";

/// Verify a `X-CSRF-Token` request header against the request's CSRF
/// cookie — the JSON-endpoint counterpart of [`verify_csrf`] (which reads
/// a form field instead). RFC 141 cycle 2.
///
/// **Why a header is a complete defence on its own, for a JSON body.** A
/// cross-site `<form>` POST cannot set an arbitrary request header — only
/// `Content-Type`, and only to one of the three form-safelisted values,
/// none of which is `application/json`. A cross-site `fetch()` that tries
/// to add this header triggers a CORS preflight, which this deployment
/// never answers with an `Access-Control-Allow-*` that would permit a
/// foreign origin. So the header's mere presence already rules out a
/// forged cross-site request; comparing its value against the cookie
/// (double-submit, same as [`verify_csrf`]) is defence in depth on top of
/// that, not the only thing standing between the request and the handler.
///
/// `header_value` is the raw `x-csrf-token` request header value, if any.
/// `cookie_header` is the raw `cookie` request header value.
pub fn verify_csrf_header(header_value: Option<&str>, cookie_header: &str) -> bool {
    let submitted = header_value.unwrap_or("");
    let from_cookie = extract_from_cookie_header(cookie_header).unwrap_or("");
    verify(submitted, from_cookie)
}

/// Pure decision: does this `Content-Type` header value count as
/// `application/json`? Case-insensitive, and tolerant of a trailing
/// `; charset=...` (`.contains`, not an exact match) — the rule
/// `routes::deletions::request_self` established (RFC 149 §2) and RFC 152
/// half D reuses for `/webauthn/authenticate/{start,finish}`.
pub fn is_json_content_type(content_type: Option<&str>) -> bool {
    content_type
        .map(|ct| ct.to_ascii_lowercase().contains("application/json"))
        .unwrap_or(false)
}

/// `Content-Type: application/json` as a JSON-body endpoint's complete
/// CSRF defence (RFC 152 half D — see [`is_json_content_type`]'s own doc
/// for why the header's mere presence already rules out a forged
/// cross-site request, the same reasoning [`verify_csrf_header`] gives for
/// a custom header). `Some(response)` is a 400 whose body says the header
/// *is* the control, not content negotiation — the wording
/// `routes::deletions::request_self` established; `None` means the caller
/// already sent the right header and may proceed.
///
/// Takes `&worker::Request` directly rather than a pre-extracted header
/// value: every call site needs the same two lines (`req.headers().get(
/// "content-type")`) and there is no pure value worth pulling further out
/// — [`is_json_content_type`] above is that pure core, host-tested on its
/// own.
pub fn require_json_content_type(req: &worker::Request) -> worker::Result<Option<Response>> {
    let content_type = req.headers().get("content-type").ok().flatten();
    if is_json_content_type(content_type.as_deref()) {
        return Ok(None);
    }
    let mut resp = Response::from_json(&serde_json::json!({
        "error": "Content-Type: application/json required (this header is this route's CSRF control)",
    }))?.with_status(400);
    resp.headers_mut().set("cache-control", "no-store").ok();
    Ok(Some(resp))
}

#[cfg(test)]
mod tests;
