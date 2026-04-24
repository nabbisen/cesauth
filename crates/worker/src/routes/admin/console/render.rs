//! Shared response-shaping helpers for the admin console.
//!
//! * [`prefers_json`] inspects `Accept` to decide whether the caller
//!   wants an HTML page (browser default) or a JSON body (scripts).
//! * [`html_response`] and [`json_response`] set the baseline security
//!   headers every console response carries: strict CSP (no scripts
//!   allowed, inline style only), `no-store`, frame-deny.
//!
//! The console never loads external JS, never loads external fonts,
//! never loads external images; so the CSP can be uncompromising
//! without hurting rendering.

use worker::{Request, Response, Result};

/// Returns `true` iff the caller sent `Accept: application/json`.
///
/// We match "prefers JSON over HTML" cheaply: look for
/// `application/json` in the `Accept` header. An exact comparison is
/// too strict (browsers send `*/*`), so we accept any Accept that
/// contains `application/json` and does NOT strongly prefer `text/html`
/// over it. This mirrors the `curl --header 'Accept: application/json'`
/// / `curl -H 'Accept:'` split that operators use.
pub fn prefers_json(req: &Request) -> bool {
    let Ok(Some(accept)) = req.headers().get("accept") else {
        return false;
    };
    let lower = accept.to_ascii_lowercase();
    if !lower.contains("application/json") {
        return false;
    }
    // If both text/html and application/json appear, we go with whichever
    // shows up first. That matches browsers (text/html,...) sending HTML,
    // and `curl -H 'Accept: application/json,*/*'` sending JSON.
    match (lower.find("application/json"), lower.find("text/html")) {
        (Some(j), Some(h)) => j <= h,
        (Some(_), None)    => true,
        _                  => false,
    }
}

/// Return an HTML response with the strict admin-surface CSP.
///
/// Sets:
///   * `content-type: text/html; charset=utf-8`
///   * `cache-control: no-store` (admin pages are never cached by
///     proxies or the browser; session bearer in every request)
///   * a CSP that forbids `script-src` entirely and pins `style-src`
///     to self + inline
pub fn html_response(body: String) -> Result<Response> {
    let mut resp = Response::from_html(body)?;
    let h = resp.headers_mut();
    let _ = h.set("cache-control", "no-store");
    let _ = h.set(
        "content-security-policy",
        "default-src 'self'; \
         script-src 'none'; \
         style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; \
         form-action 'self'; \
         frame-ancestors 'none'; \
         base-uri 'none'",
    );
    let _ = h.set("x-content-type-options", "nosniff");
    let _ = h.set("x-frame-options",        "DENY");
    let _ = h.set("referrer-policy",        "no-referrer");
    Ok(resp)
}

/// Return a JSON response with the same no-cache / no-frame headers.
pub fn json_response(value: &serde_json::Value) -> Result<Response> {
    let mut resp = Response::from_json(value)?;
    let h = resp.headers_mut();
    let _ = h.set("cache-control", "no-store");
    let _ = h.set("x-content-type-options", "nosniff");
    let _ = h.set("x-frame-options",        "DENY");
    let _ = h.set("referrer-policy",        "no-referrer");
    Ok(resp)
}
