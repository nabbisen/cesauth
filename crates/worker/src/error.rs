//! Error types for the worker crate, and the one-way mapping from
//! `cesauth_core::CoreError` into RFC-6749-shaped responses.
//!
//! Spec §10.3: "internal errors and external responses must be separated;
//! failure reasons must not be over-exposed". The one place those two
//! worlds meet is here. Anything that widens the outbound vocabulary
//! should be made in this file, reviewed on its own, and added with a
//! test.

use cesauth_core::CoreError;
use worker::{Response, Result};

/// Turn a `CoreError` into an OAuth-style JSON error response. Audit
/// logging happens at the route level; this function is intentionally
/// side-effect-free.
pub fn oauth_error_response(err: &CoreError) -> Result<Response> {
    use CoreError::*;
    let (code, status): (&str, u16) = match err {
        InvalidRequest(_)       => ("invalid_request",        400),
        InvalidGrant(_)         => ("invalid_grant",          400),
        InvalidClient           => ("invalid_client",         401),
        InvalidScope(_)         => ("invalid_scope",          400),
        UnsupportedGrantType(_) => ("unsupported_grant_type", 400),
        PkceMismatch            => ("invalid_grant",          400),
        LoginRequired           => ("login_required",         400),
        WebAuthn(_)
        | JwtValidation(_)
        | JwtSigning
        | MagicLinkExpired
        | MagicLinkMismatch
        | Serialization
        | Internal              => ("server_error",           500),
    };

    let body = serde_json::json!({ "error": code });
    let mut resp = Response::from_json(&body)?.with_status(status);
    let _ = resp.headers_mut().set("cache-control", "no-store");
    let _ = resp.headers_mut().set("pragma",        "no-cache");
    Ok(resp)
}

/// Same shape but for the WWW-Authenticate Bearer realm per RFC 6750.
/// Use on protected resource endpoints, not on `/token`.
pub fn bearer_error_response(code: &str, status: u16) -> Result<Response> {
    let body = serde_json::json!({ "error": code });
    let mut resp = Response::from_json(&body)?.with_status(status);
    let _ = resp.headers_mut().set(
        "www-authenticate",
        &format!(r#"Bearer error="{code}""#),
    );
    let _ = resp.headers_mut().set("cache-control", "no-store");
    Ok(resp)
}
