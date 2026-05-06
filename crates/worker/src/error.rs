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

/// Pure decision: which OAuth-shape error code + HTTP status
/// does this `CoreError` map to? Extracted from
/// `oauth_error_response` so tests can exercise the BCP-
/// critical wire-equivalence properties without constructing
/// a `worker::Response` (which is wasm-bindgen-backed and
/// panics on the host test target).
pub(crate) fn oauth_error_code_status(err: &CoreError) -> (&'static str, u16) {
    use CoreError::*;
    match err {
        InvalidRequest(_)       => ("invalid_request",        400),
        InvalidGrant(_)         => ("invalid_grant",          400),
        // v0.34.0: refresh-token reuse maps to the SAME wire
        // response as invalid_grant. Distinguishing them
        // externally would let attackers probe whether a
        // presented jti is currently retired (= a real-but-
        // rotated-out token) vs wholly unknown — the BCP
        // §4.13 / RFC 9700 §4.14.2 explicitly call this out
        // as an avoidable side-channel. The internal vs
        // external distinction (audit + logs see the
        // forensic detail; the wire sees the bare error code)
        // is exactly what spec §10.3 asks for.
        RefreshTokenReuse { .. } => ("invalid_grant",         400),
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
    }
}

/// Turn a `CoreError` into an OAuth-style JSON error response. Audit
/// logging happens at the route level; this function is intentionally
/// side-effect-free.
pub fn oauth_error_response(err: &CoreError) -> Result<Response> {
    let (code, status) = oauth_error_code_status(err);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// **v0.34.0 / ADR-011** — Refresh-token reuse must produce
    /// the SAME wire response as legitimate `invalid_grant`. If
    /// these ever diverge, an attacker can probe whether a
    /// presented jti is currently in the family's retired_jtis
    /// ring by submitting a guess and observing the response.
    /// The internal/external split (audit + logs see the
    /// distinction; the wire doesn't) is the BCP §4.13 / spec
    /// §10.3 contract.
    #[test]
    fn refresh_token_reuse_maps_to_same_wire_code_and_status_as_invalid_grant() {
        let reuse = oauth_error_code_status(&CoreError::RefreshTokenReuse {
            reused_jti:  "any".into(),
            was_retired: true,
        });
        let revoked = oauth_error_code_status(
            &CoreError::InvalidGrant("refresh token revoked"),
        );

        assert_eq!(reuse, revoked,
            "reuse and revoked must produce identical (code, status) — \
             differing would let attackers probe whether a presented \
             jti is currently retired vs wholly unknown");
        assert_eq!(reuse, ("invalid_grant", 400));
    }

    /// **v0.34.0** — Same property must hold across BOTH
    /// `was_retired` flag values. A divergence between
    /// retired-vs-unknown reuse would re-introduce the
    /// side-channel even with reuse-vs-revoked unified.
    #[test]
    fn refresh_token_reuse_same_response_regardless_of_was_retired() {
        let retired_reuse = oauth_error_code_status(&CoreError::RefreshTokenReuse {
            reused_jti:  "any".into(),
            was_retired: true,
        });
        let unknown_reuse = oauth_error_code_status(&CoreError::RefreshTokenReuse {
            reused_jti:  "any".into(),
            was_retired: false,
        });
        assert_eq!(retired_reuse, unknown_reuse,
            "the two reuse subcases must be wire-indistinguishable");
    }

    /// **v0.34.0** — pin the `invalid_grant` wire code so
    /// future changes to the error-table notice if this ever
    /// drifts. RFC 6749 §5.2 lists `invalid_grant` as the
    /// correct error for "the provided refresh token is
    /// invalid, expired, revoked, [or] does not match the
    /// redirection URI used in the authorization request".
    /// Reuse falls under "revoked" from RFC 9700 §4.14.2's
    /// perspective (the family is revoked the moment reuse is
    /// detected).
    #[test]
    fn refresh_token_reuse_uses_invalid_grant_per_rfc_6749() {
        let (code, _) = oauth_error_code_status(&CoreError::RefreshTokenReuse {
            reused_jti:  "any".into(),
            was_retired: false,
        });
        assert_eq!(code, "invalid_grant");
    }
}
