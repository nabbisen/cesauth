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
        // v0.37.0: rate-limit gets HTTP 429. RFC 6749 doesn't
        // define a `rate_limited` error code, so we use
        // `invalid_request` as the closest spec-defined code
        // (RFC 6749 §5.2 lists it as catch-all for "invalid"
        // request shape). The 429 status conveys the actual
        // semantics; a Retry-After header carries the wait
        // time. Modern OAuth clients understand 429 + Retry-
        // After regardless of the body code.
        RateLimited { .. }       => ("invalid_request",       429),
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

    // **v0.51.1 (RFC 004)** — WebAuthn failures include a typed `kind`
    // field so clients can branch on the category without parsing the
    // diagnostic detail string (which does NOT appear on the wire).
    let body = if let CoreError::WebAuthn(detail) = err {
        let kind = cesauth_core::webauthn::classify_webauthn_error(detail);
        serde_json::json!({
            "error": code,
            "kind":  kind.as_str(),
        })
    } else {
        serde_json::json!({ "error": code })
    };

    let mut resp = Response::from_json(&body)?.with_status(status);
    let _ = resp.headers_mut().set("cache-control", "no-store");
    let _ = resp.headers_mut().set("pragma",        "no-cache");

    // v0.37.0: on a rate-limit response, surface the
    // `Retry-After` hint. RFC 7231 §7.1.3 says it can be a
    // positive integer (seconds). Clamp at 1 to avoid the
    // case where `resets_in` is 0 (the window has already
    // rolled but the gate is still active for this request).
    if let CoreError::RateLimited { retry_after_secs } = err {
        let secs = std::cmp::max(1, *retry_after_secs);
        let _ = resp.headers_mut().set("retry-after", &secs.to_string());
    }
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

    // =================================================================
    // v0.37.0 — Per-family rate limit on /token refresh (ADR-011 §Q1)
    // =================================================================

    /// **v0.37.0** — Rate-limit responses use HTTP 429.
    /// RFC 7231 §6.6 reserves 429 for "Too Many Requests";
    /// modern OAuth clients understand it. The body code is
    /// `invalid_request` because RFC 6749 doesn't define a
    /// rate-limit code; the 429 status carries the real
    /// semantics and the Retry-After header carries the
    /// wait time.
    #[test]
    fn rate_limited_maps_to_http_429() {
        let (code, status) = oauth_error_code_status(&CoreError::RateLimited {
            retry_after_secs: 30,
        });
        assert_eq!(status, 429,
            "rate-limit response must use RFC 7231 §6.6 status code");
        assert_eq!(code, "invalid_request",
            "no spec-defined OAuth body code for rate-limit; \
             invalid_request is the catch-all per RFC 6749 §5.2");
    }

    /// **v0.37.0** — Status is 429 regardless of the
    /// `retry_after_secs` value. A client that submits
    /// rapidly can encounter different retry-after values
    /// across requests; the wire status is stable.
    #[test]
    fn rate_limited_status_is_independent_of_retry_after() {
        let (_, status_short) = oauth_error_code_status(&CoreError::RateLimited {
            retry_after_secs: 1,
        });
        let (_, status_long) = oauth_error_code_status(&CoreError::RateLimited {
            retry_after_secs: 3600,
        });
        assert_eq!(status_short, status_long);
        assert_eq!(status_short, 429);
    }

    /// **v0.37.0** — Rate-limit must NOT collide with the
    /// other 4xx conditions on the `/token` endpoint. A
    /// caller seeing 429 should know it's rate-limit, not
    /// something else; a caller seeing 400 / 401 should
    /// know it's not rate-limit. This pin catches an
    /// accidental table-mapping change.
    #[test]
    fn rate_limited_status_distinct_from_other_4xx_oauth_errors() {
        let rate_limited  = oauth_error_code_status(&CoreError::RateLimited {
            retry_after_secs: 30,
        });
        let invalid_grant = oauth_error_code_status(&CoreError::InvalidGrant("x"));
        let invalid_client = oauth_error_code_status(&CoreError::InvalidClient);
        let reuse = oauth_error_code_status(&CoreError::RefreshTokenReuse {
            reused_jti:  "x".into(),
            was_retired: true,
        });

        assert_ne!(rate_limited.1, invalid_grant.1);
        assert_ne!(rate_limited.1, invalid_client.1);
        assert_ne!(rate_limited.1, reuse.1);
    }

    // =================================================================
    // v0.51.1 — RFC 004: WebAuthn typed error response shape
    // =================================================================

    /// **RFC 004** — WebAuthn failure response must include a `kind`
    /// field so clients can branch on the category without parsing the
    /// diagnostic detail string.
    #[test]
    fn webauthn_failure_response_includes_kind_field() {
        let (code, _status) = oauth_error_code_status(
            &CoreError::WebAuthn("rpIdHash mismatch")
        );
        // oauth_error_code_status gives us the error code; the kind is
        // added by `oauth_error_response`. We test the code-status table
        // here and rely on integration tests for the full JSON shape.
        assert_eq!(code, "server_error");
        // Also confirm the classify round-trip for the most important case.
        let kind = cesauth_core::webauthn::classify_webauthn_error("rpIdHash mismatch");
        assert_eq!(kind, cesauth_core::webauthn::WebAuthnErrorKind::RelyingPartyMismatch);
    }

    /// **RFC 004** — The diagnostic detail string MUST NOT appear in
    /// the error body (privacy invariant: server logs get detail,
    /// wire gets category only).
    #[test]
    fn webauthn_failure_detail_is_not_the_kind_field_value() {
        let detail = "rpIdHash mismatch";
        let kind = cesauth_core::webauthn::classify_webauthn_error(detail);
        // kind.as_str() must not equal the raw detail string — if they
        // were ever made equal an implementer could mistake it for safe
        // forwarding. The category names are deliberately different from
        // the diagnostic strings.
        assert_ne!(
            kind.as_str(), detail,
            "kind must be a category label, not the raw diagnostic string"
        );
    }

    /// **RFC 004** — All six `WebAuthnErrorKind` variants have distinct
    /// `as_str()` values (no accidental aliasing).
    #[test]
    fn webauthn_error_kind_values_are_distinct() {
        use cesauth_core::webauthn::WebAuthnErrorKind::*;
        let all = [
            UnknownCredential.as_str(),
            RelyingPartyMismatch.as_str(),
            UserCancelled.as_str(),
            SignatureInvalid.as_str(),
            ChallengeMismatch.as_str(),
            Other.as_str(),
        ];
        let mut seen = std::collections::HashSet::new();
        for s in &all {
            assert!(seen.insert(*s), "duplicate kind value: {s}");
        }
    }
}
