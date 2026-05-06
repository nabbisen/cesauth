//! `/.well-known/openid-configuration`.
//!
//! cesauth currently advertises an **OAuth 2.0** discovery document
//! at this path, NOT a full OpenID Connect Discovery 1.0 document.
//! The reason: cesauth does not yet issue OIDC `id_token`s — the
//! `exchange_code` / `rotate_refresh` flows return only access and
//! refresh tokens. Advertising OIDC-specific metadata (the
//! `id_token_signing_alg_values_supported` field, the `openid` scope
//! in `scopes_supported`, `subject_types_supported`) would mislead
//! relying parties that read the doc and request OIDC features that
//! don't actually work.
//!
//! ID token issuance is planned for v0.26.0 (ADR-008). When that
//! lands, this module will gain the OIDC-specific fields back and
//! advertise the `openid` scope. The route path
//! (`/.well-known/openid-configuration`) is kept stable across the
//! transition so RPs don't need to re-discover.
//!
//! Until then: cesauth is an OAuth 2.0 Authorization Server (RFC
//! 6749 + 8414 metadata), not an OpenID Provider. The shape we emit
//! corresponds to RFC 8414 §2 with only the fields cesauth actually
//! supports.

use serde::Serialize;

/// The subset of OAuth 2.0 Authorization Server Metadata (RFC 8414)
/// that cesauth supports today. Built per-issuer at request time
/// (cheap) and cached in KV by the worker layer.
///
/// This is intentionally narrower than what was emitted in 0.4.x
/// through 0.24.x. Those releases advertised
/// `id_token_signing_alg_values_supported`, `subject_types_supported`,
/// and `openid` in `scopes_supported` — all of which were
/// aspirational, not implemented. v0.25.0 corrected the metadata to
/// match what the implementation actually delivers.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryDocument {
    pub issuer:                                String,
    pub authorization_endpoint:                String,
    pub token_endpoint:                        String,
    pub jwks_uri:                              String,
    pub revocation_endpoint:                   String,
    /// **v0.38.0** — RFC 7662 Token Introspection endpoint.
    /// Resource servers fetch this URL with `client_secret_basic`
    /// authentication to ask "is this token currently active,
    /// and what claims does it carry?".
    pub introspection_endpoint:                String,
    pub response_types_supported:              &'static [&'static str],
    pub token_endpoint_auth_methods_supported: &'static [&'static str],
    /// **v0.38.0** — Auth methods accepted at the introspection
    /// endpoint. Same shape as `token_endpoint_auth_methods_supported`
    /// but the introspection endpoint requires authentication
    /// (no `none`) per RFC 7662 §2.1.
    pub introspection_endpoint_auth_methods_supported: &'static [&'static str],
    /// **v0.42.0** — Auth methods accepted at the revocation
    /// endpoint. RFC 7009 + RFC 8414 §2: revocation accepts
    /// `none` (public clients revoke by token possession),
    /// `client_secret_basic`, and `client_secret_post`. The
    /// difference vs introspection is the `none` entry —
    /// RFC 7009 §2.1 explicitly allows public-client
    /// revocation, RFC 7662 §2.1 doesn't.
    pub revocation_endpoint_auth_methods_supported: &'static [&'static str],
    pub code_challenge_methods_supported:      &'static [&'static str],
    pub grant_types_supported:                 &'static [&'static str],
    pub scopes_supported:                      &'static [&'static str],
}

impl DiscoveryDocument {
    /// Build the discovery document for the given issuer URL.
    ///
    /// `issuer` should be exactly what clients will see in the `iss`
    /// claim of issued tokens. We do not normalize it here - if the
    /// caller is inconsistent about trailing slashes, discovery and
    /// token `iss` will drift and validation will fail for clients.
    /// Treating that as a caller bug rather than silently fixing it.
    pub fn new(issuer: &str) -> Self {
        Self {
            issuer:                                issuer.to_owned(),
            authorization_endpoint:                format!("{issuer}/authorize"),
            token_endpoint:                        format!("{issuer}/token"),
            jwks_uri:                              format!("{issuer}/jwks.json"),
            revocation_endpoint:                   format!("{issuer}/revoke"),
            introspection_endpoint:                format!("{issuer}/introspect"),
            response_types_supported:              &["code"],
            token_endpoint_auth_methods_supported: &[
                "none",
                "client_secret_basic",
                "client_secret_post",
            ],
            introspection_endpoint_auth_methods_supported: &[
                "client_secret_basic",
                "client_secret_post",
            ],
            revocation_endpoint_auth_methods_supported: &[
                "none",
                "client_secret_basic",
                "client_secret_post",
            ],
            code_challenge_methods_supported:      &["S256"],   // plain is forbidden
            grant_types_supported:                 &["authorization_code", "refresh_token"],
            // No `openid` until v0.26.0 lands id_token issuance.
            // `profile` and `email` are advertised because they
            // describe what the access token's `scope` claim can
            // carry through to userinfo-style consumers; they don't
            // imply id_token support on their own (RFC 6749).
            // `offline_access` is advertised because that's how a
            // client requests a refresh token.
            scopes_supported:                      &["profile", "email", "offline_access"],
        }
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // v0.25.0 honest-reset shape — pin the contract that the
    // discovery doc reflects what cesauth actually delivers. When
    // v0.26.0 lands ID token issuance, these tests update to add
    // the `openid` scope and the OIDC-specific metadata fields back.
    // -----------------------------------------------------------------

    #[test]
    fn discovery_does_not_advertise_openid_scope() {
        // OIDC-only feature; cesauth doesn't yet emit id_tokens.
        // Advertising `openid` would mislead RPs.
        let d = DiscoveryDocument::new("https://auth.example.com");
        assert!(!d.scopes_supported.contains(&"openid"),
            "scopes_supported must NOT include `openid` until id_token is real");
    }

    #[test]
    fn discovery_advertises_oauth2_scopes_only() {
        // OAuth 2.0 scopes that don't imply OIDC. Pin the exact set.
        let d = DiscoveryDocument::new("https://auth.example.com");
        assert_eq!(d.scopes_supported, &["profile", "email", "offline_access"]);
    }

    #[test]
    fn discovery_response_types_is_code_only() {
        let d = DiscoveryDocument::new("https://auth.example.com");
        assert_eq!(d.response_types_supported, &["code"]);
    }

    #[test]
    fn discovery_grant_types_match_implementation() {
        // The token endpoint accepts authorization_code +
        // refresh_token. Advertising any other grant_type
        // would mislead RPs.
        let d = DiscoveryDocument::new("https://auth.example.com");
        assert_eq!(d.grant_types_supported, &["authorization_code", "refresh_token"]);
    }

    #[test]
    fn discovery_code_challenge_methods_is_s256_only() {
        // `plain` PKCE is forbidden — the verifier rejects it.
        let d = DiscoveryDocument::new("https://auth.example.com");
        assert_eq!(d.code_challenge_methods_supported, &["S256"]);
        assert!(!d.code_challenge_methods_supported.contains(&"plain"));
    }

    #[test]
    fn discovery_endpoints_anchor_to_issuer() {
        let d = DiscoveryDocument::new("https://auth.example.com");
        assert_eq!(d.authorization_endpoint, "https://auth.example.com/authorize");
        assert_eq!(d.token_endpoint,         "https://auth.example.com/token");
        assert_eq!(d.jwks_uri,               "https://auth.example.com/jwks.json");
        assert_eq!(d.revocation_endpoint,    "https://auth.example.com/revoke");
        // v0.38.0
        assert_eq!(d.introspection_endpoint, "https://auth.example.com/introspect");
    }

    /// **v0.38.0** — RFC 7662 §2.1 requires authentication on
    /// the introspection endpoint. The advertised methods must
    /// not include `none`.
    #[test]
    fn discovery_introspection_endpoint_requires_authentication() {
        let d = DiscoveryDocument::new("https://auth.example.com");
        assert!(!d.introspection_endpoint_auth_methods_supported.contains(&"none"),
            "RFC 7662 §2.1: introspection must require client authentication");
        assert!(d.introspection_endpoint_auth_methods_supported.contains(&"client_secret_basic"),
            "client_secret_basic must be advertised — it's the spec-recommended method for /introspect");
    }

    #[test]
    fn discovery_serializes_without_oidc_fields() {
        // Pin that the wire output omits the OIDC-specific fields.
        // A future maintainer who adds `id_token_signing_alg_values_supported`
        // back without also implementing id_token issuance fails this
        // test.
        let d = DiscoveryDocument::new("https://auth.example.com");
        let json = serde_json::to_string(&d).unwrap();
        assert!(!json.contains("id_token_signing_alg_values_supported"),
            "OIDC field must not appear in v0.25.0 discovery: {json}");
        assert!(!json.contains("subject_types_supported"),
            "OIDC field must not appear in v0.25.0 discovery: {json}");
        assert!(!json.contains("\"openid\""),
            "openid scope must not appear in scopes_supported: {json}");
    }

    #[test]
    fn discovery_token_endpoint_auth_methods_match_implementation() {
        // The token endpoint accepts these three auth methods. If
        // the implementation grows a new one (e.g.,
        // `private_key_jwt`), this test must be updated alongside
        // — and the discovery doc must reflect the truth.
        let d = DiscoveryDocument::new("https://auth.example.com");
        assert_eq!(d.token_endpoint_auth_methods_supported,
            &["none", "client_secret_basic", "client_secret_post"]);
    }

    // ============================================================
    // v0.42.0 — RFC 7009 revocation endpoint auth methods
    // ============================================================

    #[test]
    fn discovery_revocation_endpoint_auth_methods_advertised() {
        // RFC 8414 §2 + RFC 7009 §2.1: the revocation
        // endpoint accepts `none` (public clients
        // revoke by token possession) + the two
        // confidential-client methods.
        let d = DiscoveryDocument::new("https://auth.example.com");
        assert_eq!(d.revocation_endpoint_auth_methods_supported,
            &["none", "client_secret_basic", "client_secret_post"]);
    }

    #[test]
    fn discovery_revocation_endpoint_auth_methods_includes_none() {
        // Pin the difference vs the introspection
        // endpoint: revocation MUST list `none`,
        // introspection MUST NOT. RFC 7662 §2.1
        // requires confidential auth for introspection;
        // RFC 7009 §2.1 explicitly allows public-client
        // revocation.
        let d = DiscoveryDocument::new("https://auth.example.com");
        assert!(d.revocation_endpoint_auth_methods_supported.contains(&"none"),
            "revocation MUST list `none` per RFC 7009 §2.1");
        assert!(!d.introspection_endpoint_auth_methods_supported.contains(&"none"),
            "introspection MUST NOT list `none` per RFC 7662 §2.1");
    }

    #[test]
    fn discovery_revocation_endpoint_auth_methods_in_wire_form() {
        // The new field must appear in serialized JSON.
        // Spec-conformant clients (`oauth-discovery`-
        // style libraries) read this to decide which
        // auth method to present at the endpoint.
        let d = DiscoveryDocument::new("https://auth.example.com");
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("revocation_endpoint_auth_methods_supported"),
            "new RFC 8414 field must appear in wire JSON: {json}");
    }
}
