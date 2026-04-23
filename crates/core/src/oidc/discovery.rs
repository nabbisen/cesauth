//! `/.well-known/openid-configuration`.
//!
//! We emit a deliberately narrow discovery document: only the flows and
//! algorithms cesauth actually supports. Listing capabilities we do not
//! implement would mislead relying parties.

use serde::Serialize;

/// The subset of OpenID Connect Discovery 1.0 metadata we support.
///
/// This is built *per-issuer* at request time (cheap) and then cached in
/// KV by the worker layer (`CACHE` binding). KV is acceptable here
/// because a stale discovery doc can never let an attacker forge a
/// token - the worst case is a client seeing an old endpoint URL.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryDocument {
    pub issuer:                                String,
    pub authorization_endpoint:                String,
    pub token_endpoint:                        String,
    pub jwks_uri:                              String,
    pub revocation_endpoint:                   String,
    pub response_types_supported:              &'static [&'static str],
    pub subject_types_supported:               &'static [&'static str],
    pub id_token_signing_alg_values_supported: &'static [&'static str],
    pub token_endpoint_auth_methods_supported: &'static [&'static str],
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
            response_types_supported:              &["code"],
            subject_types_supported:               &["public"],
            // EdDSA only. If we ever add another algorithm we MUST also
            // teach the verifier side; do not silently widen this list.
            id_token_signing_alg_values_supported: &["EdDSA"],
            token_endpoint_auth_methods_supported: &[
                "none",
                "client_secret_basic",
                "client_secret_post",
            ],
            code_challenge_methods_supported:      &["S256"],   // plain is forbidden
            grant_types_supported:                 &["authorization_code", "refresh_token"],
            scopes_supported:                      &["openid", "profile", "email", "offline_access"],
        }
    }
}
