//! JWT claim structures and the JWKS document.
//!
//! We keep access-token claims minimal: an overly chatty access token is
//! a privacy and log-bloat problem, and anything downstream resource
//! servers need can be re-derived from `sub` + a userinfo call.

use serde::{Deserialize, Serialize};

/// Claims embedded in access tokens.
///
/// `aud` is a single value (not the RFC-permitted array) because cesauth
/// issues one token per audience. Multi-audience tokens complicate
/// revocation accounting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss:   String,
    pub sub:   String,
    pub aud:   String,
    pub exp:   i64,
    pub iat:   i64,
    pub jti:   String,
    pub scope: String,
    /// Client the token was issued to. Distinct from `aud`: a client can
    /// request a token for a resource audience that is not itself.
    pub cid:   String,
}

/// Claims embedded in id tokens (OIDC core §2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss:   String,
    pub sub:   String,
    pub aud:   String,
    pub exp:   i64,
    pub iat:   i64,
    pub auth_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name:  Option<String>,
}

/// A single JSON Web Key (RFC 7517), narrowed to the OKP / Ed25519 case.
///
/// We do not implement RSA or EC keys. If we ever need to, that's a new
/// variant, not a stringly-typed `alg` field.
///
/// `Jwk` is a server-side output only: cesauth is the identity provider
/// and publishes JWKS; it never parses a foreign JWKS (it is not an OIDC
/// relying party). That lets us use `&'static str` for the fixed fields
/// and skip `Deserialize`.
#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    pub kty: &'static str,  // always "OKP"
    pub crv: &'static str,  // always "Ed25519"
    pub alg: &'static str,  // always "EdDSA"
    #[serde(rename = "use")]
    pub use_: &'static str, // always "sig"
    pub kid: String,
    /// Base64url-encoded 32-byte public key, no padding.
    pub x: String,
}

impl Jwk {
    pub fn ed25519(kid: String, x_b64url_nopad: String) -> Self {
        Self {
            kty: "OKP",
            crv: "Ed25519",
            alg: "EdDSA",
            use_: "sig",
            kid,
            x: x_b64url_nopad,
        }
    }
}

/// The `/jwks.json` document.
#[derive(Debug, Clone, Serialize)]
pub struct JwksDocument {
    pub keys: Vec<Jwk>,
}
