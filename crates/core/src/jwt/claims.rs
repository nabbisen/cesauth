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

// ---------------------------------------------------------------------------
// RFC 060 — JWT claims serialization tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── AccessTokenClaims ─────────────────────────────────────────────────

    #[test]
    fn access_token_claims_round_trip_json() {
        let c = AccessTokenClaims {
            iss:   "https://auth.example.com".to_owned(),
            sub:   "u-001".to_owned(),
            aud:   "https://api.example.com".to_owned(),
            exp:   1_700_001_000,
            iat:   1_700_000_000,
            jti:   "jti-abc".to_owned(),
            scope: "openid email".to_owned(),
            cid:   "client-1".to_owned(),
        };
        let json  = serde_json::to_string(&c).unwrap();
        let back: AccessTokenClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sub, "u-001");
        assert_eq!(back.scope, "openid email");
        assert_eq!(back.cid, "client-1");
    }

    #[test]
    fn access_token_claims_contains_all_required_fields() {
        let c = AccessTokenClaims {
            iss: "i".to_owned(), sub: "s".to_owned(), aud: "a".to_owned(),
            exp: 2000, iat: 1000, jti: "j".to_owned(),
            scope: "openid".to_owned(), cid: "c".to_owned(),
        };
        let json = serde_json::to_string(&c).unwrap();
        for field in &["iss", "sub", "aud", "exp", "iat", "jti", "scope", "cid"] {
            assert!(json.contains(field), "JWT must contain field {field}");
        }
    }

    // ── IdTokenClaims ─────────────────────────────────────────────────────

    #[test]
    fn id_token_nonce_omitted_when_none() {
        let c = IdTokenClaims {
            iss: "i".to_owned(), sub: "s".to_owned(), aud: "a".to_owned(),
            exp: 2000, iat: 1000, auth_time: 900,
            nonce: None, email: None, email_verified: None, name: None,
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(!json.contains("nonce"),          "absent nonce must not appear in JSON");
        assert!(!json.contains("email"),          "absent email must not appear in JSON");
        assert!(!json.contains("email_verified"), "absent email_verified must not appear");
        assert!(!json.contains("\"name\""),       "absent name must not appear in JSON");
    }

    #[test]
    fn id_token_optional_fields_present_when_some() {
        let c = IdTokenClaims {
            iss: "i".to_owned(), sub: "s".to_owned(), aud: "a".to_owned(),
            exp: 2000, iat: 1000, auth_time: 900,
            nonce: Some("n123".to_owned()),
            email: Some("u@example.com".to_owned()),
            email_verified: Some(true),
            name: Some("Alice".to_owned()),
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"nonce\""));
        assert!(json.contains("\"email\""));
        assert!(json.contains("\"email_verified\""));
        assert!(json.contains("\"name\""));
    }

    // ── Jwk ───────────────────────────────────────────────────────────────

    #[test]
    fn jwk_ed25519_constructor() {
        let jwk = Jwk::ed25519("kid-1".to_owned(), "base64urlpubkey".to_owned());
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, "Ed25519");
        assert_eq!(jwk.alg, "EdDSA");
        assert_eq!(jwk.use_, "sig");
        assert_eq!(jwk.kid, "kid-1");
        assert_eq!(jwk.x, "base64urlpubkey");
    }

    #[test]
    fn jwks_document_serializes_keys_array() {
        let doc = JwksDocument {
            keys: vec![Jwk::ed25519("k1".to_owned(), "x1".to_owned())],
        };
        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"keys\""), "JWKS must have keys array");
        assert!(json.contains("\"OKP\""));
        assert!(json.contains("\"k1\""));
        // RFC 7517: `use` field name (serialized as "use" not "use_")
        assert!(json.contains("\"use\""), "JWK must serialize use_ as \"use\"");
    }
}
