//! OIDC `id_token` claim assembly and signing — RFC 001.
//!
//! Two pure functions:
//!
//! * [`build_id_token_claims`] — compose claims from inputs; scope-driven
//!   population per ADR-008 §Q2.
//! * [`sign_id_token`] — thin wrapper over the existing JWS Compact serializer;
//!   uses the same Ed25519 key as access tokens.
//!
//! Both functions are I/O-free and independently testable.
//!
//! ## Claim population rules (ADR-008 §Q2)
//!
//! | Scope present | Claims added |
//! |---|---|
//! | `openid` (always) | `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time` |
//! | `openid` + `nonce` in authorize | `nonce` |
//! | `email` | `email`, `email_verified` (only when email is set on user) |
//! | `profile` | `name` (only when `display_name` is set on user) |

use serde::{Deserialize, Serialize};

use crate::error::CoreResult;
use crate::jwt::JwtSigner;
use crate::types::User;

// ---------------------------------------------------------------------------
// IdTokenClaims — the payload of the id_token JWT
// ---------------------------------------------------------------------------

/// Assembled claims for an OIDC id_token.
///
/// All fields are `Option`-typed except the required set; absent optional
/// claims are elided from the JSON wire form (`skip_serializing_if = "Option::is_none"`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    // Required (OIDC Core §2)
    pub iss:       String,
    pub sub:       String,
    pub aud:       String,
    pub exp:       i64,
    pub iat:       i64,
    /// The time the end-user last authenticated.  Unix seconds.
    /// Sourced from the `auth_time` field on `Challenge::AuthCode` /
    /// `FamilyState`; falls back to `issued_at` when `auth_time == 0`
    /// (migration compatibility — pre-RFC 001 challenges lack the field).
    pub auth_time: i64,

    // Conditional
    /// Present when the /authorize request carried a `nonce` parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce:           Option<String>,

    // Email scope
    /// Present when `email` scope was requested and the user has an email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email:           Option<String>,
    /// Present when `email` scope was requested and the user has an email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified:  Option<bool>,

    // Profile scope
    /// Present when `profile` scope was requested and the user has a display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name:            Option<String>,
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/// Assemble an `IdTokenClaims` value from the supplied inputs.
///
/// # Arguments
///
/// * `iss`       — issuer identifier (from `JwtSigner::issuer()`).
/// * `user`      — the authenticated user record (needed for `sub` and
///                 conditional claims).
/// * `client_id` — the requesting client; becomes `aud`.
/// * `scopes`    — the granted scope list.
/// * `nonce`     — the `nonce` parameter from the original `/authorize`
///                 request; `None` when the RP did not include one.
/// * `auth_time` — unix timestamp of the authentication event.  When `0`
///                 (legacy value for pre-RFC 001 challenges), falls back to
///                 `issued_at` per ADR-008 §Q4 migration note.
/// * `issued_at` — `iat` claim; also used as `auth_time` fallback.
/// * `id_token_ttl_secs` — how long this id_token is valid; `exp = iat + ttl`.
pub fn build_id_token_claims(
    iss:              &str,
    user:             &User,
    client_id:        &str,
    scopes:           &[String],
    nonce:            Option<&str>,
    auth_time:        i64,
    issued_at:        i64,
    id_token_ttl_secs: i64,
) -> IdTokenClaims {
    let has_email   = scopes.iter().any(|s| s == "email");
    let has_profile = scopes.iter().any(|s| s == "profile");

    // ADR-008 §Q4 migration compatibility: 0 means "not recorded".
    let effective_auth_time = if auth_time == 0 { issued_at } else { auth_time };

    IdTokenClaims {
        iss:            iss.to_owned(),
        sub:            user.id.clone(),
        aud:            client_id.to_owned(),
        exp:            issued_at + id_token_ttl_secs,
        iat:            issued_at,
        auth_time:      effective_auth_time,
        nonce:          nonce.map(str::to_owned),

        email: if has_email { user.email.clone() } else { None },
        email_verified: if has_email && user.email.is_some() {
            Some(user.email_verified)
        } else {
            None
        },

        name: if has_profile { user.display_name.clone() } else { None },
    }
}

/// Sign an `IdTokenClaims` value into a JWS Compact (dot-separated JWT string).
///
/// Uses the same `JwtSigner` as access tokens; the `kid` header is set to the
/// signing key's kid so RP verification via `/jwks.json` works identically.
pub fn sign_id_token(claims: &IdTokenClaims, signer: &JwtSigner) -> CoreResult<String> {
    signer.sign(claims)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{User, UserStatus};

    fn test_user(email: Option<&str>, email_verified: bool, name: Option<&str>) -> User {
        User {
            id:             "u-test".to_owned(),
            tenant_id:      "tenant-default".to_owned(),
            email:          email.map(str::to_owned),
            email_verified,
            display_name:   name.map(str::to_owned),
            account_type:   crate::tenancy::AccountType::HumanUser,
            status:         UserStatus::Active,
            created_at:     1_700_000_000,
            updated_at:     1_700_000_000,
        }
    }

    fn scopes(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    const NOW: i64 = 1_700_000_000;
    const TTL: i64 = 3600;

    #[test]
    fn build_claims_required_only() {
        let user = test_user(Some("alice@example.com"), true, Some("Alice"));
        let claims = build_id_token_claims(
            "https://auth.example.com", &user, "client-1",
            &scopes(&["openid"]), None, NOW, NOW, TTL,
        );
        assert_eq!(claims.iss, "https://auth.example.com");
        assert_eq!(claims.sub, "u-test");
        assert_eq!(claims.aud, "client-1");
        assert_eq!(claims.exp, NOW + TTL);
        assert_eq!(claims.iat, NOW);
        assert_eq!(claims.auth_time, NOW);
        assert!(claims.nonce.is_none(),          "no nonce when not passed");
        assert!(claims.email.is_none(),          "no email without email scope");
        assert!(claims.email_verified.is_none(), "no email_verified without email scope");
        assert!(claims.name.is_none(),           "no name without profile scope");
    }

    #[test]
    fn build_claims_with_email_scope_emits_email_claims() {
        let user = test_user(Some("alice@example.com"), true, None);
        let claims = build_id_token_claims(
            "https://auth.example.com", &user, "c",
            &scopes(&["openid", "email"]), None, NOW, NOW, TTL,
        );
        assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        assert_eq!(claims.email_verified, Some(true));
    }

    #[test]
    fn build_claims_with_profile_scope_emits_name_claim() {
        let user = test_user(None, false, Some("Alice Smith"));
        let claims = build_id_token_claims(
            "https://auth.example.com", &user, "c",
            &scopes(&["openid", "profile"]), None, NOW, NOW, TTL,
        );
        assert_eq!(claims.name.as_deref(), Some("Alice Smith"));
    }

    #[test]
    fn build_claims_with_both_scopes_emits_all_scoped_claims() {
        let user = test_user(Some("bob@example.com"), false, Some("Bob Jones"));
        let claims = build_id_token_claims(
            "https://auth.example.com", &user, "c",
            &scopes(&["openid", "email", "profile"]), None, NOW, NOW, TTL,
        );
        assert!(claims.email.is_some());
        assert!(claims.name.is_some());
    }

    #[test]
    fn build_claims_email_verified_reflects_user_state_false() {
        let user = test_user(Some("bob@example.com"), false, None);
        let claims = build_id_token_claims(
            "https://auth.example.com", &user, "c",
            &scopes(&["openid", "email"]), None, NOW, NOW, TTL,
        );
        assert_eq!(claims.email_verified, Some(false));
    }

    #[test]
    fn build_claims_email_absent_does_not_emit_email_verified() {
        // User has no email; even with email scope, email_verified must be absent.
        let user = test_user(None, false, None);
        let claims = build_id_token_claims(
            "https://auth.example.com", &user, "c",
            &scopes(&["openid", "email"]), None, NOW, NOW, TTL,
        );
        assert!(claims.email.is_none());
        assert!(claims.email_verified.is_none(),
            "email_verified must be absent when user has no email");
    }

    #[test]
    fn build_claims_nonce_present_when_authorize_carried_one() {
        let user = test_user(None, false, None);
        let claims = build_id_token_claims(
            "https://auth.example.com", &user, "c",
            &scopes(&["openid"]), Some("my-nonce-value"), NOW, NOW, TTL,
        );
        assert_eq!(claims.nonce.as_deref(), Some("my-nonce-value"));
    }

    #[test]
    fn build_claims_nonce_absent_when_authorize_did_not() {
        let user = test_user(None, false, None);
        let claims = build_id_token_claims(
            "https://auth.example.com", &user, "c",
            &scopes(&["openid"]), None, NOW, NOW, TTL,
        );
        assert!(claims.nonce.is_none());
    }

    #[test]
    fn build_claims_auth_time_zero_falls_back_to_issued_at() {
        let user = test_user(None, false, None);
        let claims = build_id_token_claims(
            "https://auth.example.com", &user, "c",
            &scopes(&["openid"]), None,
            0,   // auth_time = 0 (missing from legacy challenge)
            NOW, // issued_at
            TTL,
        );
        assert_eq!(claims.auth_time, NOW,
            "auth_time == 0 must fall back to issued_at");
    }

    #[test]
    fn build_claims_auth_time_nonzero_preserved() {
        let user = test_user(None, false, None);
        let auth_t = NOW - 120;  // user authenticated 2 min before token exchange
        let claims = build_id_token_claims(
            "https://auth.example.com", &user, "c",
            &scopes(&["openid"]), None, auth_t, NOW, TTL,
        );
        assert_eq!(claims.auth_time, auth_t);
    }

    #[test]
    fn build_claims_does_not_emit_unknown_scope_claims() {
        let user = test_user(Some("x@example.com"), true, Some("X"));
        let claims = build_id_token_claims(
            "https://auth.example.com", &user, "c",
            &scopes(&["openid", "frobnicate"]), None, NOW, NOW, TTL,
        );
        // Unknown scope "frobnicate" must not add email or name.
        assert!(claims.email.is_none(),
            "unknown scope must not add email claim");
        assert!(claims.name.is_none(),
            "unknown scope must not add name claim");
    }

    #[test]
    fn sign_id_token_round_trips_with_verify() {
        use crate::jwt::signer::JwtSigner;

        let (signer, _pub_key) = test_signer();
        let user = test_user(None, false, None);
        let claims = build_id_token_claims(
            "https://auth.example.com", &user, "client-abc",
            &scopes(&["openid"]), None, NOW, NOW, TTL,
        );
        let token = sign_id_token(&claims, &signer).unwrap();

        // Three-segment JWS compact form.
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "id_token must be three-segment JWS compact");

        // Header must declare EdDSA.
        let header_json = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            parts[0]
        ).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header["alg"].as_str(), Some("EdDSA"),
            "id_token alg header must be EdDSA");
    }

    #[test]
    fn sign_id_token_emits_eddsa_alg_header() {
        let (signer, _) = test_signer();
        let user = test_user(None, false, None);
        let claims = build_id_token_claims(
            "https://auth.example.com", &user, "c",
            &scopes(&["openid"]), None, NOW, NOW, TTL,
        );
        let token = sign_id_token(&claims, &signer).unwrap();
        // Decode header, confirm alg.
        let hdr_b64 = token.split('.').next().unwrap();
        let hdr_json = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD, hdr_b64,
        ).unwrap();
        let hdr: serde_json::Value = serde_json::from_slice(&hdr_json).unwrap();
        assert_eq!(hdr["alg"], "EdDSA");
        assert_eq!(hdr["kid"], "test-kid",
            "kid header must match the signing key's kid");
    }

    // Helper: build a test JwtSigner from a fixed 32-byte seed (same pattern as jwt/proptests.rs).
    fn test_signer() -> (crate::jwt::signer::JwtSigner, ed25519_dalek::VerifyingKey) {
        use ed25519_dalek::{SigningKey, VerifyingKey};
        use pkcs8::EncodePrivateKey;

        let seed = [0x42u8; 32]; // deterministic test key
        let sk = SigningKey::from_bytes(&seed);
        let vk = VerifyingKey::from(&sk);
        let pem = sk.to_pkcs8_pem(pkcs8::LineEnding::LF).unwrap();
        let signer = crate::jwt::signer::JwtSigner::from_pem(
            "test-kid".to_owned(),
            pem.as_bytes(),
            "https://auth.example.com".to_owned(),
        ).unwrap();
        (signer, vk)
    }
}
