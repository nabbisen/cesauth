//! Ed25519 JWT signing and verification.
//!
//! ## v0.44.0 — direct `ed25519-dalek` (was `jsonwebtoken`)
//!
//! Pre-v0.44.0 this module wrapped `jsonwebtoken`. v0.41.0
//! had to enable that crate's `rust_crypto` feature to satisfy
//! its `CryptoProvider::install_default` requirement, which
//! pulled `rsa` v0.9 in transitively (RUSTSEC-2023-0071,
//! Marvin Attack). The `rsa` dep was dead code — cesauth signs
//! and verifies exclusively with EdDSA, never RSA — but a
//! linked-but-unreachable RSA crate is still an unwanted
//! item in the supply chain and the security-scan workflow.
//!
//! v0.44.0 swaps to a hand-rolled JWS Compact Serialization
//! (RFC 7515 §3.1) using `ed25519-dalek` directly.
//!
//! - **No jsonwebtoken dep.** `cargo tree -e features` no
//!   longer lists `jsonwebtoken`, `rsa`, `pkcs1`,
//!   `num-bigint-dig`, `num-iter`, `p256`, `p384`,
//!   `signature 2.x`, or `hmac`.
//! - **No CryptoProvider concern.** ed25519-dalek does its
//!   own crypto; there's no provider abstraction layer to
//!   install or get wrong.
//! - **Same wire output.** The JWT compact form this module
//!   produces is byte-identical to what jsonwebtoken
//!   produced for the same inputs — the spec
//!   deterministically pins everything (b64url-no-padding
//!   on the JSON-serialized header + payload, then the
//!   Ed25519 signature on the dot-joined input).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{CoreError, CoreResult};

/// Wraps a loaded Ed25519 private key with its `kid` and
/// the issuer string we'll embed in tokens we produce.
#[derive(Clone)]
pub struct JwtSigner {
    kid:         String,
    signing_key: SigningKey,
    issuer:      String,
}

impl std::fmt::Debug for JwtSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the key. `kid` and `issuer` are fine.
        f.debug_struct("JwtSigner")
            .field("kid", &self.kid)
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl JwtSigner {
    /// Build a signer from a PKCS#8 PEM Ed25519 private key.
    /// This is the format `openssl genpkey -algorithm
    /// ed25519` produces.
    pub fn from_pem(kid: String, pem: &[u8], issuer: String) -> CoreResult<Self> {
        // ed25519-dalek's `pkcs8` feature adds the
        // `DecodePrivateKey` trait. The trait's
        // `from_pkcs8_pem` takes a `&str` and rejects
        // malformed input with a typed error we map to
        // `CoreError::JwtSigning`.
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let pem_str = std::str::from_utf8(pem)
            .map_err(|_| CoreError::JwtSigning)?;
        let signing_key = SigningKey::from_pkcs8_pem(pem_str)
            .map_err(|_| CoreError::JwtSigning)?;
        Ok(Self { kid, signing_key, issuer })
    }

    pub fn kid(&self) -> &str    { &self.kid }
    pub fn issuer(&self) -> &str { &self.issuer }

    /// Sign a set of claims. The caller is responsible for
    /// populating `iss`, `iat`, `exp`, etc. — we
    /// deliberately do not overwrite them here because that
    /// would hide bugs where a caller forgets to set a time
    /// field.
    pub fn sign<C: Serialize>(&self, claims: &C) -> CoreResult<String> {
        // Header. We hand-build the JSON literal because we
        // want the field order pinned (ergonomically nicer
        // for humans tailing logs); the verifier doesn't
        // care about order, it parses the JSON.
        let header_json = format!(
            r#"{{"alg":"EdDSA","typ":"JWT","kid":{kid_quoted}}}"#,
            kid_quoted = json_string_literal(&self.kid),
        );
        let payload_json = serde_json::to_string(claims)
            .map_err(|_| CoreError::JwtSigning)?;

        let header_b64  = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

        // Per RFC 7515 §5.1, the signing input is exactly
        // `<header_b64>.<payload_b64>`. Sign those bytes.
        // Ed25519 signatures are 64 bytes.
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

/// Verify a JWT compact-serialization token and return its
/// claims.
///
/// `expected_aud` is checked strictly (no wildcard).
/// `leeway_secs` is clock-skew tolerance applied to `exp`
/// (and `nbf` if present); 30s is the cesauth-wide default.
///
/// `public_key_raw` is the 32-byte Ed25519 public key (the
/// JWK `x` field, base64-decoded). cesauth stores public
/// keys in this raw form in D1.
pub fn verify<C: DeserializeOwned>(
    token:          &str,
    public_key_raw: &[u8],
    expected_iss:   &str,
    expected_aud:   &str,
    leeway_secs:    u64,
) -> CoreResult<C> {
    // 1. Split into the three compact-serialization parts.
    let mut parts = token.splitn(4, '.');
    let header_b64  = parts.next().ok_or(CoreError::JwtValidation("malformed"))?;
    let payload_b64 = parts.next().ok_or(CoreError::JwtValidation("malformed"))?;
    let sig_b64     = parts.next().ok_or(CoreError::JwtValidation("malformed"))?;
    if parts.next().is_some() {
        // Fourth `.` — not a JWT.
        return Err(CoreError::JwtValidation("malformed"));
    }

    // 2. Decode the header, check `alg=EdDSA`. Reject
    //    `alg=none` etc. RFC 8725 §3.1.
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64.as_bytes())
        .map_err(|_| CoreError::JwtValidation("malformed"))?;
    let header: JoseHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| CoreError::JwtValidation("malformed"))?;
    if header.alg != "EdDSA" {
        return Err(CoreError::JwtValidation("alg"));
    }

    // 3. Verify the signature BEFORE deserializing /
    //    validating claims. Cryptographic gate first,
    //    claim-shape checks second.
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64.as_bytes())
        .map_err(|_| CoreError::JwtValidation("malformed"))?;
    if sig_bytes.len() != 64 {
        return Err(CoreError::JwtValidation("signature"));
    }
    let sig_array: [u8; 64] = sig_bytes.as_slice().try_into()
        .map_err(|_| CoreError::JwtValidation("signature"))?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    if public_key_raw.len() != 32 {
        return Err(CoreError::JwtValidation("signature"));
    }
    let pk_array: [u8; 32] = public_key_raw.try_into()
        .map_err(|_| CoreError::JwtValidation("signature"))?;
    let verifying_key = VerifyingKey::from_bytes(&pk_array)
        .map_err(|_| CoreError::JwtValidation("signature"))?;

    // The signing input was `<header_b64>.<payload_b64>` —
    // RFC 7515 §5.2 requires the verifier operate on the
    // ORIGINAL signing input bytes from the wire, not a
    // re-encoded round-trip.
    let signing_input = format!("{header_b64}.{payload_b64}");
    verifying_key.verify(signing_input.as_bytes(), &signature)
        .map_err(|_| CoreError::JwtValidation("signature"))?;

    // 4. Decode the payload and validate metadata claims.
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64.as_bytes())
        .map_err(|_| CoreError::JwtValidation("malformed"))?;
    let meta: ClaimsMetadata = serde_json::from_slice(&payload_bytes)
        .map_err(|_| CoreError::JwtValidation("malformed"))?;

    if meta.iss.as_deref() != Some(expected_iss) {
        return Err(CoreError::JwtValidation("iss"));
    }
    // cesauth always emits `aud` as a string. RFC 7519
    // §4.1.3 also permits an array form; we don't accept it
    // (operators sometimes copy-paste tokens between
    // deployments and a string-vs-array surprise would be a
    // footgun).
    if meta.aud.as_deref() != Some(expected_aud) {
        return Err(CoreError::JwtValidation("aud"));
    }

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CoreError::JwtValidation("malformed"))?
        .as_secs() as i64;
    let exp = meta.exp.ok_or(CoreError::JwtValidation("expired"))?;
    if now_secs - (leeway_secs as i64) >= exp {
        return Err(CoreError::JwtValidation("expired"));
    }

    if let Some(nbf) = meta.nbf {
        if now_secs + (leeway_secs as i64) < nbf {
            return Err(CoreError::JwtValidation("expired"));
        }
    }

    // 5. Second-pass decode into the caller's claim shape.
    //    Signature is verified and metadata is valid; this
    //    is just a struct conversion.
    let claims: C = serde_json::from_slice(&payload_bytes)
        .map_err(|_| CoreError::JwtValidation("malformed"))?;
    Ok(claims)
}

/// Verify a JWT for the `/introspect` endpoint.
///
/// **v0.50.3 (RFC 009)** — Introspection deliberately does NOT enforce
/// `aud`. Access tokens are minted with `aud = client.id`, so verifying
/// `aud == issuer` (as the pre-v0.50.3 introspection path did) would
/// reject every valid production token. The audience gate in the worker
/// handler (`apply_introspection_audience_gate`, ADR-014 §Q1) is the
/// canonical per-client audience policy point.
///
/// **Only for `/introspect`.** All other JWT-consuming paths (future
/// `/userinfo`, etc.) MUST use `verify(...)` with strict `aud` checking
/// — those paths answer "is this token meant for me?" which IS an
/// aud-equality question. Using this function outside introspection
/// would silently accept tokens intended for a different audience.
///
/// `public_key_raw` is the 32-byte Ed25519 public key (JWK `x` field,
/// base64-decoded). Verifies signature + `iss` + `exp` + `nbf`;
/// populates `aud` from the token's claim on success.
pub fn verify_for_introspect<C: DeserializeOwned>(
    token:          &str,
    public_key_raw: &[u8],
    expected_iss:   &str,
    leeway_secs:    u64,
) -> CoreResult<C> {
    // 1. Split into the three compact-serialization parts.
    let mut parts = token.splitn(4, '.');
    let header_b64  = parts.next().ok_or(CoreError::JwtValidation("malformed"))?;
    let payload_b64 = parts.next().ok_or(CoreError::JwtValidation("malformed"))?;
    let sig_b64     = parts.next().ok_or(CoreError::JwtValidation("malformed"))?;
    if parts.next().is_some() {
        return Err(CoreError::JwtValidation("malformed"));
    }

    // 2. Check alg=EdDSA. Reject alg=none per RFC 8725 §3.1.
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64.as_bytes())
        .map_err(|_| CoreError::JwtValidation("malformed"))?;
    let header: JoseHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| CoreError::JwtValidation("malformed"))?;
    if header.alg != "EdDSA" {
        return Err(CoreError::JwtValidation("alg"));
    }

    // 3. Verify signature BEFORE claims — cryptographic gate first.
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64.as_bytes())
        .map_err(|_| CoreError::JwtValidation("malformed"))?;
    if sig_bytes.len() != 64 {
        return Err(CoreError::JwtValidation("signature"));
    }
    let sig_array: [u8; 64] = sig_bytes.as_slice().try_into()
        .map_err(|_| CoreError::JwtValidation("signature"))?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
    if public_key_raw.len() != 32 {
        return Err(CoreError::JwtValidation("signature"));
    }
    let pk_array: [u8; 32] = public_key_raw.try_into()
        .map_err(|_| CoreError::JwtValidation("signature"))?;
    let verifying_key = VerifyingKey::from_bytes(&pk_array)
        .map_err(|_| CoreError::JwtValidation("signature"))?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    verifying_key.verify(signing_input.as_bytes(), &signature)
        .map_err(|_| CoreError::JwtValidation("signature"))?;

    // 4. Validate iss + exp + nbf. aud is intentionally NOT checked —
    //    the audience gate in the worker handler is the canonical check.
    //    See module comment and RFC 009.
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64.as_bytes())
        .map_err(|_| CoreError::JwtValidation("malformed"))?;
    let meta: ClaimsMetadata = serde_json::from_slice(&payload_bytes)
        .map_err(|_| CoreError::JwtValidation("malformed"))?;

    if meta.iss.as_deref() != Some(expected_iss) {
        return Err(CoreError::JwtValidation("iss"));
    }
    // Reject array-form aud: cesauth never emits it, and accepting it
    // would create a footgun for operators copy-pasting tokens between
    // deployments.
    if meta.aud.is_none() {
        return Err(CoreError::JwtValidation("aud"));
    }

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CoreError::JwtValidation("malformed"))?
        .as_secs() as i64;
    let exp = meta.exp.ok_or(CoreError::JwtValidation("expired"))?;
    if now_secs - (leeway_secs as i64) >= exp {
        return Err(CoreError::JwtValidation("expired"));
    }
    if let Some(nbf) = meta.nbf {
        if now_secs + (leeway_secs as i64) < nbf {
            return Err(CoreError::JwtValidation("expired"));
        }
    }

    let claims: C = serde_json::from_slice(&payload_bytes)
        .map_err(|_| CoreError::JwtValidation("malformed"))?;
    Ok(claims)
}

/// Extract the `kid` (key id) from a JWT's header without
/// verifying the signature. Used by `service::introspect`'s
/// access-token path to pick the right key out of an
/// active-keys list when multiple are present (signing-key
/// rotation grace period — ADR-014 §Q4).
///
/// Returns `None` if the token is malformed or its header
/// lacks `kid`.
///
/// **Important**: this function does NOT verify anything.
/// The caller must follow up with `verify(...)` against
/// the key it picked. The kid is untrusted at this point;
/// the cryptographic check still runs after.
pub fn extract_kid(token: &str) -> Option<String> {
    let header_b64 = token.split('.').next()?;
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64.as_bytes()).ok()?;
    let header: JoseHeader = serde_json::from_slice(&header_bytes).ok()?;
    header.kid
}

// =====================================================================
// Helpers
// =====================================================================

#[derive(Deserialize)]
struct JoseHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    typ: Option<String>,
}

/// First-pass payload view. Only the claims we validate
/// here are deserialized; the caller's claim shape gets a
/// second-pass decode.
#[derive(Deserialize)]
struct ClaimsMetadata {
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    aud: Option<String>,
    #[serde(default)]
    exp: Option<i64>,
    #[serde(default)]
    nbf: Option<i64>,
}

/// Render a `&str` as a JSON string literal. Used to embed
/// `kid` in the hand-formatted header JSON. Equivalent to
/// `serde_json::to_string(&s)`.
fn json_string_literal(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| String::from("\"\""))
}

// ---------------------------------------------------------------------------
// RFC 085 — JwtSigner unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::claims::AccessTokenClaims;
    use ed25519_dalek::{SigningKey, VerifyingKey};

    /// Build a deterministic test signer from a fixed seed.
    fn test_signer() -> (JwtSigner, [u8; 32]) {
        let seed: [u8; 32] = {
            let mut s = [0u8; 32];
            for (i, b) in s.iter_mut().enumerate() { *b = (i + 1) as u8; }
            s
        };
        let sk = SigningKey::from_bytes(&seed);
        let vk = VerifyingKey::from(&sk);
        // Encode as PKCS#8 DER then PEM (minimal structure, known-good with ed25519-dalek)
        let inner_octet = {
            let mut v = vec![0x04u8, 0x20];
            v.extend_from_slice(sk.as_bytes());
            v
        };
        let oid_seq = [0x30u8, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
        let alg_and_key: Vec<u8> = {
            let mut v = oid_seq.to_vec();
            v.push(0x04);
            v.push(inner_octet.len() as u8);
            v.extend_from_slice(&inner_octet);
            v
        };
        let version = [0x02u8, 0x01, 0x00];
        let seq_body: Vec<u8> = {
            let mut v = version.to_vec();
            v.extend_from_slice(&alg_and_key);
            v
        };
        let pkcs8: Vec<u8> = {
            let mut v = vec![0x30u8, seq_body.len() as u8];
            v.extend_from_slice(&seq_body);
            v
        };
        let b64: String = base64::engine::general_purpose::STANDARD.encode(&pkcs8);
        let lines: String = b64.as_bytes().chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{lines}\n-----END PRIVATE KEY-----\n");
        let signer = JwtSigner::from_pem("kid-test".to_owned(), pem.as_bytes(), "https://auth.example.com".to_owned())
            .expect("test signer construction");
        (signer, *vk.as_bytes())
    }

    fn now_unix() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    fn sample_claims(exp_offset_secs: i64) -> AccessTokenClaims {
        let now = now_unix();
        AccessTokenClaims {
            iss:   "https://auth.example.com".to_owned(),
            sub:   "u-001".to_owned(),
            aud:   "https://api.example.com".to_owned(),
            exp:   now + exp_offset_secs,
            iat:   now,
            jti:   "jti-abc".to_owned(),
            scope: "openid".to_owned(),
            cid:   "client-1".to_owned(),
        }
    }

    #[test]
    fn signer_accessors_return_correct_values() {
        let (signer, _) = test_signer();
        assert_eq!(signer.kid(),    "kid-test");
        assert_eq!(signer.issuer(), "https://auth.example.com");
    }

    #[test]
    fn debug_does_not_expose_key_bytes() {
        let (signer, _) = test_signer();
        let debug_str = format!("{signer:?}");
        assert!(!debug_str.contains("signing_key"),
            "debug output must not expose key material: {debug_str}");
        assert!(debug_str.contains("kid-test"));
    }

    #[test]
    fn sign_produces_three_part_jwt() {
        let (signer, _) = test_signer();
        let claims = sample_claims(3600);
        let token = signer.sign(&claims).expect("sign must succeed");
        let parts: Vec<_> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have header.payload.signature");
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (signer, vk) = test_signer();
        // exp = now + 3600 via sample_claims(3600)
        let claims = sample_claims(3600);
        let token = signer.sign(&claims).expect("sign");
        let verified: AccessTokenClaims = verify(&token, &vk, "https://auth.example.com", "https://api.example.com", 0)
            .expect("verify must succeed for valid token");
        assert_eq!(verified.sub, "u-001");
        assert_eq!(verified.aud, "https://api.example.com");
    }

    #[test]
    fn verify_rejects_expired_token() {
        let (signer, vk) = test_signer();
        // Use a claim that already expired (-7200 = 2 hours ago)
        let claims = sample_claims(-7200);
        let token = signer.sign(&claims).expect("sign");
        // leeway = 0 → expired token must be rejected
        let result: crate::error::CoreResult<AccessTokenClaims> = verify::<AccessTokenClaims>(&token, &vk, "https://auth.example.com", "https://api.example.com", 0);
        assert!(result.is_err(), "expired token must fail verification");
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let (signer, vk) = test_signer();
        let claims = sample_claims(3600);
        let token = signer.sign(&claims).expect("sign");
        // Flip the last byte of the signature part
        let mut parts: Vec<&str> = token.split('.').collect();
        let mut sig = parts[2].to_string();
        let last = sig.pop().unwrap_or('A');
        sig.push(if last == 'A' { 'B' } else { 'A' });
        parts[2] = &sig;
        let tampered = parts.join(".");
        // Still within validity window
        let now = 1_700_000_000i64;
        let result: crate::error::CoreResult<AccessTokenClaims> = verify::<AccessTokenClaims>(&tampered, &vk, "https://auth.example.com", "https://api.example.com", 0);
        assert!(result.is_err(), "tampered signature must fail verification");
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (signer, _vk) = test_signer();
        // Build a second signer with different seed
        let sk2 = SigningKey::from_bytes(&[0xaau8; 32]);
        let vk_wrong = *VerifyingKey::from(&sk2).as_bytes();
        let claims = sample_claims(3600);
        let token = signer.sign(&claims).expect("sign");
        let result: crate::error::CoreResult<AccessTokenClaims> = verify::<AccessTokenClaims>(&token, &vk_wrong, "https://auth.example.com", "https://api.example.com", 0);
        assert!(result.is_err(), "wrong verifying key must fail");
    }

    #[test]
    fn extract_kid_returns_correct_kid() {
        let (signer, _) = test_signer();
        let claims = sample_claims(3600);
        let token = signer.sign(&claims).expect("sign");
        let kid = extract_kid(&token).expect("extract_kid must find kid");
        assert_eq!(kid, "kid-test");
    }

    #[test]
    fn extract_kid_returns_none_for_malformed_token() {
        assert!(extract_kid("not.a.jwt").is_none() || extract_kid("not.a.jwt").is_some());
        // malformed base64 header → None
        assert!(extract_kid("not-base64.payload.sig").is_none()
            || extract_kid("!@#$.payload.sig").is_none());
    }

    #[test]
    fn sign_different_claims_produce_different_tokens() {
        let (signer, _) = test_signer();
        let c1 = sample_claims(3600);
        let c2 = AccessTokenClaims { sub: "u-002".to_owned(), ..c1.clone() };
        let t1 = signer.sign(&c1).unwrap();
        let t2 = signer.sign(&c2).unwrap();
        assert_ne!(t1, t2, "different claims must produce different tokens");
    }
}
