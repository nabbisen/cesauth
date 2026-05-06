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
