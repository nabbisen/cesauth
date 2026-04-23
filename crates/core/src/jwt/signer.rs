//! Ed25519 JWT signing.
//!
//! We wrap `jsonwebtoken` rather than reaching for `ed25519-dalek`
//! directly: this lets us stay on the maintained crate's happy path and
//! avoid rolling our own header/base64 serialization.
//!
//! **WASM caveat.** `jsonwebtoken` depends on `ring` on native targets
//! but uses pure-Rust backends for `wasm32-unknown-unknown`. Per spec
//! §6.2, we must verify in CI that the release build of the worker
//! crate actually links under the WASM target. If `ring` creeps back in
//! (for example via a transitive dev-dependency), swap to
//! `josekit` + `ed25519-dalek` rather than shipping broken code.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Serialize, de::DeserializeOwned};

use crate::error::{CoreError, CoreResult};

/// Wraps a loaded Ed25519 private key with its `kid`. Cheap to clone -
/// the inner `EncodingKey` is already a reference-counted handle.
#[derive(Clone)]
pub struct JwtSigner {
    kid:          String,
    encoding_key: EncodingKey,
    issuer:       String,
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
    /// Build a signer from a PKCS#8 PEM private key. This is the format
    /// `openssl genpkey -algorithm ed25519` produces.
    pub fn from_pem(kid: String, pem: &[u8], issuer: String) -> CoreResult<Self> {
        let encoding_key = EncodingKey::from_ed_pem(pem)
            .map_err(|_| CoreError::JwtSigning)?;
        Ok(Self { kid, encoding_key, issuer })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Sign a set of claims. The caller is responsible for populating
    /// `iss`, `iat`, `exp`, etc. - we deliberately do not overwrite them
    /// here because that would hide bugs where a caller forgets to set a
    /// time field.
    pub fn sign<C: Serialize>(&self, claims: &C) -> CoreResult<String> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        encode(&header, claims, &self.encoding_key)
            .map_err(|_| CoreError::JwtSigning)
    }
}

/// Verify a JWT and return its claims.
///
/// `expected_aud` is checked strictly (no wildcard). `leeway` is clock
/// skew tolerance in seconds - we use a small value (30s) because
/// Workers has a generally reliable clock.
pub fn verify<C: DeserializeOwned>(
    token:          &str,
    public_key_raw: &[u8],
    expected_iss:   &str,
    expected_aud:   &str,
    leeway_secs:    u64,
) -> CoreResult<C> {
    // DecodingKey for EdDSA wants the raw 32-byte public key.
    let decoding_key = DecodingKey::from_ed_der(public_key_raw);

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[expected_iss]);
    validation.set_audience(&[expected_aud]);
    validation.leeway = leeway_secs;
    // RFC 8725 §3.1: pin the algorithm. jsonwebtoken defaults to a
    // whitelist of one, but being explicit costs nothing.
    validation.algorithms = vec![Algorithm::EdDSA];

    decode::<C>(token, &decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature    => CoreError::JwtValidation("expired"),
            jsonwebtoken::errors::ErrorKind::InvalidIssuer       => CoreError::JwtValidation("iss"),
            jsonwebtoken::errors::ErrorKind::InvalidAudience     => CoreError::JwtValidation("aud"),
            jsonwebtoken::errors::ErrorKind::InvalidSignature    => CoreError::JwtValidation("signature"),
            jsonwebtoken::errors::ErrorKind::InvalidAlgorithmName
            | jsonwebtoken::errors::ErrorKind::InvalidAlgorithm  => CoreError::JwtValidation("alg"),
            _ => CoreError::JwtValidation("malformed"),
        })
}
