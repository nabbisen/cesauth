//! PKCE (RFC 7636).
//!
//! Only S256 is implemented on purpose. `plain` exists in the RFC for
//! backwards compatibility and offers no protection, and the spec (§4.2)
//! requires Authorization Code + PKCE, so clients that cannot do S256
//! are out of scope.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};

/// Supported code_challenge_method values. Serialized as their OAuth
/// string form for discovery / error responses and for persistence in
/// the `AuthChallenge` DO (via `StoredChallenge`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ChallengeMethod {
    S256,
}

impl ChallengeMethod {
    pub fn parse(s: &str) -> CoreResult<Self> {
        match s {
            "S256"  => Ok(Self::S256),
            // "plain" is explicitly rejected. Per RFC 7636 §4.2, public
            // clients MUST NOT use plain, and confidential clients gain
            // nothing from it either.
            "plain" => Err(CoreError::InvalidRequest("code_challenge_method: plain is not supported")),
            _       => Err(CoreError::InvalidRequest("code_challenge_method: unknown value")),
        }
    }
}

/// Validate that `verifier` produces `challenge` under `method`.
///
/// `verifier` is the raw string from the `code_verifier` form field on
/// the token endpoint. `challenge` is whatever we stored when the
/// authorize request came in. On match, returns `Ok(())`; on mismatch
/// or malformed input, returns `CoreError::PkceMismatch`. The distinction
/// between "malformed" and "mismatch" is deliberately flattened:
/// RFC 6749 wants a single generic error so probing attacks can't tell
/// the difference.
pub fn verify(verifier: &str, challenge: &str, method: ChallengeMethod) -> CoreResult<()> {
    // RFC 7636 §4.1: verifier length must be 43..=128.
    if !(43..=128).contains(&verifier.len()) {
        return Err(CoreError::PkceMismatch);
    }

    match method {
        ChallengeMethod::S256 => {
            let mut hasher = Sha256::new();
            hasher.update(verifier.as_bytes());
            let digest = hasher.finalize();
            let computed = URL_SAFE_NO_PAD.encode(digest);
            // Constant-time compare. Sha256 output plus its base64
            // encoding is not secret, but habits matter.
            if constant_time_eq(computed.as_bytes(), challenge.as_bytes()) {
                Ok(())
            } else {
                Err(CoreError::PkceMismatch)
            }
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-answer test vector from RFC 7636 Appendix B.
    const RFC_VERIFIER:  &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn verify_accepts_rfc_vector() {
        assert!(verify(RFC_VERIFIER, RFC_CHALLENGE, ChallengeMethod::S256).is_ok());
    }

    #[test]
    fn verify_rejects_flipped_bit() {
        // Replace the final character to produce a mismatching challenge.
        let mut bad = RFC_CHALLENGE.to_string();
        bad.pop();
        bad.push('A');
        assert!(verify(RFC_VERIFIER, &bad, ChallengeMethod::S256).is_err());
    }

    #[test]
    fn verify_rejects_short_verifier() {
        // Anything under 43 chars is a protocol error, not a mismatch.
        assert!(verify("tooshort", RFC_CHALLENGE, ChallengeMethod::S256).is_err());
    }

    #[test]
    fn challenge_method_rejects_plain() {
        assert!(ChallengeMethod::parse("plain").is_err());
    }
}
