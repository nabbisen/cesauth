//! Magic Link fallback (spec §4.1 step 4).
//!
//! Fires only when Passkey enrollment does not exist or has failed. The
//! transport is an email with a one-time code; we don't also support
//! SMS, because the spec forbids it and because SMS OTP has a long
//! history of SIM-swap attacks.
//!
//! Storage split:
//! * The current, unused OTP hash lives in the `AuthChallenge` Durable
//!   Object (strong consistency: at-most-once consumption).
//! * Delivery metadata (send time, attempt counter) lives in the same
//!   DO. Audit trail of *attempts* goes to R2 through the worker layer.
//!
//! We never store the plaintext OTP. The DO keeps only a hash.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use getrandom::getrandom;
use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};

/// Length of the plaintext code the user types back in. 8 base32-ish
/// characters is ~40 bits of entropy, which is safe inside a 10-minute
/// window and tolerant to mistyping at this length.
const OTP_LEN: usize = 8;

/// Base32-ish alphabet: no 0/O/1/I/L to reduce transcription errors.
/// Case-insensitive on input; we uppercase before compare.
const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

/// A freshly minted OTP and the hash to store for later verification.
#[derive(Debug, Clone)]
pub struct IssuedOtp {
    /// Send this to the user. Never log or persist verbatim.
    pub code_plaintext: String,
    /// Store this hash in the AuthChallenge DO.
    pub code_hash:      String,
    /// Absolute expiry in unix seconds. The DO enforces this, but we
    /// return it so the caller can surface "valid for N minutes" UX.
    pub expires_at:     i64,
}

/// Mint an OTP.
///
/// `ttl_secs` is the lifetime measured from `now`. The caller supplies
/// `now` because Workers test environments like to control the clock.
pub fn issue(now_unix: i64, ttl_secs: i64) -> CoreResult<IssuedOtp> {
    let mut buf = [0u8; OTP_LEN];
    getrandom(&mut buf).map_err(|_| CoreError::Internal)?;

    let mut code = String::with_capacity(OTP_LEN);
    for &b in &buf {
        // Uniform-ish modulo is acceptable here because ALPHABET.len()
        // (31) divides 2^8=256 close to evenly; bias is well below the
        // entropy margin we actually need.
        let idx = (b as usize) % ALPHABET.len();
        code.push(ALPHABET[idx] as char);
    }

    let code_hash = hash(&code);
    Ok(IssuedOtp {
        code_plaintext: code,
        code_hash,
        expires_at: now_unix.saturating_add(ttl_secs),
    })
}

/// Verify a user-supplied OTP against a stored hash.
///
/// This is a pure function: no side effects, no storage. The *consumer*
/// (the AuthChallenge DO) is responsible for ensuring a hash can be
/// used at most once - this function just says whether the bytes match.
pub fn verify(submitted: &str, stored_hash: &str, now_unix: i64, expires_at: i64) -> CoreResult<()> {
    if now_unix > expires_at {
        return Err(CoreError::MagicLinkExpired);
    }
    // Normalize: strip whitespace and uppercase. Email clients sometimes
    // word-wrap or add zero-width characters; we accept mild mangling
    // but nothing structural.
    let normalized: String = submitted
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_uppercase)
        .collect();

    let submitted_hash = hash(&normalized);
    if constant_time_eq(submitted_hash.as_bytes(), stored_hash.as_bytes()) {
        Ok(())
    } else {
        Err(CoreError::MagicLinkMismatch)
    }
}

fn hash(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
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
mod tests;
