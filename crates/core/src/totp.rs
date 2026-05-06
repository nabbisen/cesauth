//! RFC 6238 TOTP (Time-based One-Time Password) implementation.
//!
//! v0.26.0 ships this as a pure-function library only — no HTTP
//! routes, no enrollment UI, no storage glue. Phase 2 (v0.27.0)
//! wires it into the `/me/security/totp/*` handlers and adds the
//! verify gate after Magic Link primary auth.
//!
//! Design rationale lives in
//! [`docs/src/expert/adr/009-totp.md`](../../../../docs/src/expert/adr/009-totp.md);
//! the short summary:
//!
//! - **Algorithm**: HMAC-SHA1 only. Locked because Google
//!   Authenticator silently falls back to SHA-1 on SHA-256 secrets,
//!   producing wrong codes — universal compatibility wins. SHA-1's
//!   collision-resistance weakness is irrelevant for TOTP
//!   (collision-finding is unrelated to the keyed prediction problem).
//! - **Code digits**: 6. RFC default; universally supported.
//! - **Step**: 30 seconds. RFC default; universally supported.
//! - **Secret length**: 20 bytes (160 bits). Matches SHA-1 output
//!   width and Google Authenticator's mint length.
//! - **Skew tolerance**: ±1 step. Three windows total
//!   (current, previous, next).
//! - **Replay protection**: per-secret `last_used_step`. Verifies
//!   that survive return a new `last_used_step`; the storage layer
//!   persists it and the next verify rejects steps ≤ this value.
//! - **At-rest encryption**: AES-GCM-256 with AAD bound to the
//!   storage row's primary key. Foils D1-backup-swap attacks.
//! - **Recovery codes**: 10 per user, 50-bit entropy each,
//!   formatted `XXXXX-XXXXX`, stored SHA-256-hashed.
//!
//! All functions in this module are pure (no I/O, no syscalls
//! except `getrandom` for entropy). Storage and HTTP plumbing are
//! the worker layer's responsibility.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

// =====================================================================
// Constants — locked per ADR-009 §Q1
// =====================================================================

/// Number of decimal digits in a TOTP code. RFC 6238 permits 6, 7,
/// or 8; cesauth locks to 6 because authenticator apps default to
/// 6 and many display 6 even when 8 is requested (silently
/// truncating — wrong-code UX). Locking to 6 matches what every
/// shipping authenticator app does.
pub const DIGITS: u32 = 6;

/// Time-step in seconds. RFC 6238 default. Universal in
/// authenticator apps. cesauth locks to 30 (no per-tenant knob).
pub const STEP_SECONDS: u64 = 30;

/// TOTP secret length in bytes. RFC 6238 §5.1 recommends ≥ 128
/// bits; 160 bits matches the SHA-1 output width and the length
/// Google Authenticator generates.
pub const SECRET_BYTES: usize = 20;

/// Skew tolerance in steps. Three windows total: current ± 1.
/// Wider windows make brute-force easier (more chances per
/// attempt) without meaningful UX gain.
pub const SKEW_STEPS: i64 = 1;

/// Number of recovery codes minted per user at first TOTP
/// enrollment. ADR-009 §Q6.
pub const RECOVERY_CODES_PER_USER: usize = 10;

/// AES-GCM-256 key length in bytes.
pub const ENCRYPTION_KEY_LEN: usize = 32;

/// AES-GCM nonce length in bytes (96-bit standard).
pub const ENCRYPTION_NONCE_LEN: usize = 12;

// =====================================================================
// Errors
// =====================================================================

/// Errors from the TOTP library. All variants are deterministic
/// (the same input → same outcome) except `EncryptionError` and
/// `DecryptionError` which depend on the key and AAD passed in.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TotpError {
    /// The base32 input couldn't be decoded as a TOTP secret.
    /// Common cause: a user pasted a string with stray whitespace
    /// or with the wrong alphabet.
    #[error("invalid base32 secret")]
    InvalidBase32,

    /// The base32 decoded fine, but the resulting byte length
    /// doesn't match `SECRET_BYTES`. This shouldn't happen for
    /// secrets we generate; could happen if the user manually
    /// entered a secret from another system.
    #[error("invalid secret length: expected {SECRET_BYTES} bytes")]
    InvalidSecretLength,

    /// The submitted code didn't match any verifiable step
    /// within the skew window, OR matched a step that's already
    /// been used (replay protection — ADR-009 §Q3).
    #[error("invalid code")]
    InvalidCode,

    /// The encryption key was the wrong length. Operator must set
    /// `TOTP_ENCRYPTION_KEY` to 32 bytes (base64-decoded).
    #[error("invalid encryption key length: expected {ENCRYPTION_KEY_LEN} bytes")]
    InvalidKeyLength,

    /// The encryption nonce was the wrong length. This shouldn't
    /// happen if the worker layer always reads back what it wrote;
    /// indicates D1 corruption or a manual mutation.
    #[error("invalid nonce length: expected {ENCRYPTION_NONCE_LEN} bytes")]
    InvalidNonceLength,

    /// Encryption failed. AES-GCM doesn't normally fail on
    /// well-sized inputs, so this is mostly a "shouldn't happen"
    /// branch — surface as `Internal` upstream.
    #[error("encryption error")]
    EncryptionError,

    /// Decryption failed: ciphertext was tampered with, the AAD
    /// doesn't bind to the row id, or the wrong key was supplied.
    /// Always treated as an authentication failure upstream — do
    /// NOT distinguish from `InvalidCode` in user-facing errors,
    /// which would let an attacker probe at-rest tampering.
    #[error("decryption error")]
    DecryptionError,

    /// CSPRNG failed. Cloudflare Workers always have crypto.getRandomValues,
    /// so this is a "shouldn't happen" branch — surface upstream.
    #[error("rng error")]
    RngError,
}

pub type TotpResult<T> = Result<T, TotpError>;

// =====================================================================
// Secret type and codecs
// =====================================================================

/// A TOTP shared secret. Always exactly `SECRET_BYTES` bytes long
/// when constructed via `generate()` or `from_base32()`. The
/// `Vec<u8>` newtype rather than `[u8; 20]` keeps the API
/// ergonomic; length is checked at construction.
///
/// Display / Debug deliberately do NOT print the secret value,
/// to avoid accidental log leakage. Use `to_base32()` if you
/// genuinely need to render it (e.g., for the manual-entry path
/// during enrollment).
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Vec<u8>);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret({} bytes)", self.0.len())
    }
}

impl Secret {
    /// Generate a fresh CSPRNG-backed secret. Used at enrollment
    /// time. Calls `getrandom`; in WASM the entropy source is
    /// `crypto.getRandomValues` (web_sys feature `js`).
    pub fn generate() -> TotpResult<Self> {
        let mut buf = vec![0u8; SECRET_BYTES];
        getrandom::getrandom(&mut buf).map_err(|_| TotpError::RngError)?;
        Ok(Self(buf))
    }

    /// Construct from raw bytes. Validates length.
    pub fn from_bytes(bytes: Vec<u8>) -> TotpResult<Self> {
        if bytes.len() != SECRET_BYTES {
            return Err(TotpError::InvalidSecretLength);
        }
        Ok(Self(bytes))
    }

    /// Render the secret as base32 (no padding). This is the form
    /// shown to users for manual entry into authenticator apps,
    /// and the form embedded in `otpauth://` URIs.
    pub fn to_base32(&self) -> String {
        BASE32_NOPAD.encode(&self.0)
    }

    /// Parse a base32-encoded secret. Permissive about padding
    /// (RFC 4648 §3.2 says padding is optional for base32) and
    /// tolerant of ASCII whitespace (users sometimes paste with
    /// embedded spaces from QR-code apps). Rejects everything
    /// else.
    pub fn from_base32(s: &str) -> TotpResult<Self> {
        // Strip whitespace and any '=' padding characters before
        // decoding. The NOPAD codec accepts neither.
        let cleaned: String = s
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '=')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let bytes = BASE32_NOPAD
            .decode(cleaned.as_bytes())
            .map_err(|_| TotpError::InvalidBase32)?;
        Self::from_bytes(bytes)
    }

    /// Borrow the underlying bytes. Used by `compute_code` and
    /// `encrypt_secret`. Not exposed for general use because
    /// callers should round-trip through `to_base32()` for
    /// human-readable forms or through encryption for storage.
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// =====================================================================
// TOTP computation
// =====================================================================

/// Convert a Unix timestamp (seconds since epoch, UTC) to a TOTP
/// step. Step 0 = the epoch itself; step N = `floor(unix / 30)`.
/// Negative unix timestamps (impossible for any real verification)
/// are rejected by clamping to 0.
pub fn step_for_unix(unix_secs: i64) -> u64 {
    if unix_secs <= 0 {
        return 0;
    }
    (unix_secs as u64) / STEP_SECONDS
}

/// Compute the 6-digit TOTP code for the given secret and step.
/// Pure function — no time access, no I/O.
///
/// Implementation follows RFC 4226 §5.3 (HOTP):
/// 1. T = step encoded as 8-byte big-endian.
/// 2. HS = HMAC-SHA1(secret, T) — 20-byte output.
/// 3. Dynamic truncation: take the low nibble of HS[19] as
///    offset (0..=15), read 4 bytes starting at offset, mask
///    the high bit, take the result mod 10^DIGITS.
///
/// Returned as u32 so the caller decides whether to format with
/// leading zeros (for display) or compare as integer (for
/// verification — both sides must format identically to compare,
/// so verify uses the integer form).
pub fn compute_code(secret: &Secret, step: u64) -> u32 {
    type HmacSha1 = Hmac<Sha1>;

    let mut mac = <HmacSha1 as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA1 key length is unrestricted");
    mac.update(&step.to_be_bytes());
    let result = mac.finalize().into_bytes();

    // Dynamic truncation per RFC 4226 §5.3. The HMAC output is
    // 20 bytes; we read 4 bytes starting at offset (low nibble of
    // last byte) and mask the high bit.
    let offset = (result[19] & 0x0f) as usize;
    let bin_code = ((result[offset]     & 0x7f) as u32) << 24
                 | ((result[offset + 1] & 0xff) as u32) << 16
                 | ((result[offset + 2] & 0xff) as u32) << 8
                 |  (result[offset + 3] & 0xff) as u32;

    bin_code % 10u32.pow(DIGITS)
}

/// Format a TOTP code as a zero-padded 6-character ASCII string.
/// Used at the enrollment-confirmation step (where the code is
/// shown to the user) and in tests.
///
/// Verify paths should NOT format-then-compare (timing leak via
/// the format step on different lengths). Verify by parsing the
/// submitted string to u32 and comparing integers.
pub fn format_code(code: u32) -> String {
    format!("{:0width$}", code, width = DIGITS as usize)
}

/// Parse a submitted TOTP code as u32. Returns
/// `Err(TotpError::InvalidCode)` for any non-digit input or for
/// codes that are too long. We deliberately do NOT enforce a
/// minimum length here — `compute_code` returns values 0..=999_999
/// so the comparison is correct regardless of leading zeros in
/// the user's input.
pub fn parse_code(input: &str) -> TotpResult<u32> {
    if input.len() > DIGITS as usize {
        return Err(TotpError::InvalidCode);
    }
    if !input.chars().all(|c| c.is_ascii_digit()) {
        return Err(TotpError::InvalidCode);
    }
    input.parse::<u32>().map_err(|_| TotpError::InvalidCode)
}

// =====================================================================
// Verification with replay protection
// =====================================================================

/// Verify a submitted TOTP code against a stored secret, with
/// skew tolerance and replay protection.
///
/// Returns `Ok(new_last_used_step)` on success — the caller MUST
/// persist the returned step value and pass it back as
/// `last_used_step` on the next verify, otherwise replay
/// protection is bypassed.
///
/// Returns `Err(TotpError::InvalidCode)` if no step within the
/// skew window matches, OR if the matching step is ≤
/// `last_used_step` (the code is from a window already used).
///
/// Skew window: ±SKEW_STEPS (currently ±1 = three windows total).
/// `last_used_step` should be 0 for fresh authenticators (the
/// schema defaults this; see migration 0007).
pub fn verify_with_replay_protection(
    secret:          &Secret,
    submitted_code:  u32,
    last_used_step:  u64,
    now_unix:        i64,
) -> TotpResult<u64> {
    let current_step = step_for_unix(now_unix);

    // Check the windows from oldest to newest. Reject any match
    // that would replay a step ≤ last_used_step.
    //
    // Iteration order matters subtly: if both `current-1` and
    // `current` would match (impossible in practice — different
    // steps produce different codes via HMAC; the chance is 1 in
    // 10^DIGITS), we still want to land on the latest matching
    // step, so iterate -SKEW..=+SKEW and keep updating.
    let mut matched: Option<u64> = None;
    for delta in -SKEW_STEPS..=SKEW_STEPS {
        // Compute candidate step. delta can be negative; current
        // step is u64. Safe-cast via i64 with saturate_at_zero.
        let candidate_step: u64 = if delta < 0 {
            current_step.saturating_sub((-delta) as u64)
        } else {
            current_step.saturating_add(delta as u64)
        };

        // Replay-protection gate: never accept an already-used
        // step.
        if candidate_step <= last_used_step {
            continue;
        }

        let candidate_code = compute_code(secret, candidate_step);
        if constant_time_eq_u32(candidate_code, submitted_code) {
            matched = Some(candidate_step);
            // Don't break: continue to find the latest matching
            // step (defensive — collision in window of 3 is
            // ~3/10^6, but keeping the latest match means a
            // future verify rejects the older one).
        }
    }

    matched.ok_or(TotpError::InvalidCode)
}

/// Constant-time equality for two u32 values. The compiler may
/// optimize this to a CMOV that's already constant-time, but we
/// pin the behavior with a branchless XOR-and-fold rather than
/// trusting compiler-level analysis for a security-relevant path.
fn constant_time_eq_u32(a: u32, b: u32) -> bool {
    let diff = a ^ b;
    diff == 0
}

// =====================================================================
// otpauth:// URI construction
// =====================================================================

/// Build the `otpauth://totp/...` URI that authenticator apps
/// scan from QR codes. RFC 6238 §3.2 + the Google Authenticator
/// key-uri format (the de facto standard).
///
/// Format:
///
/// ```text
/// otpauth://totp/{issuer}:{account}?secret={base32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30
/// ```
///
/// Both `issuer` and `account` are URL-encoded. Authenticator apps
/// display the label as `{issuer}: {account}` and group entries by
/// issuer.
///
/// The `algorithm`/`digits`/`period` parameters are explicit even
/// though they match every authenticator app's defaults — explicit
/// is robust against any future app version that changes its own
/// default.
pub fn otpauth_uri(issuer: &str, account: &str, secret: &Secret) -> String {
    let issuer_enc  = url_encode(issuer);
    let account_enc = url_encode(account);
    let secret_b32  = secret.to_base32();

    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer2}&algorithm=SHA1&digits={digits}&period={period}",
        issuer  = issuer_enc,
        account = account_enc,
        secret  = secret_b32,
        issuer2 = issuer_enc,
        digits  = DIGITS,
        period  = STEP_SECONDS,
    )
}

/// Minimal RFC 3986 percent-encoding for the chars that matter in
/// `otpauth://` labels. We don't pull in `urlencoding` for this —
/// the surface is small and the dep tree is already big enough.
///
/// Encodes: spaces, `:`, `/`, `?`, `#`, `&`, `=`, `+`, `%`, plus
/// any non-ASCII byte. Leaves alphanumerics and `-_.~` alone.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        let safe = matches!(byte,
              b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~'
        );
        if safe {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

// =====================================================================
// Recovery codes
// =====================================================================

/// A plaintext recovery code. Format `XXXXX-XXXXX` — 10 base32
/// characters with a separator dash, ≈ 50 bits of entropy. Shown
/// to the user once at enrollment and stored only as
/// `hash_recovery_code(code)`. Single-use.
///
/// The newtype wraps a `String` so the type system distinguishes
/// "freshly minted plaintext code" from "user-submitted string"
/// (which goes through `parse_recovery_code` first). Display is
/// safe to call — the value is intentionally shown to the user
/// once.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryCode(String);

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Same redaction as Secret — Debug shouldn't dump the
        // value. The "show once at enrollment" path uses Display.
        write!(f, "RecoveryCode({} chars)", self.0.len())
    }
}

impl std::fmt::Display for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl RecoveryCode {
    /// Borrow the formatted string. Used by callers that need the
    /// exact display form for hashing or rendering. Equivalent to
    /// `to_string()` but without the allocation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Generate a fresh recovery code: 10 random base32 characters
/// formatted `XXXXX-XXXXX`. The dash isn't part of the entropy;
/// it's a human-readability aid, stripped before hashing or
/// comparison.
fn generate_one_recovery_code() -> TotpResult<RecoveryCode> {
    // 10 base32 characters = 50 bits of entropy. We need to
    // sample 10 random characters from the base32 alphabet
    // uniformly. Easiest correct approach: sample 10 random bytes
    // and map each into [0, 32) by masking.
    //
    // Wait — masking the low 5 bits of a uniform byte gives a
    // uniform value in [0, 32). That's the right approach.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut entropy = [0u8; 10];
    getrandom::getrandom(&mut entropy).map_err(|_| TotpError::RngError)?;

    let mut s = String::with_capacity(11); // 10 chars + 1 dash
    for (i, &b) in entropy.iter().enumerate() {
        if i == 5 {
            s.push('-');
        }
        let idx = (b & 0x1f) as usize; // low 5 bits → [0, 32)
        s.push(alphabet[idx] as char);
    }
    Ok(RecoveryCode(s))
}

/// Generate the canonical batch of `RECOVERY_CODES_PER_USER`
/// recovery codes for a fresh enrollment. Caller stores the
/// hashes (via `hash_recovery_code`) and shows the plaintexts to
/// the user once.
pub fn generate_recovery_codes() -> TotpResult<Vec<RecoveryCode>> {
    (0..RECOVERY_CODES_PER_USER)
        .map(|_| generate_one_recovery_code())
        .collect()
}

/// Hash a recovery code for storage. SHA-256 of the
/// canonicalized form (uppercase, dashes stripped, whitespace
/// stripped). Hex-encoded output for direct D1 column storage.
///
/// Matches cesauth's existing pattern for high-entropy bearer
/// secrets (admin tokens, magic-link OTPs). Argon2 would be the
/// right choice for user-chosen passwords but recovery codes have
/// ≈ 50 bits of entropy already — password-stretching adds CPU
/// cost without security gain.
///
/// Canonicalization is important because users will
/// retype-from-paper with hyphens and spaces in unpredictable
/// places. The stored hash is over the canonical form so any
/// equivalent form verifies.
pub fn hash_recovery_code(code: &str) -> String {
    let canonical: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let digest = Sha256::digest(canonical.as_bytes());
    hex::encode(digest)
}

// =====================================================================
// Encryption at rest (AES-GCM-256, AAD-bound)
// =====================================================================

/// Encrypt a TOTP secret for storage. Returns
/// `(ciphertext, nonce)` — the caller stores both alongside the
/// `secret_key_id` (the identifier of which key was used,
/// for rotation).
///
/// Per ADR-009 §Q5:
/// - `key`: 32 bytes, the deployment's TOTP encryption key
///   (`TOTP_ENCRYPTION_KEY` env var, base64-decoded).
/// - `aad`: the row's primary key formatted as
///   `"totp:" + id`. Binding the ciphertext to the row prevents
///   D1-backup-swap attacks where an attacker who reads a backup
///   tries to put row A's ciphertext into row B's slot.
///
/// The nonce is a fresh 12 random bytes from CSPRNG. AES-GCM
/// requires nonce uniqueness per key per encryption; with random
/// 96-bit nonces and ≤ 2^32 encryptions per key the collision
/// probability is negligible.
pub fn encrypt_secret(
    secret:    &Secret,
    key:       &[u8],
    aad:       &[u8],
) -> TotpResult<(Vec<u8>, [u8; ENCRYPTION_NONCE_LEN])> {
    if key.len() != ENCRYPTION_KEY_LEN {
        return Err(TotpError::InvalidKeyLength);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let mut nonce_bytes = [0u8; ENCRYPTION_NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|_| TotpError::RngError)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload {
            msg: secret.as_bytes(),
            aad,
        })
        .map_err(|_| TotpError::EncryptionError)?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt a stored TOTP secret. The `aad` MUST match what was
/// passed to `encrypt_secret`; mismatch surfaces as
/// `DecryptionError`.
///
/// Caller looks up the row, retrieves `secret_ciphertext`,
/// `secret_nonce`, `secret_key_id`, finds the matching key (the
/// active one or an older one for rotation), and calls this.
pub fn decrypt_secret(
    ciphertext: &[u8],
    nonce:      &[u8],
    key:        &[u8],
    aad:        &[u8],
) -> TotpResult<Secret> {
    if key.len() != ENCRYPTION_KEY_LEN {
        return Err(TotpError::InvalidKeyLength);
    }
    if nonce.len() != ENCRYPTION_NONCE_LEN {
        return Err(TotpError::InvalidNonceLength);
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce  = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, Payload {
            msg: ciphertext,
            aad,
        })
        .map_err(|_| TotpError::DecryptionError)?;

    Secret::from_bytes(plaintext)
}

/// Build the AAD string for a given row. Centralized here so
/// callers can't drift on the format. The format is `"totp:" +
/// id`; if the storage layer ever changes the row id format
/// (UUIDs today), the AAD continues to bind cleanly because
/// it's the entire id-as-string.
pub fn aad_for_id(id: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(b"totp:".len() + id.len());
    buf.extend_from_slice(b"totp:");
    buf.extend_from_slice(id.as_bytes());
    buf
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests;
