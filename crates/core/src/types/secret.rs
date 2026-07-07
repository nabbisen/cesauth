//! **RFC 116** — Secret-material newtypes.
//!
//! Three types, three trust levels:
//!
//! | Type | Holds | May be persisted? | `Debug` |
//! |---|---|---|---|
//! | [`RawSecret`] | live secret material | **never** | `REDACTED` |
//! | [`HashedSecret`] | a digest of secret material | yes | `REDACTED` |
//! | [`RedactedSecret`] | nothing (display placeholder) | n/a | `REDACTED` |
//!
//! ## Design points
//!
//! * `RawSecret` implements **neither `Clone` nor `Serialize`** —
//!   moving it is the only way to pass it on, so secret flow is
//!   linear and auditable: `grep -rn "\.expose()" crates/` lists
//!   every intentional read point in the codebase.
//! * `RawSecret` zeroizes its buffer on drop (`zeroize`), so secret
//!   bytes do not linger in freed heap memory.
//! * `HashedSecret` deliberately does **not** derive `PartialEq`;
//!   the only equality is [`HashedSecret::ct_eq`], which is
//!   constant-time. Deriving `==` would reopen the timing side
//!   channel that `util::constant_time_eq_bytes` exists to close.
//! * `Debug` for both prints a fixed marker. A hash is not
//!   confidential, but redacting it keeps oracle material (and the
//!   habit of printing credentials) out of logs entirely — this is
//!   the type-level generalisation of RFC 008/030's log
//!   sanitisation work.
//!
//! Storage encoding is unchanged: `HashedSecret` serialises
//! transparently as the same hex/base64url string the schema already
//! holds (`clients.client_secret_hash`, `Challenge::MagicLink
//! .code_hash`).

use core::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The marker printed wherever secret-bearing types are formatted.
pub const REDACTION_MARKER: &str = "REDACTED";

// ---------------------------------------------------------------------------
// RawSecret
// ---------------------------------------------------------------------------

/// Live secret material: a presented `client_secret`, a submitted
/// Magic Link OTP, a decrypted TOTP seed, a PEM private key in
/// transit from the env layer.
///
/// No `Clone`. No `Serialize`. No `Display`. Buffer zeroized on drop.
pub struct RawSecret(Zeroizing<String>);

impl RawSecret {
    /// Take ownership of secret material. The caller's `String` is
    /// moved, not copied — after this call the only live copy is
    /// inside the `RawSecret`.
    pub fn new(s: String) -> Self {
        Self(Zeroizing::new(s))
    }

    /// The one intentional read point. Every call site is a reviewed
    /// location (RFC 116 acceptance criterion 3).
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// SHA-256 the material into a persistable [`HashedSecret`]
    /// (lowercase hex — matching `service::client_auth::sha256_hex`
    /// and the existing column contents).
    pub fn sha256(&self) -> HashedSecret {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.0.as_bytes());
        HashedSecret(hex::encode(h.finalize()))
    }
}

impl fmt::Debug for RawSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawSecret({REDACTION_MARKER})")
    }
}

// ---------------------------------------------------------------------------
// HashedSecret
// ---------------------------------------------------------------------------

/// A digest of secret material, safe to persist and to read back.
///
/// Equality is constant-time only ([`Self::ct_eq`]); `PartialEq` is
/// intentionally absent.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HashedSecret(String);

impl HashedSecret {
    /// Re-hydrate a digest cesauth previously stored (D1 column, DO
    /// field). Trusted boundary — no validation beyond being a
    /// `String`, since historical encodings (hex vs base64url across
    /// features) must keep loading.
    pub fn from_storage(digest: impl Into<String>) -> Self {
        Self(digest.into())
    }

    /// Constant-time comparison. The **only** equality for this type.
    pub fn ct_eq(&self, other: &HashedSecret) -> bool {
        crate::util::constant_time_eq_bytes(self.0.as_bytes(), other.0.as_bytes())
    }

    /// The digest string, for SQL binding / DO serialisation at the
    /// storage boundary. Digests are persistable by definition, so
    /// this is `pub`; it is *not* a secret leak, but route/log code
    /// should have no reason to call it.
    pub fn as_storage_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HashedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HashedSecret({REDACTION_MARKER})")
    }
}

// ---------------------------------------------------------------------------
// RedactedSecret
// ---------------------------------------------------------------------------

/// A display-only placeholder for UI/audit surfaces that must show
/// *that* a secret exists without showing anything about it (e.g.
/// the admin console's "client secret: set" indicator, audit
/// `before`/`after` deltas of credential rotations).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedSecret;

impl fmt::Debug for RedactedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTION_MARKER)
    }
}

impl fmt::Display for RedactedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTION_MARKER)
    }
}

#[cfg(test)]
mod tests;
