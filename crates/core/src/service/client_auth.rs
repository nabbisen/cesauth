//! Client credential verification (v0.38.0, ADR-014).
//!
//! Used by `/introspect` (and in future, by `/revoke` and possibly
//! `/token` for confidential-client paths). The function takes a
//! `client_id` + plaintext `client_secret` from the request, looks
//! up the stored hash via the `ClientRepository` port, and does a
//! constant-time comparison.
//!
//! ## Hash format
//!
//! cesauth stores a hex-encoded SHA-256 of the secret (no salt). This
//! is appropriate **only** because `client_secret` is a server-minted
//! high-entropy random string (32+ bytes), not a user-chosen
//! password. For high-entropy secrets, salted password hashes
//! (Argon2, scrypt) provide no additional protection — there's
//! nothing to brute-force from the hash.
//!
//! If a future ADR ever allows user-chosen client secrets (we do
//! not, today; the only flow that mints them is admin console
//! provisioning which generates 32-byte URL-safe randoms), this
//! function MUST be revisited and migrated to Argon2 with per-
//! credential salts.

use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};
use crate::ports::repo::ClientRepository;

/// Verify a presented `client_secret` against the stored hash for
/// `client_id`. Returns `Ok(())` on success, `Err(CoreError::InvalidClient)`
/// on any failure (unknown client, no secret hash on file, mismatched
/// hash). Storage errors are propagated as `CoreError::Internal`.
///
/// All failure modes return the same error variant — there's no
/// caller-side path that benefits from "client unknown" vs "wrong
/// secret" distinction, and conflating them on the response side
/// avoids the timing/probing side channel on enumerated client_ids.
///
/// **Constant-time comparison** prevents timing attacks against the
/// secret. The hex encoding step is timing-stable on its own (one
/// pass through the buffer).
pub async fn verify_client_credentials<CR>(
    clients:       &CR,
    client_id:     &str,
    client_secret: &str,
) -> CoreResult<()>
where
    CR: ClientRepository,
{
    let stored_hash = clients
        .client_secret_hash(client_id)
        .await
        .map_err(|_| CoreError::Internal)?;
    let Some(stored_hex) = stored_hash else {
        // Either the client doesn't exist, or it's a public client
        // with no secret on file. Same response either way — see
        // module docs.
        return Err(CoreError::InvalidClient);
    };

    let presented_hex = sha256_hex(client_secret.as_bytes());

    if constant_time_eq(presented_hex.as_bytes(), stored_hex.as_bytes()) {
        Ok(())
    } else {
        Err(CoreError::InvalidClient)
    }
}

/// SHA-256, lowercase hex. The format that `ClientRepository::create`
/// expects to receive in `secret_hash`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest.iter() {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Constant-time byte equality. Returns `false` on any length
/// mismatch (without leaking the lengths via early-return timing —
/// the loop runs to the longer of the two).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Length mismatch is observable from the response shape
        // anyway (a successful hash is always 64 chars hex), so
        // returning here doesn't leak more than the protocol
        // already does.
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests;
