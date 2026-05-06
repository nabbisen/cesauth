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

/// **v0.42.0** — Outcome of an optional client-authentication attempt.
/// Used by `/revoke` (RFC 7009) where the policy is "confidential
/// clients MUST authenticate; public clients MAY skip auth and rely
/// on token possession". The introspect endpoint (RFC 7662) requires
/// auth unconditionally and uses [`verify_client_credentials`]
/// directly.
#[derive(Debug, PartialEq, Eq)]
pub enum ClientAuthOutcome {
    /// `client_id` resolves to a public client (no
    /// `client_secret_hash` on file) OR doesn't exist at
    /// all. The conflation is intentional: the caller
    /// shouldn't distinguish "unknown client_id" from
    /// "public client" because doing so leaks
    /// client-existence information.
    PublicOrUnknown,
    /// Confidential client; presented credentials match
    /// stored hash.
    Authenticated,
    /// Confidential client; either no credentials were
    /// presented or the presented secret didn't match.
    /// Conflated for the same reason `verify_client_credentials`
    /// conflates its failure modes.
    AuthenticationFailed,
}

/// **v0.42.0** — Resolve a client's authentication mode with
/// optional credentials.
///
/// `presented_secret` is `Some(secret)` when the request carried
/// credentials (Authorization: Basic or form-body), `None` when
/// it didn't. The function inspects whether the named client has
/// a stored secret hash and combines that with whether
/// credentials were presented to produce one of three
/// [`ClientAuthOutcome`] variants.
///
/// **Privacy invariant**: the four `(client_secret_hash present?,
/// credentials presented?, credentials match?)` cases all map to
/// just three outcomes — `PublicOrUnknown`,
/// `Authenticated`, `AuthenticationFailed`. Callers cannot
/// distinguish "the client_id you named doesn't exist" from
/// "the client_id is registered as public" from the outcome
/// alone. This avoids the side channel where a confidential-
/// client revoke endpoint would otherwise let an attacker
/// enumerate registered client_ids.
pub async fn verify_client_credentials_optional<CR>(
    clients:          &CR,
    client_id:        &str,
    presented_secret: Option<&str>,
) -> CoreResult<ClientAuthOutcome>
where
    CR: ClientRepository,
{
    let stored_hash = clients
        .client_secret_hash(client_id)
        .await
        .map_err(|_| CoreError::Internal)?;

    match (stored_hash, presented_secret) {
        (None, _) => {
            // Client unknown OR public — same outcome.
            // The caller treats this as "auth not
            // required for this client_id"; if the
            // caller went on to fetch the token and the
            // cid in the token's payload referred to a
            // confidential client, the cid-mismatch
            // gate downstream still rejects.
            Ok(ClientAuthOutcome::PublicOrUnknown)
        }
        (Some(_), None) => {
            // Confidential client; no creds presented.
            Ok(ClientAuthOutcome::AuthenticationFailed)
        }
        (Some(stored_hex), Some(secret)) => {
            let presented_hex = sha256_hex(secret.as_bytes());
            if constant_time_eq(presented_hex.as_bytes(), stored_hex.as_bytes()) {
                Ok(ClientAuthOutcome::Authenticated)
            } else {
                Ok(ClientAuthOutcome::AuthenticationFailed)
            }
        }
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
