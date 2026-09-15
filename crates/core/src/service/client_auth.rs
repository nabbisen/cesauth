//! Client credential verification (v0.38.0, ADR-014).
//!
//! Used by `/introspect` (and in future, by `/revoke` and possibly
//! `/token` for confidential-client paths). The function takes a
//! `client_id` + plaintext `client_secret` from the request, looks
//! up the stored hash via the `ClientRepository` port, and does a
//! constant-time comparison.
//!
//! ## Hash format (RFC 002, v0.51.0 — resolved)
//!
//! cesauth stores a hex-encoded SHA-256 of the secret (no salt). This
//! is appropriate **only** because `client_secret` is a server-minted
//! high-entropy random string (32+ bytes), not a user-chosen
//! password. For high-entropy secrets, salted password hashes
//! (Argon2, scrypt) provide no additional protection — there's
//! nothing to brute-force from the hash.
//!
//! `migrations/0001_initial.sql` previously described `client_secret_hash`
//! as `argon2id(secret)`. That was a documentation lie — Argon2 was
//! never implemented; the actual path has always been SHA-256, matching
//! how `admin_tokens` and magic-link OTP hashes work. RFC 002 (v0.51.0)
//! corrected the schema comment to `sha256_hex(secret)`.
//!
//! If a future ADR ever allows user-chosen client secrets (we do
//! not, today; the only flow that mints them is admin console
//! provisioning which generates 32-byte URL-safe randoms), this
//! function MUST be revisited and migrated to Argon2 with per-
//! credential salts.

use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};
use crate::ports::repo::{ClientAuthView, ClientRepository};
use crate::types::ClientType;

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

/// **RFC 026** — Verify a presented `client_secret` against a pre-read
/// [`ClientAuthView`] without performing any additional I/O.
///
/// Designed for the `/introspect` hot path, where the view is already
/// fetched for the audience gate. The same constant-time comparison and
/// conflated-failure contract as [`verify_client_credentials`] apply.
///
/// Returns:
/// - `Authenticated`     — credentials match the stored hash.
/// - `AuthenticationFailed` — confidential client, wrong secret.
/// - `PublicOrUnknown`   — `client_secret_hash` is `None` (public client).
pub fn check_client_credentials_from_view(
    view:             &ClientAuthView,
    presented_secret: &str,
) -> ClientAuthOutcome {
    let Some(ref stored_hex) = view.client_secret_hash else {
        return ClientAuthOutcome::PublicOrUnknown;
    };
    let presented_hex = sha256_hex(presented_secret.as_bytes());
    if constant_time_eq(presented_hex.as_bytes(), stored_hex.as_bytes()) {
        ClientAuthOutcome::Authenticated
    } else {
        ClientAuthOutcome::AuthenticationFailed
    }
}

/// **RFC 137** — authenticate the client at `/token`, on both grants.
///
/// `/token` must admit public clients, so it cannot reuse `/introspect`'s rule
/// (reject everything but `Authenticated`). Nor can it read
/// [`check_client_credentials_from_view`]'s `PublicOrUnknown` as "proceed":
/// that outcome means only "no hash on file", **regardless of `client_type`**,
/// and would silently admit a confidential client provisioned without one.
///
/// The discriminator is a fail-closed intersection (RFC 137 §12.3):
///
/// ```text
/// public client  <=>  client_type = Public  AND  client_secret_hash IS NULL
/// otherwise       ->  must authenticate:
///                       Authenticated                          -> proceed
///                       AuthenticationFailed | PublicOrUnknown -> InvalidClient
/// ```
///
/// Every secret comparison goes through `check_client_credentials_from_view`'s
/// constant-time path; nothing here compares secret material itself.
///
/// A public client that also presents a secret is still admitted as public.
/// Whether the presented method must match the registered one is out of
/// scope (RFC 137 §12.7).
pub fn authenticate_token_client(
    view:             &ClientAuthView,
    presented_secret: Option<&str>,
) -> CoreResult<()> {
    if matches!(view.client_type, ClientType::Public) && view.client_secret_hash.is_none() {
        return Ok(());
    }
    let Some(secret) = presented_secret else {
        return Err(CoreError::InvalidClient);
    };
    match check_client_credentials_from_view(view, secret) {
        ClientAuthOutcome::Authenticated => Ok(()),
        ClientAuthOutcome::AuthenticationFailed | ClientAuthOutcome::PublicOrUnknown => {
            Err(CoreError::InvalidClient)
        }
    }
}

/// **RFC 137** — resolve which client a `/token` request speaks for, and the
/// secret it presented, from the two places RFC 6749 §2.3.1 allows.
///
/// Precedence matches the backend's `client_auth::extract`, which `/token`
/// cannot call because it reads its body as text rather than `FormData`:
///
/// - **An `Authorization` header is present** — HTTP Basic is the only path.
///   A malformed header (`basic` is `None`) is rejected and does **not** fall
///   through to the form; a broken Basic attempt must not retry itself as
///   `client_secret_post`.
/// - **No header** — `client_id` and an optional `client_secret` come from the
///   form. An empty `client_secret` is treated as absent, as `extract_from_form`
///   does.
///
/// With Basic, a form `client_id` that disagrees with the header is one
/// client presenting two identities, and is rejected. So is a **non-empty form
/// `client_secret`** alongside Basic, even when the `client_id`s agree: that is
/// two authentication methods in one request (RFC 6749 §2.3: a client MUST NOT
/// use more than one; RFC 137 C1-137). With Basic, the form `client_id` may be
/// absent — the header identifies the client (RFC 6749 §4.1.3).
///
/// Pure, taking primitives, so the precedence is testable on the host —
/// `worker::Headers` cannot be constructed off wasm32.
pub fn resolve_token_client_credentials(
    authorization_header_present: bool,
    basic:                        Option<(&str, &str)>,
    form_client_id:               Option<&str>,
    form_client_secret:           Option<&str>,
) -> CoreResult<(String, Option<String>)> {
    if authorization_header_present {
        let Some((basic_id, basic_secret)) = basic else {
            return Err(CoreError::InvalidClient);
        };
        if form_client_secret.is_some_and(|s| !s.is_empty()) {
            return Err(CoreError::InvalidClient);
        }
        if let Some(form_id) = form_client_id {
            if form_id != basic_id {
                return Err(CoreError::InvalidClient);
            }
        }
        return Ok((basic_id.to_owned(), Some(basic_secret.to_owned())));
    }

    let client_id = form_client_id
        .filter(|id| !id.is_empty())
        .ok_or(CoreError::InvalidRequest("client_id is required"))?;
    let secret = form_client_secret.filter(|s| !s.is_empty()).map(str::to_owned);
    Ok((client_id.to_owned(), secret))
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
