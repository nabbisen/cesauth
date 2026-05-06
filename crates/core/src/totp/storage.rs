//! Storage port for TOTP authenticators and recovery codes.
//!
//! These types and traits live alongside `cesauth_core::totp` (the
//! pure cryptography library) but are kept in a separate module so
//! the library is usable from contexts that don't have D1 access
//! (test fixtures, CLI tooling, fuzzing harnesses).
//!
//! See ADR-009 §Q4 for why TOTP gets its own table separate from
//! WebAuthn's `authenticators`. The schema is in migration 0007.
//!
//! Adapters live in `cesauth-adapter-cloudflare` (D1) and
//! `cesauth-adapter-test` (in-memory, for unit tests).

use crate::ports::PortResult;

// =====================================================================
// Value types
// =====================================================================

/// One row of `totp_authenticators`. The secret is always
/// encrypted at rest — `secret_ciphertext`, `secret_nonce`, and
/// `secret_key_id` are passed through to the worker layer which
/// looks up the active key via env, decrypts via
/// `cesauth_core::totp::decrypt_secret`, and uses the plaintext
/// `Secret` value for `compute_code` / `verify_with_replay_protection`.
///
/// `confirmed_at` is the enrollment-completion marker: NULL during
/// enrollment, set to `now` on first successful verify. Pre-
/// confirmation rows are pruned by the daily cron sweep
/// (extension lands in v0.27.0; see ADR-009 §Q9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpAuthenticator {
    pub id:                 String,
    pub user_id:            String,
    pub secret_ciphertext:  Vec<u8>,
    pub secret_nonce:       Vec<u8>,
    pub secret_key_id:      String,
    pub last_used_step:     u64,
    pub name:               Option<String>,
    pub created_at:         i64,
    pub last_used_at:       Option<i64>,
    pub confirmed_at:       Option<i64>,
}

/// One row of `totp_recovery_codes`. `code_hash` is the SHA-256
/// of the canonicalized recovery code (uppercase, no whitespace,
/// no dashes), hex-encoded. `redeemed_at` flips from NULL to a
/// unix timestamp on first successful redemption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpRecoveryCodeRow {
    pub id:           String,
    pub user_id:      String,
    pub code_hash:    String,
    pub redeemed_at:  Option<i64>,
    pub created_at:   i64,
}

// =====================================================================
// Repository trait — totp_authenticators
// =====================================================================

/// `totp_authenticators` table operations.
///
/// All methods are scoped by `user_id` (where applicable) — there
/// is no global "list all TOTP authenticators" surface. Each
/// authenticator is private to its owner.
pub trait TotpAuthenticatorRepository {
    /// Insert a freshly-minted enrollment row. The row arrives
    /// with `confirmed_at = None`; the worker flips this on
    /// first successful verify via `confirm`.
    ///
    /// Returns `Conflict` if the id is already taken (UUID
    /// collisions are astronomically rare, but the adapter must
    /// honor the PRIMARY KEY).
    async fn create(&self, row: &TotpAuthenticator) -> PortResult<()>;

    /// Find by primary key. Used by the verify route after the
    /// worker reads the `__Host-cesauth_totp` cookie that pins
    /// the authenticator id for this prompt.
    async fn find_by_id(&self, id: &str) -> PortResult<Option<TotpAuthenticator>>;

    /// Find the active confirmed authenticator for this user.
    /// Hot-path query: the post-Magic-Link verify gate calls
    /// this on every login to decide whether to prompt for a
    /// TOTP code.
    ///
    /// Returns `None` if the user has no confirmed authenticator
    /// (either never enrolled or only has unconfirmed enrollment
    /// rows). Returns the most recently confirmed row if there
    /// are multiple — users with backup authenticators see the
    /// most recently confirmed one but in v0.27.0's UI flow the
    /// distinction doesn't matter (any confirmed authenticator
    /// gates the user equally).
    async fn find_active_for_user(&self, user_id: &str)
        -> PortResult<Option<TotpAuthenticator>>;

    /// First-verify confirmation: set `confirmed_at = now`,
    /// advance `last_used_step`, and set `last_used_at = now`.
    /// Single atomic UPDATE. Returns `NotFound` if the id is
    /// missing or already confirmed (idempotency: a second
    /// confirm against the same row is a no-op-as-error).
    async fn confirm(&self, id: &str, last_used_step: u64, now: i64)
        -> PortResult<()>;

    /// Subsequent-verify update: advance `last_used_step` and
    /// set `last_used_at = now`. Used after `confirm` for every
    /// verify that follows. Returns `NotFound` if the id is
    /// missing.
    async fn update_last_used_step(&self, id: &str, last_used_step: u64, now: i64)
        -> PortResult<()>;

    /// Delete an authenticator. Used by the disable-TOTP route
    /// (v0.27.0). Cascade not needed — recovery codes are stored
    /// per-user, not per-authenticator.
    async fn delete(&self, id: &str) -> PortResult<()>;

    /// Cron-sweep helper. Returns ids of rows where
    /// `confirmed_at IS NULL AND created_at < cutoff_unix`.
    /// The caller (the daily 04:00 UTC cron) deletes them in a
    /// follow-up batch.
    ///
    /// We split list-then-delete rather than DELETE-WHERE for
    /// two reasons: the list output goes into the audit log
    /// (so an operator can see what was pruned), and D1 batch
    /// DELETEs are cheap.
    async fn list_unconfirmed_older_than(&self, cutoff_unix: i64)
        -> PortResult<Vec<String>>;
}

// =====================================================================
// Repository trait — totp_recovery_codes
// =====================================================================

/// `totp_recovery_codes` table operations.
pub trait TotpRecoveryCodeRepository {
    /// Bulk-insert recovery codes. Called once per user at
    /// first TOTP enrollment. The plaintexts have already been
    /// shown to the user; this stores the hashes.
    ///
    /// Adapters MUST insert all rows or none (transactional);
    /// a partial failure leaves the user with fewer codes than
    /// the system promised, which is bad UX.
    async fn bulk_create(&self, rows: &[TotpRecoveryCodeRow]) -> PortResult<()>;

    /// Look up a recovery code by user + hash. Used by the
    /// recovery redemption route. Returns `Some` only if a row
    /// exists with this exact hash and `redeemed_at IS NULL`.
    async fn find_unredeemed_by_hash(&self, user_id: &str, code_hash: &str)
        -> PortResult<Option<TotpRecoveryCodeRow>>;

    /// Mark a recovery code as redeemed. Atomic single-row
    /// UPDATE. Returns `NotFound` if the id is missing or
    /// already redeemed (concurrent redemption — the second
    /// caller fails closed).
    async fn mark_redeemed(&self, id: &str, now: i64) -> PortResult<()>;

    /// Count remaining (unredeemed) codes for the user. Surfaced
    /// in the user's `/me/security` page so they know when to
    /// regenerate.
    async fn count_remaining(&self, user_id: &str) -> PortResult<u32>;

    /// Delete all recovery codes for a user. Called when the
    /// user disables TOTP entirely or re-enrolls (which mints
    /// fresh codes; the old ones must not be valid alongside).
    async fn delete_all_for_user(&self, user_id: &str) -> PortResult<()>;
}
