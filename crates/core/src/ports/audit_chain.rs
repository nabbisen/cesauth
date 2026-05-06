//! Audit chain checkpoint storage (ADR-010 Phase 2, v0.33.0).
//!
//! The chain in `audit_events` defends against tampering with
//! existing rows: any modification of a past row breaks the
//! `chain_hash` chain at that point and every row after it.
//! That covers the "edit one row" attack.
//!
//! It does NOT cover the **wholesale rewrite** attack: an
//! attacker who can write to the entire `audit_events` table can
//! rewrite the table from any seq onward, recompute every chain
//! hash from scratch, and end up with a chain that verifies
//! internally. The chain has no built-in defense against that.
//!
//! The defense is **chain head checkpoints**: periodically
//! record the (seq, chain_hash) of the verified chain tail to a
//! storage location separate from `audit_events`. The verifier
//! cross-checks the recorded checkpoint against the current
//! tail; a mismatch surfaces as a tamper alarm.
//!
//! ## Why a separate trait
//!
//! The checkpoint store has different durability and access
//! requirements from the audit chain itself:
//!
//! - **Different blast radius.** v0.33.0 ships a Cloudflare KV
//!   adapter for the checkpoint; the audit chain lives in D1.
//!   An attacker has to compromise BOTH stores synchronously to
//!   evade detection.
//! - **Tiny, never grows.** The checkpoint store holds two
//!   records (latest verified head + last verification result).
//!   It would be wasteful to put them in `audit_events` even if
//!   the blast radius were the same.
//! - **Different access pattern.** Read on every verification,
//!   write only when verification succeeds. KV is well-suited;
//!   D1 is overkill.
//!
//! ## What's in the store
//!
//! Two records, both serialized JSON:
//!
//! - **`AuditChainCheckpoint`**: the latest verified
//!   `(seq, chain_hash, verified_at)` tuple. Updated after a
//!   successful verification run. Used as the resume point for
//!   incremental verification AND as the cross-check value for
//!   tamper detection.
//! - **`AuditVerificationResult`**: the most-recent verification
//!   run's outcome. Surfaced in the admin UI so operators can
//!   see chain status without triggering a fresh verification.

use super::PortResult;
use serde::{Deserialize, Serialize};

/// The verified chain head as of the last successful
/// verification run.
///
/// On a fresh deployment with no prior verification this record
/// is absent; the verifier treats that as "start from the
/// genesis row, no cross-check available". After the first
/// successful run the record is present and subsequent runs
/// cross-check against it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditChainCheckpoint {
    /// The `seq` of the last row the verifier walked
    /// successfully. The next verification resumes from rows
    /// with `seq > last_verified_seq`.
    pub last_verified_seq: i64,
    /// The `chain_hash` of the row at `last_verified_seq`. The
    /// verifier cross-checks: the row with `seq =
    /// last_verified_seq` in the current `audit_events` table
    /// MUST have `chain_hash == this.chain_hash`. A mismatch
    /// indicates wholesale-rewrite tampering at or before that
    /// seq.
    pub chain_hash:        String,
    /// Unix-seconds timestamp of the verification run that
    /// produced this checkpoint.
    pub verified_at:       i64,
}

/// Outcome of one verification run. Persisted alongside the
/// checkpoint so the admin UI can render a status summary
/// without triggering a fresh run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditVerificationResult {
    /// Unix-seconds when the verifier ran.
    pub run_at:                 i64,
    /// Total chain length the verifier saw (= MAX(seq) at run
    /// time, including the genesis row).
    pub chain_length:           i64,
    /// `true` iff every link the verifier checked passed:
    /// `payload_hash` matches the row's payload, `previous_hash`
    /// matches the predecessor's `chain_hash`, and `chain_hash`
    /// is recomputable from the canonical inputs.
    pub valid:                  bool,
    /// First seq where verification failed, or `None` if the
    /// chain is fully valid. The admin UI surfaces this so
    /// operators can investigate the row directly.
    pub first_mismatch_seq:     Option<i64>,
    /// `true` iff a previous checkpoint existed AND the row at
    /// `last_verified_seq` in the current table has the
    /// recorded chain_hash. `false` indicates wholesale-rewrite
    /// tampering. `None` if no prior checkpoint exists (cold
    /// start).
    pub checkpoint_consistent:  Option<bool>,
    /// How many rows the verifier walked in this run. With
    /// incremental verification this is usually small (rows
    /// added since the last checkpoint).
    pub rows_walked:            u64,
}

/// Storage trait for the chain head checkpoint + last
/// verification result. Two adapters ship in v0.33.0:
/// in-memory (for tests and non-Cloudflare deployments) and
/// Cloudflare KV (production).
pub trait AuditChainCheckpointStore {
    /// Read the most-recent successful checkpoint, or `None` if
    /// no verification has succeeded yet.
    async fn read_checkpoint(&self) -> PortResult<Option<AuditChainCheckpoint>>;

    /// Persist a new checkpoint. Called after a successful
    /// verification run. Implementations MAY allow the new
    /// checkpoint to overwrite an older one — last-write-wins
    /// is fine because the verifier only writes after
    /// successful walks.
    async fn write_checkpoint(&self, cp: &AuditChainCheckpoint) -> PortResult<()>;

    /// Read the most-recent verification result (success OR
    /// failure). Distinct from `read_checkpoint` because a
    /// failed verification does NOT advance the checkpoint but
    /// SHOULD update the result so the admin UI surfaces the
    /// alarm.
    async fn read_last_result(&self) -> PortResult<Option<AuditVerificationResult>>;

    /// Persist a verification result. Called by the verifier on
    /// every run, success or failure.
    async fn write_last_result(&self, r: &AuditVerificationResult) -> PortResult<()>;
}
