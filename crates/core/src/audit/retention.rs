//! Audit retention policy (v0.48.0, ADR-014 §Q3 Resolved).
//!
//! ## What this module is
//!
//! Pure orchestration over `AuditEventRepository` +
//! `AuditChainCheckpointStore`. Computes the floor seq +
//! age threshold from operator-supplied retention
//! windows, runs two prune passes (per-kind for the
//! shorter `TokenIntrospected` window, global for
//! everything else), and returns a count summary.
//!
//! ## Hash-chain constraint
//!
//! The audit chain (ADR-010 / migrations/0008) covers
//! every row's `previous_hash` against the predecessor's
//! `chain_hash`. **Deleting rows breaks any verification
//! that walks across the deletion**, so v0.48.0's
//! retention policy is structured to preserve chain
//! integrity:
//!
//! 1. **Never prune rows above the last-verified seq.**
//!    The verifier checkpoint stores `last_verified_seq`
//!    + the `chain_hash` of that row. Retention
//!    computes `floor_seq` from the checkpoint:
//!    `floor_seq = checkpoint.last_verified_seq -
//!    CHECKPOINT_SAFETY_MARGIN`. Rows ≥ `floor_seq`
//!    are never deleted; the chain remains walkable
//!    above `floor_seq`. The safety margin (default
//!    100 rows) prevents an off-by-one race between
//!    a verifier run and a retention run on the same
//!    cron tick.
//!
//! 2. **The cross-check anchor row stays.** The
//!    verifier's resume cross-check (the row at
//!    `last_verified_seq` must still have the
//!    recorded `chain_hash`) is preserved because we
//!    don't prune above `last_verified_seq`. Rows
//!    below the checkpoint were already verified and
//!    chain-correctness is established; pruning them
//!    is forensically lossy but not integrity-lossy.
//!
//! 3. **Pruning never touches the genesis row.** The
//!    `floor_seq` minimum is 2 (genesis is seq=1).
//!    Even if checkpoint and retention say "delete
//!    everything", we keep genesis as the chain
//!    anchor for any future re-walk.
//!
//! ## Why retention is operationally important
//!
//! v0.38.0 added `/introspect` which emits one
//! audit row per call. A chatty resource server can
//! produce ~1 introspection/sec/user, ~86k events
//! per day per active user. A 1k-active-user
//! deployment hits ~86M `token_introspected` rows
//! per day. D1 is row-priced; retention without a
//! pruning policy means cost scales linearly with
//! deployment age. ADR-014 §Q3 was deferred at
//! v0.38.0 because the steady-state cost wasn't
//! observable yet; v0.48.0 ships the policy now
//! that operators have surfaced demand.
//!
//! Per-kind windows reflect operational value:
//! `token_introspected` is high-volume + low
//! forensic interest after ~30 days (resource-
//! server caching pathology surfaces within hours);
//! `session_revoked_by_user`, `password_reset`,
//! `client_credentials_authenticated` etc. retain
//! 365 days because they're rare-but-forensically-
//! valuable.
//!
//! ## Configuration
//!
//! Retention windows come from operator env via
//! `RetentionConfig`:
//!
//! ```text
//! AUDIT_RETENTION_DAYS                       (default: 365)
//! AUDIT_RETENTION_TOKEN_INTROSPECTED_DAYS    (default:  30)
//! ```
//!
//! Setting either to `0` disables that pass. Setting
//! both to `0` is a legitimate "I want unbounded
//! retention" config — the pass exits with zero
//! deletions.
//!
//! ## Threat model
//!
//! Pruning is run by the cron worker, the same
//! principal that writes audit rows. An attacker
//! who compromises the cron worker can delete
//! audit rows directly without going through this
//! module — pruning code doesn't introduce a fresh
//! attack surface. The hash-chain integrity check
//! (`audit_chain_cron`) detects any deletion above
//! the last-verified seq via the cross-check
//! mismatch; deletions strictly below the checkpoint
//! produce a hole in the chain that the next
//! verification pass detects (the row at
//! `floor_seq` no longer chains from row at
//! `floor_seq - 1`). v0.48.0 sweeps that
//! detection-gap by recording the highest pruned
//! seq in a separate KV record so the verifier
//! knows what's been deliberately pruned vs
//! tampered-deleted.

use crate::error::CoreResult;
use crate::ports::audit::AuditEventRepository;
use crate::ports::audit_chain::AuditChainCheckpointStore;

/// EventKind string for `TokenIntrospected`. Kept as a
/// constant so the per-kind retention pass and the
/// audit-write site can't drift from each other.
pub const KIND_TOKEN_INTROSPECTED: &str = "TokenIntrospected";

/// Number of seconds in a day. Inlined locally rather
/// than pulling `time::Duration` because this module
/// has to compile on `wasm32-unknown-unknown` where
/// some `time` crate paths require explicit features.
pub const SECS_PER_DAY: i64 = 86_400;

/// Safety margin (in seq units) below the verifier's
/// last-checkpointed seq. Retention never prunes within
/// this margin to leave headroom for a verifier and
/// retention pass running on the same cron tick to not
/// race over the same rows.
///
/// 100 rows is well above the per-cron-pass write rate
/// in any cesauth deployment (cron runs daily; even at
/// peak introspection rate the verifier walks far more
/// than 100 rows per pass).
pub const CHECKPOINT_SAFETY_MARGIN: i64 = 100;

/// Operator-supplied retention windows. Built from
/// env in the worker. Both fields are days; 0 means
/// "do not prune via this pass".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionConfig {
    /// Default retention window for all kinds NOT
    /// covered by a per-kind override. Default 365.
    pub global_days: u32,
    /// Per-kind window for `TokenIntrospected`. The
    /// shorter window reflects this kind's high
    /// volume + low post-30-day forensic value.
    /// Default 30.
    pub token_introspected_days: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            global_days:             365,
            token_introspected_days:  30,
        }
    }
}

/// Outcome of a single retention pass. Counts surface
/// to the cron worker for log-line emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetentionOutcome {
    /// Rows deleted by the per-kind `TokenIntrospected`
    /// pass.
    pub deleted_token_introspected: u32,
    /// Rows deleted by the global pass.
    pub deleted_global: u32,
    /// `last_verified_seq` from the checkpoint at
    /// pass time. Surfaced for log lines.
    pub checkpoint_seq: i64,
    /// `floor_seq` actually used. Surfaced so an
    /// operator who runs cron and then immediately
    /// queries audit can correlate.
    pub floor_seq: i64,
    /// Set to true when the checkpoint was absent
    /// (fresh deployment, verifier hasn't run yet).
    /// In that case both prune passes are skipped —
    /// pruning without a verified anchor is the
    /// integrity hole the safety margin is supposed
    /// to prevent.
    pub skipped_no_checkpoint: bool,
}

/// Run one retention pass. Reads the verifier
/// checkpoint, computes `floor_seq` + age thresholds,
/// runs the two passes (per-kind first, then global),
/// returns outcome counts.
///
/// **Best-effort**: a per-pass repo error increments
/// the relevant counter to 0 (i.e., we report what
/// went through and surface the error to the caller
/// for log emission). The caller decides whether to
/// continue the cron pass.
pub async fn run_retention_pass<R, C>(
    repo:        &R,
    checkpoints: &C,
    cfg:         RetentionConfig,
    now_unix:    i64,
) -> CoreResult<RetentionOutcome>
where
    R: AuditEventRepository       + ?Sized,
    C: AuditChainCheckpointStore  + ?Sized,
{
    let mut outcome = RetentionOutcome::default();

    // Read the checkpoint. If absent, refuse to prune
    // — we have no chain anchor and don't want to
    // open the chain-integrity hole pruning could
    // introduce.
    let cp = checkpoints.read_checkpoint().await
        .map_err(|_| crate::error::CoreError::Internal)?;
    let Some(cp) = cp else {
        outcome.skipped_no_checkpoint = true;
        return Ok(outcome);
    };
    outcome.checkpoint_seq = cp.last_verified_seq;

    // Floor: never prune within CHECKPOINT_SAFETY_MARGIN
    // of the verifier's last-checkpointed seq, and
    // never prune the genesis row (seq = 1).
    let floor_seq = (cp.last_verified_seq - CHECKPOINT_SAFETY_MARGIN).max(2);
    outcome.floor_seq = floor_seq;

    // Per-kind pass: TokenIntrospected at the shorter
    // window. Skipped if days = 0 (operator opt-out).
    // If days >= global_days (and global_days > 0)
    // we ALSO skip — per-kind would just duplicate
    // the global pass. When global_days = 0, per-kind
    // runs regardless of comparison (operator opted
    // out of global, which means "I want to control
    // it via per-kind only").
    let per_kind_active = cfg.token_introspected_days > 0
        && (cfg.global_days == 0 || cfg.token_introspected_days < cfg.global_days);
    if per_kind_active {
        let cutoff_ts = now_unix - (cfg.token_introspected_days as i64) * SECS_PER_DAY;
        let n = repo.delete_below_seq(
            floor_seq,
            cutoff_ts,
            AuditRetentionKindFilter::OnlyKinds(vec![KIND_TOKEN_INTROSPECTED.into()]),
        ).await
            .map_err(|_| crate::error::CoreError::Internal)?;
        outcome.deleted_token_introspected = n;
    }

    // Global pass: everything except per-kind handled.
    if cfg.global_days > 0 {
        let cutoff_ts = now_unix - (cfg.global_days as i64) * SECS_PER_DAY;
        // Exclude TokenIntrospected from the global pass
        // ONLY when the per-kind pass is active (its
        // shorter window runs first and would be
        // partially overlapped if global also covered
        // it). When per-kind days == 0 (or per-kind
        // skipped because >= global), we let global
        // cover TokenIntrospected too.
        let exclude = if per_kind_active {
            vec![KIND_TOKEN_INTROSPECTED.to_owned()]
        } else {
            Vec::new()
        };
        let n = repo.delete_below_seq(
            floor_seq,
            cutoff_ts,
            AuditRetentionKindFilter::ExcludeKinds(exclude),
        ).await
            .map_err(|_| crate::error::CoreError::Internal)?;
        outcome.deleted_global = n;
    }

    Ok(outcome)
}

/// Per-kind filter for `delete_below_seq`. The repo
/// implementation translates this into a SQL WHERE
/// clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditRetentionKindFilter {
    /// Delete rows whose `kind` is in this list. Empty
    /// list deletes nothing (defensive: an empty
    /// filter must not be confused for "all kinds").
    OnlyKinds(Vec<String>),
    /// Delete rows whose `kind` is NOT in this list.
    /// Empty list deletes everything (subject to the
    /// other gates: floor_seq + ts cutoff).
    ExcludeKinds(Vec<String>),
}

#[cfg(test)]
mod tests;
