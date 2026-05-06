//! Audit chain verifier (ADR-010 Phase 2, v0.33.0).
//!
//! Walks the `audit_events` chain from a starting seq forward,
//! verifying every link and reporting the outcome. Persists a
//! fresh checkpoint on success.
//!
//! ## What "verification" means here
//!
//! For each row past the resume point, the verifier checks:
//!
//! 1. **`payload_hash` integrity.** SHA-256 of the row's
//!    `payload` bytes must equal `payload_hash`. Catches
//!    in-place edits to the payload column.
//! 2. **`chain_hash` integrity.** Recomputed
//!    `compute_chain_hash(previous_hash, payload_hash, seq, ts,
//!    kind, id)` must equal `chain_hash`. Catches in-place
//!    edits to any chain-input field.
//! 3. **Chain linkage.** The row's `previous_hash` must equal
//!    the actual predecessor row's `chain_hash`. Catches
//!    deletion of intermediate rows and reordering.
//!
//! On a fresh deployment with no prior checkpoint the verifier
//! also cross-checks the genesis row's sentinel hashes.
//!
//! On runs WITH a prior checkpoint the verifier additionally
//! cross-checks `checkpoint.chain_hash` against the current
//! row at `checkpoint.last_verified_seq`. A mismatch indicates
//! the chain has been rewritten BEFORE the checkpoint —
//! wholesale-rewrite tampering, the attack the chain
//! mechanism alone can't catch.
//!
//! ## Incremental verification
//!
//! The default mode resumes from `checkpoint.last_verified_seq`
//! and walks forward. Operators can trigger a full re-verify
//! from the admin UI; the worker layer calls
//! [`verify_chain_full`] to rewalk from the genesis row.
//!
//! Both modes write the same `AuditVerificationResult` shape;
//! the result's `rows_walked` field tells the operator which
//! mode was used.

use crate::audit::chain::{
    compute_chain_hash, verify_payload_hash, GENESIS_HASH,
};
use crate::ports::audit::AuditEventRepository;
use crate::ports::audit_chain::{
    AuditChainCheckpoint, AuditChainCheckpointStore,
    AuditVerificationResult,
};
use crate::ports::PortResult;

/// Page size when walking the chain via
/// `AuditEventRepository::fetch_after_seq`. Sized to fit a few
/// pages comfortably under a Workers cron's CPU budget while
/// keeping memory bounded.
const PAGE_SIZE: u32 = 200;

/// Run an incremental chain verification. Resumes from the last
/// checkpoint (or seq=0 if none), walks the chain forward in
/// pages, verifies every link, and on success writes a fresh
/// checkpoint + result. On failure the checkpoint is NOT
/// advanced (so the next run retries from the same point); the
/// result IS written so the admin UI surfaces the alarm.
///
/// Returns the result that was written so the caller (cron
/// handler, admin "verify now" button) can include it in any
/// log line or response body.
pub async fn verify_chain<R, C>(
    repo:        &R,
    checkpoints: &C,
    now_unix:    i64,
) -> PortResult<AuditVerificationResult>
where
    R: AuditEventRepository       + ?Sized,
    C: AuditChainCheckpointStore  + ?Sized,
{
    let prior = checkpoints.read_checkpoint().await?;
    let resume_from = prior.as_ref().map(|c| c.last_verified_seq).unwrap_or(0);

    // Cross-check: if a prior checkpoint exists, the row at its
    // seq must still have the recorded chain_hash. Detects
    // wholesale-rewrite tampering BEFORE the checkpoint.
    let checkpoint_consistent = match &prior {
        Some(cp) => {
            // Read the row at last_verified_seq via fetch_after_seq
            // with a (seq - 1) cursor.
            let page = repo.fetch_after_seq(cp.last_verified_seq - 1, 1).await?;
            match page.first() {
                Some(row) if row.seq == cp.last_verified_seq => {
                    Some(row.chain_hash == cp.chain_hash)
                }
                _ => Some(false),  // row at checkpointed seq is gone
            }
        }
        None => None,
    };

    let outcome = walk_and_verify(repo, resume_from, &prior).await?;
    let total_seq = match &outcome.last_good {
        Some(seq) => *seq,
        None => match &prior {
            Some(cp) => cp.last_verified_seq,
            None     => 0,
        },
    };

    let result = AuditVerificationResult {
        run_at:                now_unix,
        chain_length:          outcome.chain_length,
        valid:                 outcome.first_mismatch.is_none() && checkpoint_consistent.unwrap_or(true),
        first_mismatch_seq:    outcome.first_mismatch,
        checkpoint_consistent,
        rows_walked:           outcome.rows_walked,
    };

    checkpoints.write_last_result(&result).await?;

    // Advance the checkpoint ONLY on success. Detected tampering
    // means the next run should re-attempt from the same point;
    // the operator's job is to investigate the alarm before the
    // chain advances.
    if result.valid {
        if let Some(seq) = outcome.last_good {
            // Find the row at `seq` to get its chain_hash. We
            // remembered it from the walk; re-fetch is one
            // round-trip but keeps the walk loop free of
            // checkpoint-specific bookkeeping.
            let page = repo.fetch_after_seq(seq - 1, 1).await?;
            if let Some(row) = page.first().filter(|r| r.seq == seq) {
                checkpoints.write_checkpoint(&AuditChainCheckpoint {
                    last_verified_seq: seq,
                    chain_hash:        row.chain_hash.clone(),
                    verified_at:       now_unix,
                }).await?;
            }
        }
        // No `last_good` means the chain is empty or the verifier
        // didn't walk past the prior checkpoint. Don't advance.
    }

    Ok(result)
}

/// Run a FULL re-verification, ignoring any prior checkpoint.
/// The caller is the operator-triggered "verify now" path; cron
/// runs use [`verify_chain`] instead.
///
/// Behavior is identical to `verify_chain` except the resume
/// point is hard-coded to seq=0 and the prior-checkpoint
/// cross-check is skipped (`checkpoint_consistent: None`).
/// On success this DOES advance the checkpoint to the new head.
pub async fn verify_chain_full<R, C>(
    repo:        &R,
    checkpoints: &C,
    now_unix:    i64,
) -> PortResult<AuditVerificationResult>
where
    R: AuditEventRepository       + ?Sized,
    C: AuditChainCheckpointStore  + ?Sized,
{
    let outcome = walk_and_verify(repo, 0, &None).await?;

    let result = AuditVerificationResult {
        run_at:                now_unix,
        chain_length:          outcome.chain_length,
        valid:                 outcome.first_mismatch.is_none(),
        first_mismatch_seq:    outcome.first_mismatch,
        checkpoint_consistent: None,
        rows_walked:           outcome.rows_walked,
    };

    checkpoints.write_last_result(&result).await?;

    if result.valid {
        if let Some(seq) = outcome.last_good {
            let page = repo.fetch_after_seq(seq - 1, 1).await?;
            if let Some(row) = page.first().filter(|r| r.seq == seq) {
                checkpoints.write_checkpoint(&AuditChainCheckpoint {
                    last_verified_seq: seq,
                    chain_hash:        row.chain_hash.clone(),
                    verified_at:       now_unix,
                }).await?;
            }
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------
// Internal walk
// ---------------------------------------------------------------------

struct WalkOutcome {
    /// Highest seq verified successfully in this run, or in a
    /// prior checkpoint if the walk found nothing new.
    last_good:      Option<i64>,
    /// First seq where verification failed, or `None` if all
    /// walked rows passed.
    first_mismatch: Option<i64>,
    /// Total chain length at the time of the walk (the highest
    /// seq across the whole table, regardless of where the walk
    /// resumed).
    chain_length:   i64,
    /// How many rows were walked + verified in this run.
    rows_walked:    u64,
}

/// Page-paginated walk over rows with `seq > from_seq`.
///
/// Verifies each row's payload_hash + chain_hash + previous_hash
/// linkage against the predecessor. Stops at the first mismatch
/// (`first_mismatch` populated, `last_good` unchanged from the
/// last passing row).
///
/// `prev_for_anchor` is the prior checkpoint, if any. Used as
/// the predecessor's `chain_hash` for the FIRST row of the
/// walk. On a cold start (no prior checkpoint) the genesis row
/// is its own anchor (its previous_hash = GENESIS_HASH).
async fn walk_and_verify<R>(
    repo:            &R,
    from_seq:        i64,
    prev_for_anchor: &Option<AuditChainCheckpoint>,
) -> PortResult<WalkOutcome>
where
    R: AuditEventRepository + ?Sized,
{
    let chain_length = match repo.tail().await? {
        Some(t) => t.seq,
        None    => 0,
    };

    let mut last_good:       Option<i64> = prev_for_anchor.as_ref().map(|c| c.last_verified_seq);
    let mut first_mismatch:  Option<i64> = None;
    let mut rows_walked:     u64         = 0;
    let mut prev_chain_hash: String      = match prev_for_anchor {
        Some(cp) => cp.chain_hash.clone(),
        None     => GENESIS_HASH.to_owned(),
    };
    let mut cursor = from_seq;

    'outer: loop {
        let page = repo.fetch_after_seq(cursor, PAGE_SIZE).await?;
        if page.is_empty() {
            break;
        }
        let last_seq_in_page = page.last().unwrap().seq;

        for row in page {
            rows_walked += 1;
            cursor = row.seq;

            // The genesis row (seq=1) is the chain anchor — its
            // chain_hash equals the GENESIS_HASH sentinel by
            // convention, NOT a recomputable hash. We accept it
            // as-is provided its sentinel fields match.
            if row.seq == 1 {
                if row.previous_hash != GENESIS_HASH || row.chain_hash != GENESIS_HASH {
                    first_mismatch = Some(row.seq);
                    break 'outer;
                }
                last_good = Some(row.seq);
                prev_chain_hash = row.chain_hash.clone();
                continue;
            }

            // Payload hash must match the canonical bytes.
            if !verify_payload_hash(&row.payload_hash, row.payload.as_bytes()) {
                first_mismatch = Some(row.seq);
                break 'outer;
            }

            // Chain linkage: previous_hash must equal predecessor's
            // chain_hash.
            if row.previous_hash != prev_chain_hash {
                first_mismatch = Some(row.seq);
                break 'outer;
            }

            // Recompute chain_hash from canonical inputs.
            let recomputed = compute_chain_hash(
                &row.previous_hash,
                &row.payload_hash,
                row.seq,
                row.ts,
                &row.kind,
                &row.id,
            );
            if recomputed != row.chain_hash {
                first_mismatch = Some(row.seq);
                break 'outer;
            }

            last_good = Some(row.seq);
            prev_chain_hash = row.chain_hash.clone();
        }

        // Page boundary continuation. If the page had fewer rows
        // than PAGE_SIZE we're at the end of the chain.
        if cursor != last_seq_in_page {
            break;  // mismatch broke 'outer; defensive guard
        }
    }

    Ok(WalkOutcome { last_good, first_mismatch, chain_length, rows_walked })
}

// End-to-end tests for the verifier live in
// `cesauth-adapter-test::audit_chain::tests` — the verifier
// uses port traits whose only impls are in adapter-test, and
// circular dev-dependencies (core dev-depending on adapter-test)
// produce duplicate trait artifacts in Rust's compilation
// model. Co-locating the tests with the in-memory adapters is
// the idiomatic workaround.
