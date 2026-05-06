//! Audit chain verification cron handler (Phase 2 of ADR-010,
//! v0.33.0).
//!
//! Wired into the daily 04:00 UTC scheduled event alongside the
//! anonymous-trial sweep. Runs an incremental verification:
//! resumes from the last checkpoint, walks new rows, writes a
//! fresh checkpoint on success.
//!
//! Failure modes:
//!
//! - **Tamper detected.** `verify_chain` returns a result with
//!   `valid = false` (and likely a populated
//!   `first_mismatch_seq`). The cron writes the result to the
//!   checkpoint store (so the admin UI surfaces the alarm) and
//!   logs at error level via `console_error!`. The cron does
//!   NOT propagate an error to the runtime — the result is
//!   already persisted, and a runtime error would make the
//!   alarm less visible (it'd only show in Cloudflare's
//!   invocation history rather than in the admin UI).
//!
//! - **Storage outage.** `verify_chain` itself returns
//!   `PortError`. The cron logs and propagates so the operator
//!   can see "the verifier couldn't run" distinctly from "the
//!   verifier ran and found tamper".
//!
//! Operators reading this handler: the meat is in
//! `cesauth_core::audit::verifier::verify_chain`. This file is
//! the env-touching glue.

use cesauth_cf::ports::audit::CloudflareAuditEventRepository;
use cesauth_cf::ports::audit_chain::CloudflareAuditChainCheckpointStore;
use cesauth_core::audit::verifier::verify_chain;
use cesauth_core::ports::PortResult;
use time::OffsetDateTime;
use worker::{console_error, console_log, Env};

/// Run one daily verification. Returns `Ok(())` if the verifier
/// COMPLETED (regardless of whether it found tamper); returns
/// `Err` only if the verifier itself couldn't run.
pub async fn run(env: &Env) -> PortResult<()> {
    let repo        = CloudflareAuditEventRepository::new(env);
    let checkpoints = CloudflareAuditChainCheckpointStore::new(env);
    let now_unix    = OffsetDateTime::now_utc().unix_timestamp();

    let result = verify_chain(&repo, &checkpoints, now_unix).await?;

    if result.valid {
        console_log!(
            "audit chain verified: chain_length={}, rows_walked={}, checkpoint_consistent={:?}",
            result.chain_length, result.rows_walked, result.checkpoint_consistent,
        );
    } else {
        // Tamper detected. The result was already written to the
        // checkpoint store by `verify_chain`. Surface here so the
        // platform-level Workers logs also carry the alarm.
        console_error!(
            "audit chain TAMPER DETECTED: first_mismatch_seq={:?}, checkpoint_consistent={:?}, chain_length={}",
            result.first_mismatch_seq, result.checkpoint_consistent, result.chain_length,
        );
    }

    Ok(())
}
