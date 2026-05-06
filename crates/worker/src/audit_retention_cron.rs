//! Audit retention cron handler (v0.48.0, ADR-014 §Q3).
//!
//! Fourth pass on the daily 04:00 UTC scheduled event,
//! after `sweep`, `audit_chain_cron`, and
//! `session_index_audit`. Independent: a retention
//! failure must not block the other passes (and vice
//! versa).
//!
//! Reads the verifier checkpoint, computes the safe
//! prune floor, deletes audit rows older than the
//! per-kind / global windows. The pure orchestration
//! lives in `cesauth_core::audit::retention`; this
//! handler is env-touching glue.
//!
//! ## Config
//!
//! Operator env vars (both optional):
//!
//! - `AUDIT_RETENTION_DAYS` — default 365.
//! - `AUDIT_RETENTION_TOKEN_INTROSPECTED_DAYS` — default 30.
//!
//! Setting either to `0` disables that pass. The pure
//! service refuses to prune at all without a verifier
//! checkpoint, so a fresh deployment runs cron-no-ops
//! until `audit_chain_cron` writes the first checkpoint
//! (typically the next day).

use cesauth_cf::ports::audit::CloudflareAuditEventRepository;
use cesauth_cf::ports::audit_chain::CloudflareAuditChainCheckpointStore;
use cesauth_core::audit::retention::{
    run_retention_pass, RetentionConfig,
};
use cesauth_core::ports::PortResult;
use time::OffsetDateTime;
use worker::{console_error, console_log, Env};

/// Run one daily retention pass. Returns `Ok(())`
/// regardless of whether deletes happened; surfaces
/// counts via `console_log!` for operator dashboards.
/// Returns `Err` only if the storage layer is
/// unreachable.
pub async fn run(env: &Env) -> PortResult<()> {
    let cfg = read_config(env);
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let repo = CloudflareAuditEventRepository::new(env);
    let cps  = CloudflareAuditChainCheckpointStore::new(env);

    let outcome = run_retention_pass(&repo, &cps, cfg, now).await
        .map_err(|e| {
            console_error!("audit_retention: pass failed: {e:?}");
            cesauth_core::ports::PortError::Unavailable
        })?;

    if outcome.skipped_no_checkpoint {
        console_log!(
            "audit_retention: skipped (no chain checkpoint yet — \
             waiting for first verification cron run)"
        );
        return Ok(());
    }

    console_log!(
        "audit_retention: deleted_token_introspected={} deleted_global={} \
         checkpoint_seq={} floor_seq={} \
         (cfg: global_days={} ti_days={})",
        outcome.deleted_token_introspected,
        outcome.deleted_global,
        outcome.checkpoint_seq,
        outcome.floor_seq,
        cfg.global_days,
        cfg.token_introspected_days,
    );

    Ok(())
}

/// Read retention config from env. Missing or
/// non-numeric values fall back to the published
/// defaults; an explicit `0` disables the pass.
fn read_config(env: &Env) -> RetentionConfig {
    let global = env.var("AUDIT_RETENTION_DAYS").ok()
        .and_then(|v| v.to_string().parse().ok())
        .unwrap_or(365);
    let ti = env.var("AUDIT_RETENTION_TOKEN_INTROSPECTED_DAYS").ok()
        .and_then(|v| v.to_string().parse().ok())
        .unwrap_or(30);
    RetentionConfig {
        global_days:             global,
        token_introspected_days: ti,
    }
}
