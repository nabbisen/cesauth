//! Session-index repair cron handler (v0.49.0,
//! ADR-012 §Q1.5).
//!
//! Fifth pass on the daily 04:00 UTC scheduled event,
//! after `sweep`, `audit_chain_cron`,
//! `session_index_audit`, and `audit_retention_cron`.
//! Independent of the others.
//!
//! ## Relationship to v0.40.0 detection
//!
//! v0.40.0's `session_index_audit` walks D1 outward to
//! the DOs and emits drift events but does NOT mutate
//! D1. v0.49.0's repair pass repeats the walk + classify
//! and (when opted-in via env) writes the repairs.
//!
//! The two passes COULD be unified, but keeping them
//! separate gives operators the option to:
//!
//! 1. Run detection-only on a fresh deployment
//!    (audit pass on, repair pass off-by-default).
//! 2. Watch the drift event stream for a few weeks.
//! 3. Turn repair on
//!    (`SESSION_INDEX_AUTO_REPAIR=true`) once they're
//!    confident the upstream paths are stable.
//!
//! The walk itself is cheap (each row is one DO query
//! at most, batched at 1000), so doing it twice on
//! cron is negligible cost.
//!
//! ## Config
//!
//! Operator env vars:
//!
//! - `SESSION_INDEX_AUTO_REPAIR` — `"true"` to enable
//!   D1 mutations. Anything else (unset, "false", "0",
//!   etc.) treats the pass as detection-only. Default:
//!   detection-only.
//! - `SESSION_INDEX_REPAIR_BATCH_LIMIT` — max rows per
//!   pass. Default 1000 (matches the v0.40.0 audit
//!   batch).

use cesauth_cf::ports::session_index::CloudflareSessionIndexRepo;
use cesauth_cf::ports::store::CloudflareActiveSessionStore;
use cesauth_core::ports::PortResult;
use cesauth_core::session_index::repair::{
    run_repair_pass, RepairConfig,
};
use time::OffsetDateTime;
use worker::{console_error, console_log, Env};

pub async fn run(env: &Env) -> PortResult<()> {
    let cfg = read_config(env);
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let index = CloudflareSessionIndexRepo::new(env);
    let store = CloudflareActiveSessionStore::new(env);

    let outcome = run_repair_pass(&index, &store, cfg, now).await
        .map_err(|e| {
            console_error!("session_index_repair: pass failed: {e:?}");
            cesauth_core::ports::PortError::Unavailable
        })?;

    if outcome.dry_run {
        console_log!(
            "session_index_repair: [DRY RUN] walked={} in_sync={} \
             would-repair-do_vanished={} would-repair-do_newer_revoke={} \
             anomalous={} errors={} \
             (set SESSION_INDEX_AUTO_REPAIR=true to enable repairs)",
            outcome.walked, outcome.in_sync,
            outcome.do_vanished_repaired,
            outcome.do_newer_revoke_repaired,
            outcome.anomalous_alert_only,
            outcome.errors,
        );
    } else {
        console_log!(
            "session_index_repair: walked={} in_sync={} \
             repaired-do_vanished={} repaired-do_newer_revoke={} \
             anomalous={} errors={}",
            outcome.walked, outcome.in_sync,
            outcome.do_vanished_repaired,
            outcome.do_newer_revoke_repaired,
            outcome.anomalous_alert_only,
            outcome.errors,
        );
    }

    Ok(())
}

fn read_config(env: &Env) -> RepairConfig {
    let auto = env.var("SESSION_INDEX_AUTO_REPAIR").ok()
        .map(|v| v.to_string() == "true")
        .unwrap_or(false);
    let batch = env.var("SESSION_INDEX_REPAIR_BATCH_LIMIT").ok()
        .and_then(|v| v.to_string().parse().ok())
        .unwrap_or(1000);
    RepairConfig {
        auto_repair_enabled: auto,
        batch_limit:         batch,
    }
}
