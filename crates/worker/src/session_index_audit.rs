//! Daily session-index drift detection (v0.40.0, ADR-012 §Q1).
//!
//! Walks `user_sessions` (active rows), peeks the
//! `ActiveSession` DO for each, classifies via
//! `cesauth_core::session_index::classify`, and emits one
//! `session_index_drift` audit event per drift detected.
//! No repair is performed — v0.40.0 is detection-only.
//!
//! ## Why detection-only
//!
//! Two reasons this release ships detection without
//! repair:
//!
//! 1. **Operational visibility comes first.** Until we
//!    have data on how often drift actually occurs, we
//!    don't know whether automated repair is the right
//!    response or whether the appropriate action is
//!    "alert a human and let them decide". Shipping the
//!    detection signal lets operators build the dashboard
//!    panel and watch for a few weeks before we wire up
//!    the destructive D1 mutations.
//! 2. **Repair is safer to ship after observing
//!    classification.** If the cron emits, say, 10000
//!    `AnomalousD1RevokedDoActive` events after
//!    deployment, that's a structural bug in the mirror
//!    write paths — fixing the root cause is the right
//!    move, not auto-rewriting D1.
//!
//! ## Scope cap
//!
//! v0.40.0 walks the first 1000 active rows of
//! `user_sessions`. For the cesauth deployments we know
//! about, this comfortably covers the population. Larger
//! deployments would need cursor pagination across cron
//! ticks; tracked in ADR-012's Q1.5 follow-up.
//!
//! ## Failure semantics
//!
//! The cron is best-effort. A single per-row DO query
//! failure logs and continues; the next day's cron will
//! re-walk and either re-detect or self-heal (for
//! transient conditions).

use cesauth_cf::ports::store::CloudflareActiveSessionStore;
use cesauth_core::ports::store::ActiveSessionStore;
use cesauth_core::session_index::{classify, D1SessionRow, ReconcileOutcome};
use serde::Deserialize;
use worker::Env;

use crate::audit::{self, EventKind};
use crate::log::{self, Category, Level};

/// Maximum number of `user_sessions` rows to walk in one
/// cron run. Drift is rare; if the actual population is
/// larger, ADR-012 §Q1.5 covers cursor pagination across
/// ticks.
const RECONCILE_BATCH_LIMIT: i64 = 1000;

/// Aggregate counters for one cron run. Logged as a
/// summary line at the end so operators can spot
/// regressions in the volume of each outcome over time.
#[derive(Debug, Default, serde::Serialize)]
pub struct ReconcileStats {
    pub walked:                          u64,
    pub in_sync:                         u64,
    pub do_vanished:                     u64,
    pub do_newer_revoke:                 u64,
    pub anomalous_d1_revoked_do_active:  u64,
    /// Per-row infrastructure failures (DO query failed,
    /// row malformed, etc.). Surfaces as a separate counter
    /// so operators can distinguish "drift" (correctness
    /// signal) from "cron is unhealthy" (operational
    /// signal).
    pub errors:                          u64,
}

/// Run one pass of the session-index drift detector.
/// Called from the daily 04:00 UTC scheduled handler.
/// Returns the stats so the caller can log a summary line.
pub async fn run(env: &Env) -> worker::Result<ReconcileStats> {
    let cfg = match crate::config::Config::from_env(env) {
        Ok(c) => c,
        Err(e) => {
            worker::console_error!("session_index_audit: config load failed: {e:?}");
            return Ok(ReconcileStats::default());
        }
    };

    log::emit(&cfg.log, Level::Info, Category::Storage,
        "session_index_audit: pass starting", None);

    let rows = match fetch_active_rows(env, RECONCILE_BATCH_LIMIT).await {
        Ok(r) => r,
        Err(e) => {
            log::emit(&cfg.log, Level::Error, Category::Storage,
                &format!("session_index_audit: D1 read failed: {e:?}"), None);
            return Ok(ReconcileStats::default());
        }
    };

    let store = CloudflareActiveSessionStore::new(env);
    let mut stats = ReconcileStats::default();
    stats.walked = rows.len() as u64;

    for row in rows {
        let do_status = match store.status(&row.session_id).await {
            Ok(s)  => s,
            Err(_) => {
                // Per-row DO query failure. Count as an
                // error and move on; the next cron tick
                // will retry. The most common cause is
                // a transient DO routing failure;
                // persistent failures show up as a
                // growing `errors` counter that
                // operators alert on independently.
                stats.errors += 1;
                continue;
            }
        };
        let outcome = classify(&row, &do_status);
        match outcome {
            ReconcileOutcome::InSync => stats.in_sync += 1,
            ReconcileOutcome::DoVanished => {
                stats.do_vanished += 1;
                emit_drift_event(env, &row, &outcome, "do_vanished").await;
            }
            ReconcileOutcome::DoNewerRevoke { do_revoked_at } => {
                stats.do_newer_revoke += 1;
                emit_drift_event_with_extra(env, &row, &outcome, "do_newer_revoke",
                    Some(do_revoked_at)).await;
            }
            ReconcileOutcome::AnomalousD1RevokedDoActive => {
                stats.anomalous_d1_revoked_do_active += 1;
                emit_drift_event(env, &row, &outcome,
                    "anomalous_d1_revoked_do_active").await;
            }
        }
    }

    log::emit(&cfg.log, Level::Info, Category::Storage,
        &format!(
            "session_index_audit: walked={} in_sync={} do_vanished={} do_newer_revoke={} \
             anomalous={} errors={}",
            stats.walked, stats.in_sync, stats.do_vanished, stats.do_newer_revoke,
            stats.anomalous_d1_revoked_do_active, stats.errors,
        ),
        None,
    );

    Ok(stats)
}

/// Read up to `limit` non-revoked `user_sessions` rows from
/// D1, ordered oldest-first so that long-living drift
/// gets surfaced even if the table has many newer rows.
async fn fetch_active_rows(env: &Env, limit: i64) -> worker::Result<Vec<D1SessionRow>> {
    let db = env.d1("DB")?;
    let stmt = db.prepare(
        "SELECT session_id, user_id, created_at, revoked_at \
         FROM user_sessions \
         WHERE revoked_at IS NULL \
         ORDER BY created_at ASC \
         LIMIT ?1",
    )
    .bind(&[limit.into()])
    .map_err(|e| worker::Error::RustError(format!("session_index_audit bind: {e:?}")))?;
    let result = stmt.all().await
        .map_err(|e| worker::Error::RustError(format!("session_index_audit run: {e:?}")))?;
    let rows: Vec<DbRow> = result.results()
        .map_err(|e| worker::Error::RustError(format!("session_index_audit deser: {e:?}")))?;
    Ok(rows.into_iter().map(|r| D1SessionRow {
        session_id: r.session_id,
        user_id:    r.user_id,
        created_at: r.created_at,
        revoked_at: r.revoked_at,
    }).collect())
}

#[derive(Deserialize)]
struct DbRow {
    session_id: String,
    user_id:    String,
    created_at: i64,
    revoked_at: Option<i64>,
}

/// Emit one `session_index_drift` audit event for a
/// detected drift. Best-effort — a write failure here
/// would only suppress the visibility of one drift, not
/// produce incorrect state.
async fn emit_drift_event(env: &Env, row: &D1SessionRow, outcome: &ReconcileOutcome, kind_str: &str) {
    emit_drift_event_with_extra(env, row, outcome, kind_str, None).await
}

async fn emit_drift_event_with_extra(
    env:           &Env,
    row:           &D1SessionRow,
    _outcome:      &ReconcileOutcome,
    kind_str:      &str,
    do_revoked_at: Option<i64>,
) {
    let payload = match do_revoked_at {
        Some(t) => serde_json::json!({
            "session_id":    row.session_id,
            "user_id":       row.user_id,
            "drift_kind":    kind_str,
            "do_revoked_at": t,
        }),
        None => serde_json::json!({
            "session_id":    row.session_id,
            "user_id":       row.user_id,
            "drift_kind":    kind_str,
        }),
    };
    audit::write_owned(
        env, EventKind::SessionIndexDrift,
        Some(row.user_id.clone()), None,
        Some(payload.to_string()),
    ).await.ok();
}
