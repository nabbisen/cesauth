//! D1 session-index repair (v0.49.0, ADR-012 §Q1.5
//! Resolved).
//!
//! ## Relationship to v0.40.0 detection
//!
//! v0.40.0 introduced the `session_index_audit` cron
//! pass which walks D1 outward to the per-session DOs,
//! classifies each row's drift state via
//! `session_index::classify`, and emits a
//! `SessionIndexDrift` audit event per non-`InSync`
//! row. Detection-only — no repair.
//!
//! v0.49.0 adds the repair half: same classification,
//! but two of the three drift outcomes (`DoVanished`,
//! `DoNewerRevoke`) trigger a D1 mutation that brings
//! the mirror back in line with the DO. The third
//! (`AnomalousD1RevokedDoActive`) remains alert-only
//! — auto-repair would mask whatever upstream bug
//! produced it, defeating the point of the alarm.
//!
//! ## Why this is a pure service
//!
//! Same pattern as `revoke_all_other_sessions`
//! (v0.45.0) and `run_retention_pass` (v0.48.0): the
//! repair iteration is testable end-to-end without a
//! workers-rs harness. Stub `SessionIndexRepo` +
//! stub `ActiveSessionStore` lets us pin every
//! drift-x-config combination as a unit test.
//!
//! ## Auto-repair vs alert-only
//!
//! `RepairConfig` exposes a single env-driven flag
//! `auto_repair_enabled`. When `false` (the cesauth
//! default), the pass classifies + counts but emits
//! no D1 writes — same surface as v0.40.0
//! detection-only. When `true`, the pass writes the
//! repairs.
//!
//! Operators opt in deliberately. Two reasons for the
//! default-off:
//!
//! - **Trust gradient.** A deployment that hasn't
//!   yet observed a few weeks of clean drift events
//!   shouldn't have automated repair pointed at its
//!   D1 — the first cron pass after a regression
//!   could mass-delete real rows. The default-off
//!   gives operators time to watch the
//!   `session_index_drift` event stream and decide
//!   "yes, the upstream paths are stable; turn
//!   repair on".
//! - **Reversibility.** Detection produces an audit
//!   row per drift; that row references the
//!   session_id and the classification. If repair
//!   later turns out to be wrong, the drift events
//!   are the trail back to "what got changed and
//!   why". Auto-repair without the prior detection
//!   period collapses that trail.
//!
//! ## Counts surfaced
//!
//! `RepairOutcome` reports per-category counts
//! (walked, in_sync, do_vanished_repaired,
//! do_newer_revoke_repaired, anomalous_alert_only,
//! errors) so the cron log + dashboards can
//! distinguish "found 5 drifts, repaired 5" from
//! "found 5 drifts, repair config is off".

use crate::error::CoreResult;
use crate::ports::session_index::SessionIndexRepo;
use crate::ports::store::ActiveSessionStore;
use crate::session_index::{classify, D1SessionRow, ReconcileOutcome};

/// Operator-supplied config for the repair pass.
/// Mirrors the env switch named in ADR-012 §Q1.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RepairConfig {
    /// When `false` (default), the pass classifies
    /// drifts but does NOT mutate D1 — same
    /// detection-only surface as v0.40.0.
    /// When `true`, `DoVanished` and `DoNewerRevoke`
    /// drifts produce repair writes.
    pub auto_repair_enabled: bool,
    /// Maximum rows to walk in one pass. The
    /// reconcile cron uses 1000 in v0.40.0; the
    /// repair pass inherits that cap because the
    /// per-row budget is the same (one DO query +
    /// possibly one D1 mutation).
    pub batch_limit: u32,
}

/// Outcome of a single repair pass. Surfaces to the
/// cron worker for log emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RepairOutcome {
    /// Total rows examined in this pass.
    pub walked: u32,
    /// Rows where D1 and DO agreed.
    pub in_sync: u32,
    /// Rows where the DO had no record. Repaired
    /// (D1 row deleted) when `auto_repair_enabled`,
    /// counted-only otherwise.
    pub do_vanished_repaired: u32,
    /// Rows where the DO's revoke timestamp was newer
    /// than D1's. Repaired (D1 `revoked_at` set)
    /// when `auto_repair_enabled`, counted-only
    /// otherwise.
    pub do_newer_revoke_repaired: u32,
    /// Rows where D1 said revoked but the DO said
    /// active. **Never auto-repaired** — see
    /// ADR-012 §Q1, §Q1.5 paragraphs.
    pub anomalous_alert_only: u32,
    /// Per-row failures (DO query or D1 mutation
    /// errored). Best-effort: increment and continue,
    /// don't abort the batch.
    pub errors: u32,
    /// Set when `auto_repair_enabled = false`. The
    /// pass classified drifts and reports counts
    /// (so dashboards still see "we'd have repaired
    /// N rows if turned on") but emitted zero writes.
    pub dry_run: bool,
}

/// Run one repair pass. Reads up to `cfg.batch_limit`
/// rows from the D1 mirror, queries each row's
/// corresponding DO state, classifies, and (when
/// `auto_repair_enabled`) mutates D1 to bring it in
/// line.
///
/// `now_unix` is unused for the repair semantics
/// themselves (the DO's existing revoke timestamp is
/// the value written for `DoNewerRevoke`); it's
/// present in the signature for symmetry with other
/// cron pure services and for potential future use
/// (e.g., a "skip rows newer than N seconds" guard
/// against racing ongoing writes).
///
/// Best-effort: per-row errors increment `errors`
/// and continue the batch. The alternative (aborting
/// on first error) would leave the bulk of drifts
/// unrepaired forever if the first row hits a
/// transient failure.
pub async fn run_repair_pass<I, S>(
    index:   &I,
    store:   &S,
    cfg:     RepairConfig,
    _now:    i64,
) -> CoreResult<RepairOutcome>
where
    I: SessionIndexRepo,
    S: ActiveSessionStore,
{
    let mut outcome = RepairOutcome::default();
    outcome.dry_run = !cfg.auto_repair_enabled;

    let limit = cfg.batch_limit.max(1);
    let rows = index.list_active(limit).await
        .map_err(|_| crate::error::CoreError::Internal)?;

    outcome.walked = rows.len() as u32;

    for row in rows {
        // The reconcile path consumes a slim row
        // shape; classify expects the same.
        let d1_row = D1SessionRow {
            session_id: row.session_id.clone(),
            user_id:    row.user_id.clone(),
            created_at: row.created_at,
            revoked_at: row.revoked_at,
        };

        // Per-row DO query. Failure is per-row, not
        // batch-fatal.
        let do_status = match store.status(&row.session_id).await {
            Ok(s)  => s,
            Err(_) => {
                outcome.errors += 1;
                continue;
            }
        };

        match classify(&d1_row, &do_status) {
            ReconcileOutcome::InSync => {
                outcome.in_sync += 1;
            }
            ReconcileOutcome::DoVanished => {
                if cfg.auto_repair_enabled {
                    match index.delete_row(&row.session_id).await {
                        Ok(())  => outcome.do_vanished_repaired += 1,
                        Err(_)  => outcome.errors += 1,
                    }
                } else {
                    // Detection-only; count toward
                    // the would-have-repaired total.
                    outcome.do_vanished_repaired += 1;
                }
            }
            ReconcileOutcome::DoNewerRevoke { do_revoked_at } => {
                if cfg.auto_repair_enabled {
                    match index.mark_revoked(&row.session_id, do_revoked_at).await {
                        Ok(())  => outcome.do_newer_revoke_repaired += 1,
                        Err(_)  => outcome.errors += 1,
                    }
                } else {
                    outcome.do_newer_revoke_repaired += 1;
                }
            }
            ReconcileOutcome::AnomalousD1RevokedDoActive => {
                // Never auto-repair. ADR-012 §Q1
                // discusses the rationale: D1
                // revoked + DO active means the
                // revoke write succeeded against
                // D1 but failed against the DO. An
                // automated repair (forcing the DO
                // to revoke too) would mask the
                // upstream bug. This stays
                // alert-only forever.
                outcome.anomalous_alert_only += 1;
            }
        }
    }

    Ok(outcome)
}

#[cfg(test)]
mod tests;
