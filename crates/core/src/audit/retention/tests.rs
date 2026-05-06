//! Unit tests for `audit::retention::run_retention_pass`.

use super::*;
use crate::ports::audit::{
    AuditEventRepository, AuditEventRow, AuditSearch, NewAuditEvent,
};
use crate::ports::audit_chain::{
    AuditChainCheckpoint, AuditChainCheckpointStore,
};
use crate::ports::{PortError, PortResult};
use std::cell::RefCell;

// =====================================================================
// Stubs
// =====================================================================

#[derive(Default)]
struct StubRepo {
    rows: RefCell<Vec<AuditEventRow>>,
    delete_failure: RefCell<bool>,
}

impl StubRepo {
    fn install(&self, seq: i64, ts: i64, kind: &str) {
        self.rows.borrow_mut().push(AuditEventRow {
            seq, ts,
            id:            format!("ev_{seq}"),
            kind:          kind.to_owned(),
            subject:       None,
            client_id:     None,
            ip:            None,
            user_agent:    None,
            reason:        None,
            payload:       "{}".into(),
            payload_hash:  "ph".into(),
            previous_hash: "00".into(),
            chain_hash:    "ch".into(),
            created_at:    ts,
        });
    }

    fn count(&self) -> usize { self.rows.borrow().len() }

    fn count_kind(&self, k: &str) -> usize {
        self.rows.borrow().iter().filter(|r| r.kind == k).count()
    }
}

impl AuditEventRepository for StubRepo {
    async fn append(&self, _ev: &NewAuditEvent<'_>) -> PortResult<AuditEventRow> {
        unimplemented!("retention must not call append")
    }
    async fn tail(&self) -> PortResult<Option<AuditEventRow>> {
        unimplemented!("retention must not call tail")
    }
    async fn search(&self, _q: &AuditSearch) -> PortResult<Vec<AuditEventRow>> {
        unimplemented!("retention must not call search")
    }
    async fn fetch_after_seq(&self, _from_seq: i64, _limit: u32) -> PortResult<Vec<AuditEventRow>> {
        unimplemented!("retention must not call fetch_after_seq")
    }

    async fn delete_below_seq(
        &self,
        floor_seq:   i64,
        older_than:  i64,
        kind_filter: AuditRetentionKindFilter,
    ) -> PortResult<u32> {
        if *self.delete_failure.borrow() {
            return Err(PortError::Unavailable);
        }
        use AuditRetentionKindFilter as F;
        let mut rows = self.rows.borrow_mut();
        let before = rows.len();
        rows.retain(|r| {
            // Stub matches the production impls'
            // genesis-protection invariant.
            if r.seq <= 1 {
                return true;
            }
            let kind_match = match &kind_filter {
                F::OnlyKinds(ks)    => ks.iter().any(|k| k == &r.kind),
                F::ExcludeKinds(ks) => !ks.iter().any(|k| k == &r.kind),
            };
            !(r.seq < floor_seq && r.ts < older_than && kind_match)
        });
        Ok((before - rows.len()) as u32)
    }
}

#[derive(Default)]
struct StubCheckpoints {
    cp: RefCell<Option<AuditChainCheckpoint>>,
    read_failure: RefCell<bool>,
}

impl StubCheckpoints {
    fn install(&self, last_verified_seq: i64) {
        *self.cp.borrow_mut() = Some(AuditChainCheckpoint {
            last_verified_seq,
            chain_hash:        "verified".into(),
            verified_at:       100,
        });
    }
}

impl AuditChainCheckpointStore for StubCheckpoints {
    async fn read_checkpoint(&self) -> PortResult<Option<AuditChainCheckpoint>> {
        if *self.read_failure.borrow() {
            return Err(PortError::Unavailable);
        }
        Ok(self.cp.borrow().clone())
    }
    async fn write_checkpoint(&self, _: &AuditChainCheckpoint) -> PortResult<()> {
        unimplemented!("retention must not write checkpoint")
    }
    async fn read_last_result(
        &self,
    ) -> PortResult<Option<crate::ports::audit_chain::AuditVerificationResult>> {
        Ok(None)
    }
    async fn write_last_result(
        &self,
        _: &crate::ports::audit_chain::AuditVerificationResult,
    ) -> PortResult<()> {
        unimplemented!("retention must not write last_result")
    }
}

// =====================================================================
// Tests
// =====================================================================

const NOW: i64 = 1_700_000_000;
const DAY: i64 = SECS_PER_DAY;

#[tokio::test]
async fn no_checkpoint_skips_pass() {
    // Pin: pruning without a chain anchor opens an
    // integrity hole; refuse to run.
    let repo = StubRepo::default();
    repo.install(2, NOW - 400 * DAY, "TokenIntrospected");

    let cps  = StubCheckpoints::default();
    // No checkpoint installed.

    let outcome = run_retention_pass(
        &repo, &cps, RetentionConfig::default(), NOW,
    ).await.unwrap();

    assert!(outcome.skipped_no_checkpoint);
    assert_eq!(outcome.deleted_token_introspected, 0);
    assert_eq!(outcome.deleted_global,            0);
    // Row untouched.
    assert_eq!(repo.count(), 1);
}

#[tokio::test]
async fn checkpoint_present_but_below_safety_margin_is_no_op() {
    // Checkpoint at seq=50, safety margin = 100, so
    // floor_seq = max(50-100, 2) = 2. Only the genesis
    // row is below floor; nothing else gets pruned.
    let repo = StubRepo::default();
    repo.install(2,  NOW - 400 * DAY, "TokenIntrospected");
    repo.install(10, NOW - 400 * DAY, "TokenIntrospected");
    repo.install(50, NOW - 400 * DAY, "TokenIntrospected");

    let cps = StubCheckpoints::default();
    cps.install(50);

    let outcome = run_retention_pass(
        &repo, &cps, RetentionConfig::default(), NOW,
    ).await.unwrap();

    assert_eq!(outcome.floor_seq, 2,
        "floor_seq must be max(checkpoint - margin, 2) — never below 2");
    assert_eq!(outcome.deleted_token_introspected, 0);
    assert_eq!(outcome.deleted_global,            0);
    assert_eq!(repo.count(), 3);
}

#[tokio::test]
async fn token_introspected_pass_prunes_old_rows_only() {
    // Setup: 3 token_introspected rows with varying age,
    // 1 session_revoked_by_user row. Checkpoint
    // generously above all. Default config: 30d for
    // token_introspected, 365d global.
    let repo = StubRepo::default();
    repo.install(100, NOW - 35 * DAY,  "TokenIntrospected");      // older than 30d → DELETE
    repo.install(200, NOW - 31 * DAY,  "TokenIntrospected");      // older than 30d → DELETE
    repo.install(300, NOW - 25 * DAY,  "TokenIntrospected");      // newer than 30d → KEEP
    repo.install(400, NOW - 100 * DAY, "SessionRevokedByUser");   // older than 30d but global=365d → KEEP

    let cps = StubCheckpoints::default();
    cps.install(10_000);   // floor_seq = 9_900 → all rows below it

    let outcome = run_retention_pass(
        &repo, &cps, RetentionConfig::default(), NOW,
    ).await.unwrap();

    assert_eq!(outcome.deleted_token_introspected, 2);
    assert_eq!(outcome.deleted_global,            0);
    assert_eq!(repo.count(),                      2);
    assert_eq!(repo.count_kind("TokenIntrospected"), 1);
    assert_eq!(repo.count_kind("SessionRevokedByUser"), 1);
}

#[tokio::test]
async fn global_pass_prunes_only_above_global_window() {
    // Setup: a session-revoke row at age 400d (> 365d
    // global) and another at 100d. Global pass deletes
    // the 400d one; per-kind doesn't apply.
    let repo = StubRepo::default();
    repo.install(100, NOW - 400 * DAY, "SessionRevokedByUser");   // > 365d → DELETE
    repo.install(200, NOW - 100 * DAY, "SessionRevokedByUser");   // < 365d → KEEP

    let cps = StubCheckpoints::default();
    cps.install(10_000);

    let outcome = run_retention_pass(
        &repo, &cps, RetentionConfig::default(), NOW,
    ).await.unwrap();

    assert_eq!(outcome.deleted_token_introspected, 0);
    assert_eq!(outcome.deleted_global,            1);
    assert_eq!(repo.count(),                      1);
}

#[tokio::test]
async fn global_pass_excludes_token_introspected_when_per_kind_active() {
    // Critical correctness pin: when the per-kind
    // pass is active (token_introspected_days < global_days),
    // the global pass must NOT also delete
    // TokenIntrospected rows — that would double-prune
    // the recent ones.
    //
    // Setup: a 100d-old TokenIntrospected row.
    // Per-kind: 30d window → row is 100 days old, OLDER than 30d, so per-kind would delete it.
    // Global:  365d window → 100d row is younger than 365d, so global wouldn't delete it ANYWAY.
    //
    // We make this tighter by setting the row to be
    // OLDER than 365d too: per-kind would delete it
    // (older than 30), global would also delete it
    // (older than 365). The exclude-list ensures only
    // ONE pass deletes it (specifically the per-kind),
    // not BOTH. With both deletions, the count
    // arithmetic would over-report to the operator.
    let repo = StubRepo::default();
    repo.install(100, NOW - 400 * DAY, "TokenIntrospected");

    let cps = StubCheckpoints::default();
    cps.install(10_000);

    let outcome = run_retention_pass(
        &repo, &cps, RetentionConfig::default(), NOW,
    ).await.unwrap();

    assert_eq!(outcome.deleted_token_introspected, 1);
    assert_eq!(outcome.deleted_global,            0,
        "global pass must EXCLUDE TokenIntrospected when per-kind is active");
    assert_eq!(repo.count(), 0);
}

#[tokio::test]
async fn global_includes_token_introspected_when_per_kind_disabled() {
    // When operator sets token_introspected_days=0
    // (per-kind disabled), the global pass should
    // cover TokenIntrospected too. This lets
    // operators choose "I want one uniform window
    // for everything" without leaving a gap.
    let repo = StubRepo::default();
    repo.install(100, NOW - 400 * DAY, "TokenIntrospected");

    let cps = StubCheckpoints::default();
    cps.install(10_000);

    let cfg = RetentionConfig {
        global_days:             365,
        token_introspected_days: 0,
    };
    let outcome = run_retention_pass(&repo, &cps, cfg, NOW).await.unwrap();

    assert_eq!(outcome.deleted_token_introspected, 0);
    assert_eq!(outcome.deleted_global,            1);
    assert_eq!(repo.count(), 0);
}

#[tokio::test]
async fn global_includes_token_introspected_when_per_kind_geq_global() {
    // Edge case: operator sets per-kind larger than
    // global. The per-kind pass would be a no-op
    // (its window is bigger, so it deletes a subset
    // of what global would delete). Treat this as
    // "operator wants global to handle TI too" —
    // skip per-kind and let global cover it.
    let repo = StubRepo::default();
    repo.install(100, NOW - 400 * DAY, "TokenIntrospected");

    let cps = StubCheckpoints::default();
    cps.install(10_000);

    let cfg = RetentionConfig {
        global_days:             30,
        token_introspected_days: 90,   // per-kind > global
    };
    let outcome = run_retention_pass(&repo, &cps, cfg, NOW).await.unwrap();

    // Per-kind skipped; global handles it.
    assert_eq!(outcome.deleted_token_introspected, 0);
    assert_eq!(outcome.deleted_global,            1);
    assert_eq!(repo.count(), 0);
}

#[tokio::test]
async fn global_zero_disables_global_pass() {
    // Operator sets global_days=0 → global pass skipped.
    // Per-kind still runs.
    let repo = StubRepo::default();
    repo.install(100, NOW - 400 * DAY, "TokenIntrospected");
    repo.install(200, NOW - 400 * DAY, "SessionRevokedByUser");

    let cps = StubCheckpoints::default();
    cps.install(10_000);

    let cfg = RetentionConfig {
        global_days:             0,
        token_introspected_days: 30,
    };
    let outcome = run_retention_pass(&repo, &cps, cfg, NOW).await.unwrap();

    assert_eq!(outcome.deleted_token_introspected, 1);
    assert_eq!(outcome.deleted_global,            0);
    assert_eq!(repo.count(),                      1);
    assert_eq!(repo.count_kind("SessionRevokedByUser"), 1,
        "global=0 must leave non-TokenIntrospected rows untouched");
}

#[tokio::test]
async fn floor_seq_protects_recent_rows_even_when_old_by_ts() {
    // The whole point of the safety margin: a row's
    // timestamp can claim it's old (e.g., backdated
    // ts injected via SQL clock skew or a deliberate
    // attacker), but if its seq is above floor_seq it
    // must NOT be pruned. The chain-walker needs it.
    //
    // Setup: row at seq=9_950 (above floor=9_900)
    // with ts claiming it's 400 days old. Default
    // config would otherwise delete it.
    let repo = StubRepo::default();
    repo.install(9_950, NOW - 400 * DAY, "TokenIntrospected");

    let cps = StubCheckpoints::default();
    cps.install(10_000);   // floor_seq = 10_000 - 100 = 9_900

    let outcome = run_retention_pass(
        &repo, &cps, RetentionConfig::default(), NOW,
    ).await.unwrap();

    assert_eq!(outcome.deleted_token_introspected, 0,
        "row above floor_seq must be preserved regardless of ts");
    assert_eq!(repo.count(), 1);
}

#[tokio::test]
async fn checkpoint_at_genesis_keeps_genesis_safe() {
    // Brand-new deployment: only the genesis row
    // exists, checkpoint at seq=1 (genesis). floor_seq
    // = max(1 - 100, 2) = 2. Genesis is seq=1, which
    // is < 2, so technically eligible — but our
    // explicit "max(_, 2)" floor and the "row's seq <
    // floor" gate (strict inequality) protect it.
    //
    // Pin: even with an aggressive 0-day retention
    // window, the genesis row at seq=1 must survive
    // because seq=1 is NOT < floor_seq=2.
    let repo = StubRepo::default();
    repo.install(1, NOW - 1000 * DAY, "ChainGenesis");

    let cps = StubCheckpoints::default();
    cps.install(1);

    let cfg = RetentionConfig {
        global_days:             1,    // very aggressive
        token_introspected_days: 0,
    };
    let outcome = run_retention_pass(&repo, &cps, cfg, NOW).await.unwrap();

    assert_eq!(outcome.floor_seq, 2);
    assert_eq!(outcome.deleted_global, 0,
        "genesis row at seq=1 must never be pruned");
    assert_eq!(repo.count(), 1);
}

#[tokio::test]
async fn delete_failure_propagates_as_internal() {
    let repo = StubRepo::default();
    repo.install(100, NOW - 400 * DAY, "TokenIntrospected");
    *repo.delete_failure.borrow_mut() = true;

    let cps = StubCheckpoints::default();
    cps.install(10_000);

    let result = run_retention_pass(
        &repo, &cps, RetentionConfig::default(), NOW,
    ).await;

    assert!(matches!(result, Err(crate::error::CoreError::Internal)));
}

#[tokio::test]
async fn checkpoint_read_failure_propagates_as_internal() {
    let repo = StubRepo::default();
    let cps = StubCheckpoints::default();
    *cps.read_failure.borrow_mut() = true;

    let result = run_retention_pass(
        &repo, &cps, RetentionConfig::default(), NOW,
    ).await;

    assert!(matches!(result, Err(crate::error::CoreError::Internal)));
}

#[tokio::test]
async fn idempotent_second_call_is_zero_count() {
    // Run twice; second call has nothing left to prune.
    let repo = StubRepo::default();
    repo.install(100, NOW - 400 * DAY, "TokenIntrospected");

    let cps = StubCheckpoints::default();
    cps.install(10_000);

    let first = run_retention_pass(
        &repo, &cps, RetentionConfig::default(), NOW,
    ).await.unwrap();
    assert_eq!(first.deleted_token_introspected, 1);

    let second = run_retention_pass(
        &repo, &cps, RetentionConfig::default(), NOW,
    ).await.unwrap();
    assert_eq!(second.deleted_token_introspected, 0);
    assert_eq!(second.deleted_global,            0);
}

// =====================================================================
// Wire shape pins
// =====================================================================

#[test]
fn default_config_matches_published_defaults() {
    // Surfaced in the CHANGELOG and ADR-014 §Q3
    // resolution paragraph; pin so a future bump
    // doesn't silently change them.
    let cfg = RetentionConfig::default();
    assert_eq!(cfg.global_days,             365);
    assert_eq!(cfg.token_introspected_days,  30);
}

#[test]
fn safety_margin_is_one_hundred() {
    // Pin: ADR-014 §Q3 resolution paragraph cites
    // 100 rows. If the constant changes, the doc
    // must change with it.
    assert_eq!(CHECKPOINT_SAFETY_MARGIN, 100);
}

#[test]
fn kind_token_introspected_constant_matches_event_kind() {
    // The constant has to match the EventKind serde
    // representation (PascalCase per cesauth's audit
    // contract). If EventKind serde changes, this
    // test catches the drift.
    assert_eq!(KIND_TOKEN_INTROSPECTED, "TokenIntrospected");
}
