//! End-to-end tests for the audit chain verifier
//! (`cesauth_core::audit::verifier`).
//!
//! The verifier itself lives in `cesauth-core` but takes
//! port-trait references; the only impls of those traits live
//! here. Co-locating the tests with the in-memory adapters
//! sidesteps the duplicate-trait-artifact issue Rust hits when
//! a crate dev-depends on another crate that depends on it.

use super::*;

use cesauth_core::audit::chain::compute_payload_hash;
use cesauth_core::audit::verifier::{verify_chain, verify_chain_full};
use cesauth_core::ports::audit::{AuditEventRepository, NewAuditEvent};

use crate::audit::InMemoryAuditEventRepository;

const NOW: i64 = 1_700_000_000;

/// Append `n` valid events to a fresh chain (with genesis).
async fn build_chain(n: usize) -> InMemoryAuditEventRepository {
    let repo = InMemoryAuditEventRepository::with_genesis();
    let h = compute_payload_hash(b"{}");
    for i in 0..n {
        let id  = format!("e{i}");
        let ts  = 100 + i as i64;
        repo.append(&NewAuditEvent {
            id:           &id,
            ts,
            kind:         "test_event",
            subject:      None,
            client_id:    None,
            ip:           None,
            user_agent:   None,
            reason:       None,
            payload:      "{}",
            payload_hash: &h,
            created_at:   ts,
        }).await.unwrap();
    }
    repo
}

// =====================================================================
// Cold start (no prior checkpoint)
// =====================================================================

#[tokio::test]
async fn cold_start_walks_full_chain_writes_checkpoint_and_result() {
    let repo = build_chain(5).await;
    let checkpoints = InMemoryAuditChainCheckpointStore::new();

    let result = verify_chain(&repo, &checkpoints, NOW).await.unwrap();

    assert!(result.valid);
    assert!(result.first_mismatch_seq.is_none());
    assert_eq!(result.chain_length, 6, "1 genesis + 5 events");
    assert_eq!(result.rows_walked, 6);
    assert!(result.checkpoint_consistent.is_none(),
        "no prior checkpoint → checkpoint_consistent is None");

    let cp = checkpoints.read_checkpoint().await.unwrap().expect("checkpoint written");
    assert_eq!(cp.last_verified_seq, 6);
    assert_eq!(cp.verified_at, NOW);
    let tail = repo.tail().await.unwrap().unwrap();
    assert_eq!(cp.chain_hash, tail.chain_hash);

    let last = checkpoints.read_last_result().await.unwrap().expect("result written");
    assert_eq!(last, result);
}

#[tokio::test]
async fn cold_start_empty_chain_is_valid_and_writes_no_checkpoint() {
    let repo = InMemoryAuditEventRepository::new();
    let checkpoints = InMemoryAuditChainCheckpointStore::new();

    let result = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    assert!(result.valid);
    assert_eq!(result.chain_length, 0);
    assert_eq!(result.rows_walked, 0);
    assert!(result.first_mismatch_seq.is_none());

    assert!(checkpoints.read_checkpoint().await.unwrap().is_none(),
        "empty chain should not produce a checkpoint");
    assert!(checkpoints.read_last_result().await.unwrap().is_some());
}

// =====================================================================
// Incremental verification
// =====================================================================

#[tokio::test]
async fn second_run_resumes_from_checkpoint_and_walks_only_new_rows() {
    let repo = build_chain(3).await;
    let checkpoints = InMemoryAuditChainCheckpointStore::new();

    let r1 = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    assert_eq!(r1.rows_walked, 4);

    let h = compute_payload_hash(b"{}");
    repo.append(&NewAuditEvent {
        id: "e3", ts: 200, kind: "k", subject: None, client_id: None,
        ip: None, user_agent: None, reason: None,
        payload: "{}", payload_hash: &h, created_at: 200,
    }).await.unwrap();
    repo.append(&NewAuditEvent {
        id: "e4", ts: 201, kind: "k", subject: None, client_id: None,
        ip: None, user_agent: None, reason: None,
        payload: "{}", payload_hash: &h, created_at: 201,
    }).await.unwrap();

    let r2 = verify_chain(&repo, &checkpoints, NOW + 1).await.unwrap();
    assert!(r2.valid);
    assert_eq!(r2.rows_walked, 2);
    assert_eq!(r2.chain_length, 6);
    assert_eq!(r2.checkpoint_consistent, Some(true),
        "prior checkpoint at seq=4 must still match the row at seq=4");

    let cp = checkpoints.read_checkpoint().await.unwrap().unwrap();
    assert_eq!(cp.last_verified_seq, 6);
}

#[tokio::test]
async fn third_run_after_no_new_events_is_idempotent() {
    let repo = build_chain(2).await;
    let checkpoints = InMemoryAuditChainCheckpointStore::new();

    let r1 = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    assert!(r1.valid);
    let cp1 = checkpoints.read_checkpoint().await.unwrap().unwrap();

    let r2 = verify_chain(&repo, &checkpoints, NOW + 100).await.unwrap();
    assert!(r2.valid);
    assert_eq!(r2.rows_walked, 0,
        "no-new-rows incremental run should walk 0 rows");
    assert_eq!(r2.chain_length, 3);

    let cp2 = checkpoints.read_checkpoint().await.unwrap().unwrap();
    assert_eq!(cp2.last_verified_seq, cp1.last_verified_seq);
}

// =====================================================================
// Tamper detection — payload edit
// =====================================================================

#[tokio::test]
async fn payload_edit_is_detected_at_the_edited_row() {
    let repo = build_chain(5).await;
    let checkpoints = InMemoryAuditChainCheckpointStore::new();

    repo.tamper_set_payload(3, r#"{"injected":true}"#);

    let result = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    assert!(!result.valid);
    assert_eq!(result.first_mismatch_seq, Some(3),
        "verifier must locate the tamper at the edited seq");
    assert!(checkpoints.read_checkpoint().await.unwrap().is_none(),
        "tamper detection must NOT advance the checkpoint");
}

// =====================================================================
// Tamper detection — chain_hash edit
// =====================================================================

#[tokio::test]
async fn chain_hash_edit_is_detected() {
    let repo = build_chain(4).await;
    let checkpoints = InMemoryAuditChainCheckpointStore::new();

    repo.tamper_set_chain_hash(4, "0".repeat(64));

    let result = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    assert!(!result.valid);
    assert_eq!(result.first_mismatch_seq, Some(4));
}

// =====================================================================
// Tamper detection — intermediate row removal
// =====================================================================

#[tokio::test]
async fn deleted_intermediate_row_is_detected() {
    let repo = build_chain(5).await;
    let checkpoints = InMemoryAuditChainCheckpointStore::new();

    repo.tamper_delete_seq(3);

    let result = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    assert!(!result.valid);
    assert_eq!(result.first_mismatch_seq, Some(4),
        "deletion at seq=3 surfaces as a previous_hash mismatch at seq=4");
}

// =====================================================================
// Wholesale-rewrite detection (the Phase 2 raison d'être)
// =====================================================================

#[tokio::test]
async fn wholesale_rewrite_is_detected_via_checkpoint_cross_check() {
    let repo = build_chain(4).await;
    let checkpoints = InMemoryAuditChainCheckpointStore::new();

    let r1 = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    assert!(r1.valid);
    let cp1 = checkpoints.read_checkpoint().await.unwrap().unwrap();
    assert_eq!(cp1.last_verified_seq, 5);

    // Attacker wholesale-rewrites: chain re-emerges as a
    // different (but internally-consistent) chain.
    repo.tamper_clear_all();
    let h = compute_payload_hash(br#"{"forged":true}"#);
    for i in 0..4 {
        let id = format!("forged_{i}");
        repo.append(&NewAuditEvent {
            id: &id, ts: 1000 + i as i64,
            kind: "forged_event",
            subject: None, client_id: None, ip: None, user_agent: None, reason: None,
            payload: r#"{"forged":true}"#, payload_hash: &h,
            created_at: 1000 + i as i64,
        }).await.unwrap();
    }

    let r2 = verify_chain(&repo, &checkpoints, NOW + 1000).await.unwrap();
    assert!(!r2.valid,
        "wholesale rewrite must be flagged invalid even though the new chain is internally consistent");
    assert_eq!(r2.checkpoint_consistent, Some(false),
        "checkpoint cross-check must be the alarm bell here");
}

// =====================================================================
// Genesis-row sentinel handling
// =====================================================================

#[tokio::test]
async fn tampered_genesis_row_is_detected() {
    let repo = InMemoryAuditEventRepository::with_genesis();
    let checkpoints = InMemoryAuditChainCheckpointStore::new();

    repo.tamper_set_previous_hash(1, "abcd".repeat(16));

    let result = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    assert!(!result.valid);
    assert_eq!(result.first_mismatch_seq, Some(1));
}

// =====================================================================
// Full re-verification (operator-triggered)
// =====================================================================

#[tokio::test]
async fn verify_chain_full_walks_from_genesis_regardless_of_checkpoint() {
    let repo = build_chain(3).await;
    let checkpoints = InMemoryAuditChainCheckpointStore::new();

    let _ = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    let cp = checkpoints.read_checkpoint().await.unwrap().unwrap();
    assert_eq!(cp.last_verified_seq, 4);

    let result = verify_chain_full(&repo, &checkpoints, NOW + 1).await.unwrap();
    assert!(result.valid);
    assert_eq!(result.rows_walked, 4,
        "full re-verify must walk every row, not resume from the checkpoint");
    assert!(result.checkpoint_consistent.is_none(),
        "full re-verify skips the cross-check");
}
