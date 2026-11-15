//! End-to-end tests for the audit chain verifier
//! (`cesauth_core::audit::verifier`).
//!
//! The verifier itself lives in `cesauth-core` but takes
//! port-trait references; the only impls of those traits live
//! here. Co-locating the tests with the in-memory adapters
//! sidesteps the duplicate-trait-artifact issue Rust hits when
//! a crate dev-depends on another crate that depends on it.
//!
//! **RFC 184 round 2**: `verify_chain`/`verify_chain_full` return a
//! `VerificationOutcome` (`.stored` + `.refused_clean_walk`), not a
//! bare `AuditVerificationResult` — every existing assertion below
//! goes through `.stored` now, even where a case doesn't otherwise
//! care about the distinction this round added.

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
            actor:        None,
            client_id:    None,
            ip:           None,
            user_agent:   None,
            reason:       None,
            payload:      "{}",
            payload_hash: &h,
            created_at:   ts,
            request_id:    None,
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

    let outcome = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    let result = &outcome.stored;

    assert!(result.valid);
    assert!(result.first_mismatch_seq.is_none());
    assert_eq!(result.chain_length, 6, "1 genesis + 5 events");
    assert_eq!(result.rows_walked, 6);
    assert!(result.checkpoint_consistent.is_none(),
        "no prior checkpoint → checkpoint_consistent is None");
    assert!(outcome.refused_clean_walk.is_none());

    let cp = checkpoints.read_checkpoint().await.unwrap().expect("checkpoint written");
    assert_eq!(cp.last_verified_seq, 6);
    assert_eq!(cp.verified_at, NOW);
    let tail = repo.tail().await.unwrap().unwrap();
    assert_eq!(cp.chain_hash, tail.chain_hash);

    let last = checkpoints.read_last_result().await.unwrap().expect("result written");
    assert_eq!(&last, result);
}

#[tokio::test]
async fn cold_start_empty_chain_is_valid_and_writes_no_checkpoint() {
    let repo = InMemoryAuditEventRepository::new();
    let checkpoints = InMemoryAuditChainCheckpointStore::new();

    let outcome = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    assert!(outcome.stored.valid);
    assert_eq!(outcome.stored.chain_length, 0);
    assert_eq!(outcome.stored.rows_walked, 0);
    assert!(outcome.stored.first_mismatch_seq.is_none());

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
    assert_eq!(r1.stored.rows_walked, 4);

    let h = compute_payload_hash(b"{}");
    repo.append(&NewAuditEvent {
        id: "e3", ts: 200, kind: "k", subject: None, actor: None, client_id: None,
        ip: None, user_agent: None, reason: None,
        payload: "{}", payload_hash: &h, created_at: 200,
            request_id:    None,
    }).await.unwrap();
    repo.append(&NewAuditEvent {
        id: "e4", ts: 201, kind: "k", subject: None, actor: None, client_id: None,
        ip: None, user_agent: None, reason: None,
        payload: "{}", payload_hash: &h, created_at: 201,
            request_id:    None,
    }).await.unwrap();

    let r2 = verify_chain(&repo, &checkpoints, NOW + 1).await.unwrap();
    assert!(r2.stored.valid);
    assert_eq!(r2.stored.rows_walked, 2);
    assert_eq!(r2.stored.chain_length, 6);
    assert_eq!(r2.stored.checkpoint_consistent, Some(true),
        "prior checkpoint at seq=4 must still match the row at seq=4");

    let cp = checkpoints.read_checkpoint().await.unwrap().unwrap();
    assert_eq!(cp.last_verified_seq, 6);
}

#[tokio::test]
async fn third_run_after_no_new_events_is_idempotent() {
    let repo = build_chain(2).await;
    let checkpoints = InMemoryAuditChainCheckpointStore::new();

    let r1 = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    assert!(r1.stored.valid);
    let cp1 = checkpoints.read_checkpoint().await.unwrap().unwrap();

    let r2 = verify_chain(&repo, &checkpoints, NOW + 100).await.unwrap();
    assert!(r2.stored.valid);
    assert_eq!(r2.stored.rows_walked, 0,
        "no-new-rows incremental run should walk 0 rows");
    assert_eq!(r2.stored.chain_length, 3);

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

    let outcome = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    assert!(!outcome.stored.valid);
    assert_eq!(outcome.stored.first_mismatch_seq, Some(3),
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

    let outcome = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    assert!(!outcome.stored.valid);
    assert_eq!(outcome.stored.first_mismatch_seq, Some(4));
}

// =====================================================================
// Tamper detection — intermediate row removal
// =====================================================================

#[tokio::test]
async fn deleted_intermediate_row_is_detected() {
    let repo = build_chain(5).await;
    let checkpoints = InMemoryAuditChainCheckpointStore::new();

    repo.tamper_delete_seq(3);

    let outcome = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    assert!(!outcome.stored.valid);
    assert_eq!(outcome.stored.first_mismatch_seq, Some(4),
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
    assert!(r1.stored.valid);
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
            subject: None, actor: None, client_id: None, ip: None, user_agent: None, reason: None,
            payload: r#"{"forged":true}"#, payload_hash: &h,
            created_at: 1000 + i as i64,
            request_id: None,
        }).await.unwrap();
    }

    let r2 = verify_chain(&repo, &checkpoints, NOW + 1000).await.unwrap();
    assert!(!r2.stored.valid,
        "wholesale rewrite must be flagged invalid even though the new chain is internally consistent");
    assert_eq!(r2.stored.checkpoint_consistent, Some(false),
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

    let outcome = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    assert!(!outcome.stored.valid);
    assert_eq!(outcome.stored.first_mismatch_seq, Some(1));
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

    let outcome = verify_chain_full(&repo, &checkpoints, NOW + 1).await.unwrap();
    assert!(outcome.stored.valid);
    assert_eq!(outcome.stored.rows_walked, 4,
        "full re-verify must walk every row, not resume from the checkpoint");
    assert!(outcome.stored.checkpoint_consistent.is_none(),
        "full re-verify skips the cross-check");
}

// =====================================================================
// Sticky alarms (RFC 184 §3.1/§3.2) — an unacknowledged `valid: false`
// must survive a later run that would otherwise overwrite it with a
// clean result, and the checkpoint must not advance while it stands.
// =====================================================================

#[tokio::test]
async fn an_unacknowledged_alarm_survives_a_later_full_rewalk_that_looks_clean() {
    let repo = build_chain(4).await;
    let checkpoints = InMemoryAuditChainCheckpointStore::new();

    repo.tamper_set_payload(3, r#"{"injected":true}"#);
    let r1 = verify_chain_full(&repo, &checkpoints, NOW).await.unwrap();
    assert!(!r1.stored.valid);
    assert_eq!(r1.stored.first_mismatch_seq, Some(3));

    // The tamper is undone, restoring the row to what its
    // payload_hash actually attests — the next full re-walk alone
    // would now report a clean chain. This is the §2 witness: an
    // operator who presses "verify now" after a chain has been
    // made internally consistent again must not get a clean bill
    // of health for free.
    repo.tamper_set_payload(3, "{}");

    let r2 = verify_chain_full(&repo, &checkpoints, NOW + 1).await.unwrap();
    assert!(!r2.stored.valid,
        "the standing alarm must be returned, not the fresh clean-looking result");
    assert_eq!(r2.stored.first_mismatch_seq, Some(3), "the original finding, unchanged");
    assert!(!r2.stored.acknowledged);
    assert!(checkpoints.read_checkpoint().await.unwrap().is_none(),
        "the checkpoint must not advance while the alarm is unacknowledged");
}

#[tokio::test]
async fn the_cron_path_is_sticky_too() {
    // RFC 184 §3.1 says "any later run", not just the operator's
    // full re-walk — `verify_chain` (the daily cron) must obey the
    // same rule.
    let repo = build_chain(4).await;
    let checkpoints = InMemoryAuditChainCheckpointStore::new();

    repo.tamper_set_payload(3, r#"{"injected":true}"#);
    let r1 = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    assert!(!r1.stored.valid);
    // No checkpoint exists yet (the first run was invalid), so the
    // next incremental run also resumes from seq=0 — same shape as
    // the full-rewalk case above, reached through the cron entry
    // point instead.
    repo.tamper_set_payload(3, "{}");

    let r2 = verify_chain(&repo, &checkpoints, NOW + 1).await.unwrap();
    assert!(!r2.stored.valid, "cron must not silently clear a standing alarm either");
    assert_eq!(r2.stored.first_mismatch_seq, Some(3));
    assert!(checkpoints.read_checkpoint().await.unwrap().is_none());
}

#[tokio::test]
async fn a_still_invalid_later_run_updates_the_record_instead_of_being_blocked() {
    // The other half of the rule: stickiness must not make the
    // cron path go silent about a FRESH mismatch just because an
    // old one is unacknowledged — only a transition to `valid:
    // true` is refused.
    let repo = build_chain(4).await;
    let checkpoints = InMemoryAuditChainCheckpointStore::new();
    repo.tamper_set_payload(3, r#"{"injected":true}"#);

    let r1 = verify_chain_full(&repo, &checkpoints, NOW).await.unwrap();
    assert!(!r1.stored.valid);

    // Nothing is fixed; a later run finds the same tamper again and
    // must still overwrite the stored record (fresher `run_at`),
    // not just echo the first run untouched.
    let r2 = verify_chain_full(&repo, &checkpoints, NOW + 1).await.unwrap();
    assert!(!r2.stored.valid);
    assert_eq!(r2.stored.run_at, NOW + 1);
    assert!(r2.refused_clean_walk.is_none(),
        "a still-invalid run is an overwrite, not a refusal");
    let stored = checkpoints.read_last_result().await.unwrap().unwrap();
    assert_eq!(stored.run_at, NOW + 1,
        "the record must have moved, not been frozen at the first run's timestamp");
}

#[tokio::test]
async fn acknowledging_the_alarm_lets_a_later_clean_run_advance_again() {
    let repo = build_chain(4).await;
    let checkpoints = InMemoryAuditChainCheckpointStore::new();
    repo.tamper_set_payload(3, r#"{"injected":true}"#);

    let r1 = verify_chain_full(&repo, &checkpoints, NOW).await.unwrap();
    assert!(!r1.stored.valid);

    // Acknowledge, exactly as `POST .../audit/chain/acknowledge`
    // does: flip the stored result's `acknowledged` flag, nothing
    // else.
    let mut acked = checkpoints.read_last_result().await.unwrap().unwrap();
    acked.acknowledged = true;
    checkpoints.write_last_result(&acked).await.unwrap();

    repo.tamper_set_payload(3, "{}");
    let r2 = verify_chain_full(&repo, &checkpoints, NOW + 1).await.unwrap();
    assert!(r2.stored.valid, "an acknowledged alarm must not block a later clean run");
    assert!(!r2.stored.acknowledged,
        "a freshly-written clean result starts unacknowledged — there is nothing to acknowledge, but the field is not left stale from the old record either");
    assert!(checkpoints.read_checkpoint().await.unwrap().is_some(),
        "the checkpoint may advance once the standing alarm has been acknowledged");
}

// =====================================================================
// The refusal is itself evidence (RFC 184 round 2) — a refused clean
// walk must be distinguishable from "found tamper again", on both the
// return value (operator path has an actor) and the stored record
// (cron path has none).
// =====================================================================

#[tokio::test]
async fn a_refused_clean_walk_is_returned_distinctly_from_a_repeated_tamper_finding() {
    let repo = build_chain(4).await;
    let checkpoints = InMemoryAuditChainCheckpointStore::new();
    repo.tamper_set_payload(3, r#"{"injected":true}"#);

    let r1 = verify_chain_full(&repo, &checkpoints, NOW).await.unwrap();
    assert!(!r1.stored.valid);
    assert!(r1.refused_clean_walk.is_none(),
        "the very first run is a write, never a refusal");

    // Restore to clean — this press's own walk finds the chain
    // valid, but the write must be refused.
    repo.tamper_set_payload(3, "{}");
    let r2 = verify_chain_full(&repo, &checkpoints, NOW + 1).await.unwrap();

    assert!(!r2.stored.valid, "the stored alarm, unchanged");
    assert_eq!(r2.stored.first_mismatch_seq, Some(3));

    let fresh = r2.refused_clean_walk.expect(
        "a run whose own walk found the chain clean, refused, must carry that verdict",
    );
    assert!(fresh.valid, "the walk this press actually ran DID find the chain clean");
    assert_eq!(fresh.rows_walked, 5, "a full walk of a 5-row chain (genesis + 4)");
    assert!(fresh.first_mismatch_seq.is_none());

    // The two cases must not be confusable by inspecting the return
    // value alone: a repeated-tamper run (already covered by
    // `a_still_invalid_later_run_updates_the_record_instead_of_being_blocked`)
    // has `refused_clean_walk: None`; this one has `Some`, and the two
    // `fresh`/`stored` verdicts disagree on `valid` here, which is
    // exactly the wholesale-rewrite signature the round 2 handoff
    // names: a standing alarm plus an independently-clean full walk.
    assert_ne!(fresh.valid, r2.stored.valid);
}

#[tokio::test]
async fn a_refused_clean_walk_stamps_the_stored_record_for_actor_less_cron_runs() {
    // The cron path has no principal to hand a return value to — the
    // only durable trace it can leave is on the stored record itself.
    let repo = build_chain(4).await;
    let checkpoints = InMemoryAuditChainCheckpointStore::new();
    repo.tamper_set_payload(3, r#"{"injected":true}"#);

    let _ = verify_chain(&repo, &checkpoints, NOW).await.unwrap();
    repo.tamper_set_payload(3, "{}");
    let _ = verify_chain(&repo, &checkpoints, NOW + 1).await.unwrap();

    let stored = checkpoints.read_last_result().await.unwrap().unwrap();
    assert_eq!(stored.clean_walk_refused_at, Some(NOW + 1),
        "the stored record itself must carry when the refusal happened, \
         since the cron path has no audit-log actor to carry it instead");
    assert!(!stored.valid, "the alarm's own fields are untouched by the stamp");
    assert_eq!(stored.first_mismatch_seq, Some(3));
}

#[tokio::test]
async fn a_fresh_overwrite_clears_any_earlier_refusal_stamp() {
    // `clean_walk_refused_at` describes the PREVIOUS occupant of the
    // slot. Once acknowledged and genuinely re-verified clean, the new
    // record must not carry a stale refusal marker forward.
    let repo = build_chain(4).await;
    let checkpoints = InMemoryAuditChainCheckpointStore::new();
    repo.tamper_set_payload(3, r#"{"injected":true}"#);

    let _ = verify_chain_full(&repo, &checkpoints, NOW).await.unwrap();
    repo.tamper_set_payload(3, "{}");
    let _ = verify_chain_full(&repo, &checkpoints, NOW + 1).await.unwrap();
    assert_eq!(
        checkpoints.read_last_result().await.unwrap().unwrap().clean_walk_refused_at,
        Some(NOW + 1),
    );

    let mut acked = checkpoints.read_last_result().await.unwrap().unwrap();
    acked.acknowledged = true;
    checkpoints.write_last_result(&acked).await.unwrap();

    let r3 = verify_chain_full(&repo, &checkpoints, NOW + 2).await.unwrap();
    assert!(r3.stored.valid);
    assert_eq!(r3.stored.clean_walk_refused_at, None,
        "a fresh, non-refused write starts with no refusal stamp");
}

// =====================================================================
// RFC 187 G2 — the actor column, re-verified independently
// =====================================================================

#[tokio::test]
async fn g2_chain_with_pre_and_post_migration_actor_rows_verifies_valid() {
    // D2: actor is None for rows before the migration point (here: rows
    // appended with no actor, mirroring a pre-0021 row) and Some(...) for
    // rows after it. Neither shape should ever break the chain, since
    // compute_chain_hash/compute_payload_hash never read actor at all
    // (§9 assertion 2 of the handoff; also independently confirmed: the
    // field is new to NewAuditEvent/Event, not a changed signature of
    // either hash function).
    let repo = InMemoryAuditEventRepository::with_genesis();

    // "Pre-migration" row: no actor at all. The payload here is what
    // `backend::audit::Event::new(..).with_subject(..)` would actually
    // serialize to (checked for the `actor` field specifically — not
    // field-for-field — by
    // `event_with_no_actor_serializes_a_present_null_not_an_absent_key`
    // in `crates/backend/src/audit/tests.rs` — this test cannot reach
    // that type directly, adapter-test sits below backend in the dependency
    // graph) — a hand-built but realistic payload, not a placeholder.
    let pre_payload = r#"{"subject":"user-1","actor":null}"#;
    let h_pre = compute_payload_hash(pre_payload.as_bytes());
    repo.append(&NewAuditEvent {
        id: "pre-1", ts: 100, kind: "legacy_event",
        subject: Some("user-1"), actor: None,
        client_id: None, ip: None, user_agent: None, reason: None,
        payload: pre_payload, payload_hash: &h_pre, created_at: 100, request_id: None,
    }).await.unwrap();

    // "Post-migration" row: actor differs from subject, exactly the
    // shape G1's classification named (b) (admin acting on a different
    // user's behalf).
    let post_payload = r#"{"subject":"user-2","actor":"admin-1"}"#;
    let h_post = compute_payload_hash(post_payload.as_bytes());
    repo.append(&NewAuditEvent {
        id: "post-1", ts: 200, kind: "deletion_executed",
        subject: Some("user-2"), actor: Some("admin-1"),
        client_id: None, ip: None, user_agent: None, reason: None,
        payload: post_payload, payload_hash: &h_post, created_at: 200, request_id: None,
    }).await.unwrap();

    let checkpoints = InMemoryAuditChainCheckpointStore::new();
    let outcome = verify_chain_full(&repo, &checkpoints, NOW).await.unwrap();
    assert!(outcome.stored.valid, "actor column must not break chain verification");
    assert_eq!(outcome.stored.chain_length, 3, "genesis + 2 appended rows");
    assert_eq!(outcome.stored.rows_walked, 3);
    assert!(outcome.stored.first_mismatch_seq.is_none());

    // And the actor really did ride into the payload (D1), not just the
    // column — confirmed by reading the stored row back and parsing its
    // own payload JSON, not by trusting the field exists on the Rust type.
    let rows = repo.rows();
    let post = rows.iter().find(|r| r.id == "post-1").unwrap();
    assert_eq!(post.actor.as_deref(), Some("admin-1"), "column carries it");
    let payload_json: serde_json::Value = serde_json::from_str(&post.payload).unwrap();
    assert_eq!(payload_json["actor"], "admin-1", "payload carries it too (D1)");
}

#[tokio::test]
async fn g2_tampering_the_actor_column_alone_is_not_caught_by_chain_verification() {
    // **This is the required pair's second half, and it does NOT prove
    // what the handoff's §10 says it proves.** Read `verify_chain`'s own
    // module doc (`crates/core/src/audit/verifier.rs:7-30`): verification
    // checks exactly three things — payload_hash integrity, chain_hash
    // integrity, and chain linkage (previous_hash). None of the three
    // reads any indexed column (actor, subject, client_id, ...) and
    // compares it against the payload's own copy of that field. So
    // editing ONLY the `actor` column, leaving `payload`/`payload_hash`/
    // `chain_hash` untouched, changes nothing any of those three checks
    // look at — `valid` stays `true`.
    //
    // This is not new to `actor`: the SAME gap exists for `subject`,
    // `client_id`, `ip`, `user_agent`, and `reason` today, for every row
    // in the table, and predates this cut. RFC 187's own text ("the
    // actor becomes tamper-evident for free — provided you put it in
    // the payload") reads as a claim about the automated verifier; what
    // D1 actually buys is narrower: a HUMAN comparing the displayed
    // column against the archived `payload` blob (via `wrangler d1
    // execute` or an export) CAN notice the mismatch, because the
    // evidence is there to compare against. No code path does that
    // comparison automatically today.
    //
    // Per the handoff's own instruction ("if the chain breaks, stop and
    // report — that refutes the RFC's design and is worth more than an
    // implementation"): the chain does not break (see the companion
    // test above), so this is not that stop condition. But the
    // specific claim in §10 ("fails verification... the proof D1
    // bought") is reported here as not reproducing, rather than this
    // test being written to silently assert the opposite of what it
    // measures.
    let repo = InMemoryAuditEventRepository::with_genesis();
    let payload = r#"{"subject":"user-2","actor":"admin-1"}"#;
    let h = compute_payload_hash(payload.as_bytes());
    repo.append(&NewAuditEvent {
        id: "post-1", ts: 200, kind: "deletion_executed",
        subject: Some("user-2"), actor: Some("admin-1"),
        client_id: None, ip: None, user_agent: None, reason: None,
        payload, payload_hash: &h, created_at: 200, request_id: None,
    }).await.unwrap();

    repo.tamper_set_actor(2, Some("admin-2".to_owned()));

    let rows = repo.rows();
    let row = rows.iter().find(|r| r.seq == 2).unwrap();
    let payload_json: serde_json::Value = serde_json::from_str(&row.payload).unwrap();
    assert_eq!(row.actor.as_deref(), Some("admin-2"), "the column now disagrees with the payload");
    assert_eq!(payload_json["actor"], "admin-1", "the payload still says what was originally written");

    let checkpoints = InMemoryAuditChainCheckpointStore::new();
    let outcome = verify_chain_full(&repo, &checkpoints, NOW).await.unwrap();
    assert!(
        outcome.stored.valid,
        "documents the actual behaviour: a column-only tamper does not fail \
         chain verification today, contrary to the handoff's §10 claim — see \
         this test's own comment and the G2 finding in the implementation report",
    );
}
