//! RFC 118 — one named example test per invariant, so a failure names the
//! invariant before anyone reads a shrunk 60-operation sequence. Each is
//! written from the invariant's statement in the module doc, not from a store.

use super::*;
use crate::ports::store::LifetimeExpiry;
use crate::types::{ClientId, FamilyId, UserId};

fn jti(s: &str) -> Jti { Jti::from_storage(s) }

fn init(first: &str, now: i64) -> FamilyInit {
    FamilyInit {
        family_id: FamilyId::from_storage("fam"),
        user_id:   UserId::from_storage("u"),
        client_id: ClientId::from_storage("c"),
        scopes:    vec!["openid".to_owned()],
        first_jti: jti(first),
        now_unix:  now,
        auth_time: 77,
    }
}

/// A policy far from any deadline used unless a test is about expiry.
fn wide() -> RefreshLifetime { RefreshLifetime::new(1_000_000, 500_000).unwrap() }

fn rot(m: &mut FamilyModel, presented: &str, new: &str, now: i64) -> ModelOutcome {
    m.apply(&Op::Rotate { presented: jti(presented), new: jti(new), lifetime: wide() }, now)
}

fn rot_with(m: &mut FamilyModel, presented: &str, new: &str, now: i64, p: RefreshLifetime) -> ModelOutcome {
    m.apply(&Op::Rotate { presented: jti(presented), new: jti(new), lifetime: p }, now)
}

/// A family that has been rotated `n` times: jtis `j0 -> j1 -> ... -> jn`.
fn rotated(n: usize) -> FamilyModel {
    let mut m = FamilyModel::new(&init("j0", 100));
    for i in 0..n {
        let out = rot(&mut m, &format!("j{i}"), &format!("j{}", i + 1), 100 + i as i64 + 1);
        assert!(matches!(out, ModelOutcome::Rotated { .. }), "setup rotation {i}: {out:?}");
    }
    m
}

// ── 1. Single live jti ──────────────────────────────────────────────────────

#[test]
fn inv1_only_the_most_recently_issued_jti_is_accepted() {
    let mut m = FamilyModel::new(&init("j0", 100));
    assert_eq!(rot(&mut m, "j0", "j1", 101), ModelOutcome::Rotated { new_current_jti: jti("j1") });
    assert_eq!(m.state().current_jti, jti("j1"));
    // The new current is accepted; nothing else is.
    assert_eq!(rot(&mut m, "j1", "j2", 102), ModelOutcome::Rotated { new_current_jti: jti("j2") });
    assert_eq!(m.state().current_jti, jti("j2"));
}

// ── 2. Rotation kills the predecessor ───────────────────────────────────────

#[test]
fn inv2_presenting_the_replaced_jti_is_reuse_and_revokes_the_family() {
    let mut m = FamilyModel::new(&init("j0", 100));
    rot(&mut m, "j0", "j1", 101);
    assert_eq!(rot(&mut m, "j0", "j2", 105),
        ModelOutcome::ReusedAndRevoked { reused_jti: jti("j0"), was_retired: true });
    assert_eq!(m.state().revoked_at, Some(105));
    assert_eq!(m.state().current_jti, jti("j1"), "the refused rotation must not advance the family");
}

// ── 3. Revocation is absorbing ──────────────────────────────────────────────

#[test]
fn inv3_after_an_explicit_revoke_every_rotate_is_already_revoked() {
    let mut m = rotated(2);
    assert_eq!(m.apply(&Op::Revoke, 200), ModelOutcome::Revoked);
    let before = m.state().clone();
    for (p, n) in [("j2", "x1"), ("j0", "x2"), ("never-issued", "x3")] {
        assert_eq!(rot(&mut m, p, n, 201), ModelOutcome::AlreadyRevoked, "presenting {p}");
    }
    let after = m.state();
    assert_eq!((after.current_jti.clone(), after.retired_jtis.clone(), after.revoked_at, after.reused_jti.clone()),
               (before.current_jti, before.retired_jtis, before.revoked_at, before.reused_jti),
               "a revoked family must not change again");
}

#[test]
fn inv3_after_a_reuse_revocation_every_rotate_is_already_revoked_and_forensics_are_kept() {
    let mut m = rotated(2);
    assert!(matches!(rot(&mut m, "j0", "x1", 300), ModelOutcome::ReusedAndRevoked { .. }));
    let first = m.state().clone();
    // The current jti, another retired one, an unknown one: all absorbed, none
    // overwrites the first reuse.
    for (p, n) in [("j2", "x2"), ("j1", "x3"), ("never-issued", "x4")] {
        assert_eq!(rot(&mut m, p, n, 400), ModelOutcome::AlreadyRevoked);
    }
    let s = m.state();
    assert_eq!((s.revoked_at, s.reused_jti.clone(), s.reused_at, s.reuse_was_retired),
               (first.revoked_at, first.reused_jti, first.reused_at, first.reuse_was_retired),
               "the first reuse is the one recorded");
}

#[test]
fn inv3_an_expired_family_stays_dead_and_a_later_revoke_does_not_move_revoked_at() {
    let short = RefreshLifetime::new(50, 0).unwrap();
    let mut m = FamilyModel::new(&init("j0", 100));
    assert!(matches!(rot_with(&mut m, "j0", "j1", 150, short), ModelOutcome::Expired(_)));
    assert_eq!(rot(&mut m, "j0", "j2", 151), ModelOutcome::AlreadyRevoked, "even under a wide policy");
    assert_eq!(m.apply(&Op::Revoke, 999), ModelOutcome::Revoked);
    assert_eq!(m.state().revoked_at, Some(150), "the first revocation's time stands");
}

#[test]
fn inv3_an_explicit_revoke_records_no_forensics_and_no_expiry() {
    let mut m = rotated(1);
    m.apply(&Op::Revoke, 500);
    let s = m.state();
    assert_eq!((s.revoked_at, s.reused_jti.clone(), s.reused_at, s.reuse_was_retired, s.expired),
               (Some(500), None, None, None, None));
}

// ── 4. Rotation bookkeeping ─────────────────────────────────────────────────

#[test]
fn inv4_last_rotated_at_is_the_now_of_the_last_successful_rotation_and_one_jti_is_retired_each_time() {
    let mut m = FamilyModel::new(&init("j0", 100));
    assert_eq!(m.state().last_rotated_at, 100, "init sets it to the creation time");
    rot(&mut m, "j0", "j1", 130);
    assert_eq!((m.state().last_rotated_at, m.state().retired_jtis.clone()), (130, vec![jti("j0")]));
    rot(&mut m, "j1", "j2", 130); // same second: non-decreasing, not strictly increasing
    assert_eq!((m.state().last_rotated_at, m.state().retired_jtis.clone()), (130, vec![jti("j0"), jti("j1")]));
    // A refused attempt changes neither.
    rot(&mut m, "never-issued", "x", 140);
    assert_eq!(m.state().last_rotated_at, 130, "a refused rotation is not a rotation");
    assert_eq!(m.state().retired_jtis, vec![jti("j0"), jti("j1")]);
}

// ── 5. Forensic fidelity, including the cap ─────────────────────────────────

#[test]
fn inv5_a_retired_jti_in_the_ring_reports_was_retired_true() {
    let mut m = rotated(3);
    assert_eq!(rot(&mut m, "j1", "x", 500),
        ModelOutcome::ReusedAndRevoked { reused_jti: jti("j1"), was_retired: true });
    assert_eq!(m.state().reuse_was_retired, Some(true));
}

#[test]
fn inv5_a_jti_never_issued_reports_was_retired_false_and_still_revokes() {
    let mut m = rotated(3);
    assert_eq!(rot(&mut m, "shotgun", "x", 500),
        ModelOutcome::ReusedAndRevoked { reused_jti: jti("shotgun"), was_retired: false });
    assert_eq!((m.state().revoked_at, m.state().reuse_was_retired), (Some(500), Some(false)));
}

/// RFC 118 §16.2, the boundary itself: with 17 rotations exactly 16 jtis are
/// retained; the 17th-oldest rotated-out jti has been dropped and reports
/// `false`, while the 16th-oldest is still `true`. Both revoke.
#[test]
fn inv5_the_ring_holds_exactly_the_last_16_and_the_17th_oldest_reports_false() {
    // j0 -> j1 -> ... -> j17: 17 rotations, so j0..j16 were rotated out.
    let m = rotated(17);
    assert_eq!(m.state().retired_jtis.len(), RETIRED_RING_CAP);
    assert_eq!(m.state().retired_jtis.first(), Some(&jti("j1")), "j0, the oldest, was dropped");
    assert_eq!(m.state().retired_jtis.last(),  Some(&jti("j16")));

    let mut evicted = m.clone();
    assert_eq!(rot(&mut evicted, "j0", "x", 900),
        ModelOutcome::ReusedAndRevoked { reused_jti: jti("j0"), was_retired: false });
    assert!(evicted.state().revoked_at.is_some(), "an evicted jti still revokes the family");

    let mut retained = m.clone();
    assert_eq!(rot(&mut retained, "j1", "x", 900),
        ModelOutcome::ReusedAndRevoked { reused_jti: jti("j1"), was_retired: true },
        "the oldest retained jti is still recognised");
}

#[test]
fn inv5_sixteen_rotations_evict_nothing() {
    let m = rotated(16);
    assert_eq!(m.state().retired_jtis.len(), 16);
    assert_eq!(m.state().retired_jtis.first(), Some(&jti("j0")));
}

// ── 6. Expiry ───────────────────────────────────────────────────────────────

#[test]
fn inv6_absolute_expiry_revokes_records_the_deadline_and_does_not_rotate() {
    let p = RefreshLifetime::new(100, 0).unwrap();
    let mut m = FamilyModel::new(&init("j0", 1_000));
    assert!(matches!(rot_with(&mut m, "j0", "j1", 1_099, p), ModelOutcome::Rotated { .. }), "one before the deadline");
    let mut m = FamilyModel::new(&init("j0", 1_000));
    assert_eq!(rot_with(&mut m, "j0", "j1", 1_100, p), ModelOutcome::Expired(LifetimeExpiry::Absolute));
    assert_eq!((m.state().revoked_at, m.state().expired, m.state().current_jti.clone()),
               (Some(1_100), Some(LifetimeExpiry::Absolute), jti("j0")));
}

#[test]
fn inv6_idle_expiry_tracks_the_last_rotation_not_the_creation() {
    let p = RefreshLifetime::new(1_000, 50).unwrap();
    let mut m = FamilyModel::new(&init("j0", 1_000));
    assert!(matches!(rot_with(&mut m, "j0", "j1", 1_049, p), ModelOutcome::Rotated { .. }));
    // 49 seconds after creation would be idle-expired had the window not moved.
    assert!(matches!(rot_with(&mut m, "j1", "j2", 1_098, p), ModelOutcome::Rotated { .. }), "kept alive by rotating");
    assert_eq!(rot_with(&mut m, "j2", "j3", 1_148, p), ModelOutcome::Expired(LifetimeExpiry::Idle), "left idle for 50");
}

#[test]
fn inv6_when_both_deadlines_have_passed_the_absolute_one_is_recorded() {
    let p = RefreshLifetime::new(100, 10).unwrap();
    let mut m = FamilyModel::new(&init("j0", 0));
    assert_eq!(rot_with(&mut m, "j0", "j1", 5_000, p), ModelOutcome::Expired(LifetimeExpiry::Absolute));
}

#[test]
fn inv6_an_expired_family_presented_with_a_retired_jti_is_expired_not_reuse() {
    let p = RefreshLifetime::new(1_000, 20).unwrap();
    let mut m = FamilyModel::new(&init("j0", 100));
    rot_with(&mut m, "j0", "j1", 105, p);
    // j0 is retired. Present it after the idle window has passed.
    assert_eq!(rot_with(&mut m, "j0", "j2", 125, p), ModelOutcome::Expired(LifetimeExpiry::Idle));
    let s = m.state();
    assert_eq!((s.reused_jti.clone(), s.reused_at, s.reuse_was_retired), (None, None, None),
        "an expiry is not reuse: no forensics");
}

#[test]
fn inv6_lowering_the_policy_shortens_a_live_family() {
    let mut m = FamilyModel::new(&init("j0", 0));
    assert!(matches!(rot(&mut m, "j0", "j1", 500), ModelOutcome::Rotated { .. }), "live under the wide policy");
    let lowered = RefreshLifetime::new(400, 0).unwrap();
    assert_eq!(rot_with(&mut m, "j1", "j2", 501, lowered), ModelOutcome::Expired(LifetimeExpiry::Absolute),
        "the same family, under a lower cap, is past it");
}

#[test]
fn inv6_idle_zero_disables_the_idle_window_but_never_the_absolute_cap() {
    let p = RefreshLifetime::new(1_000, 0).unwrap();
    let mut m = FamilyModel::new(&init("j0", 0));
    assert!(matches!(rot_with(&mut m, "j0", "j1", 999, p), ModelOutcome::Rotated { .. }), "999s idle is fine with idle 0");
    assert_eq!(rot_with(&mut m, "j1", "j2", 1_000, p), ModelOutcome::Expired(LifetimeExpiry::Absolute));
}

// ── 7. Init uniqueness ──────────────────────────────────────────────────────

#[test]
fn inv7_init_on_an_existing_family_is_a_conflict_and_resets_nothing() {
    let mut m = rotated(3);
    let before = m.state().clone();
    let mut again = init("brand-new", 9_999);
    again.auth_time = 1;
    assert_eq!(m.apply(&Op::Init(again), 9_999), ModelOutcome::Conflict);
    let s = m.state();
    assert_eq!((s.current_jti.clone(), s.retired_jtis.clone(), s.created_at, s.last_rotated_at, s.auth_time),
               (before.current_jti, before.retired_jtis, before.created_at, before.last_rotated_at, before.auth_time));
}

// ── The rulings that followed the first harness run (RFC 118 §7) ────────────

/// Ruling §6.2: an explicit `revoke` of a family that is past a deadline but has
/// not yet been *detected* as expired records only `revoked_at`. Revocation is
/// absorbing and the first writer wins, so the family is `revoked`, not
/// `expired`, and a later rotation is `AlreadyRevoked` rather than `Expired`.
#[test]
fn inv3_an_explicit_revoke_of_an_undetected_expired_family_wins_and_expired_stays_none() {
    let short = RefreshLifetime::new(50, 0).unwrap();
    let mut m = FamilyModel::new(&init("j0", 100));
    // Well past the absolute cap, but nothing has rotated it, so nothing has noticed.
    assert_eq!(m.apply(&Op::Revoke, 500), ModelOutcome::Revoked);
    assert_eq!((m.state().revoked_at, m.state().expired), (Some(500), None));
    assert_eq!(rot_with(&mut m, "j0", "j1", 501, short), ModelOutcome::AlreadyRevoked,
        "the family is already revoked; the expired deadline is not consulted");
    assert_eq!(m.state().expired, None, "the explicit revocation stands");
}

/// Ruling §6.1: `rotate` and `revoke` on an id that was never initialised are
/// `NotFound`; `init` is not an outcome on an absent family, it creates one.
#[test]
fn absent_family_rotate_and_revoke_are_not_found() {
    let rotate = Op::Rotate { presented: jti("j0"), new: jti("j1"), lifetime: wide() };
    assert_eq!(apply_to_absent(&rotate),    Some(ModelOutcome::NotFound));
    assert_eq!(apply_to_absent(&Op::Revoke), Some(ModelOutcome::NotFound));
    assert_eq!(apply_to_absent(&Op::Init(init("j0", 100))), None, "init creates the family");
}
