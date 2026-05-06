//! Unit tests for `session_index::classify`.

use super::*;
use crate::ports::store::{AuthMethod, SessionState, SessionStatus};

fn d1_active(revoked: Option<i64>) -> D1SessionRow {
    D1SessionRow {
        session_id: "s1".into(),
        user_id:    "u1".into(),
        created_at: 100,
        revoked_at: revoked,
    }
}

fn do_state(revoked_at: Option<i64>) -> SessionState {
    SessionState {
        session_id:   "s1".into(),
        user_id:      "u1".into(),
        client_id:    "c1".into(),
        scopes:       vec!["openid".into()],
        auth_method:  AuthMethod::Passkey,
        created_at:   100,
        last_seen_at: 150,
        revoked_at,
    }
}

#[test]
fn in_sync_when_both_active() {
    let d1 = d1_active(None);
    let do_status = SessionStatus::Active(do_state(None));
    assert_eq!(classify(&d1, &do_status), ReconcileOutcome::InSync);
}

#[test]
fn in_sync_when_both_revoked_with_matching_timestamp() {
    let d1 = d1_active(Some(200));
    let do_status = SessionStatus::Revoked(do_state(Some(200)));
    assert_eq!(classify(&d1, &do_status), ReconcileOutcome::InSync);
}

// =====================================================================
// DoVanished — DO has no record (sweep deleted, or never existed)
// =====================================================================

#[test]
fn do_vanished_when_d1_active_do_notstarted() {
    // The classic "phantom row" case. D1 says active, DO
    // is gone. User sees a session in their list they
    // can't actually revoke (clicking revoke would 404
    // on the DO).
    let d1 = d1_active(None);
    let do_status = SessionStatus::NotStarted;
    assert_eq!(classify(&d1, &do_status), ReconcileOutcome::DoVanished);
}

#[test]
fn do_vanished_when_d1_revoked_do_notstarted() {
    // Less-pathological case: D1 has the revoke recorded
    // but DO is fully gone (sweep cascade after
    // absolute timeout deleted the DO). Repair is the
    // same — delete the D1 row — even though D1's state
    // is already terminal.
    let d1 = d1_active(Some(150));
    let do_status = SessionStatus::NotStarted;
    assert_eq!(classify(&d1, &do_status), ReconcileOutcome::DoVanished);
}

// =====================================================================
// DoNewerRevoke — DO has revoked_at but D1 doesn't (the common drift)
// =====================================================================

#[test]
fn do_newer_revoke_when_d1_still_thinks_active() {
    let d1 = d1_active(None);
    let do_status = SessionStatus::Revoked(do_state(Some(200)));
    assert_eq!(
        classify(&d1, &do_status),
        ReconcileOutcome::DoNewerRevoke { do_revoked_at: 200 },
    );
}

#[test]
fn idle_expired_classifies_as_do_newer_revoke() {
    // From the user's perspective, IdleExpired is
    // revoked. v0.35.0 split it as a separate variant
    // for audit attribution; for reconcile it's the
    // same drift signal as Revoked.
    let d1 = d1_active(None);
    let do_status = SessionStatus::IdleExpired(do_state(Some(180)));
    assert_eq!(
        classify(&d1, &do_status),
        ReconcileOutcome::DoNewerRevoke { do_revoked_at: 180 },
    );
}

#[test]
fn absolute_expired_classifies_as_do_newer_revoke() {
    let d1 = d1_active(None);
    let do_status = SessionStatus::AbsoluteExpired(do_state(Some(220)));
    assert_eq!(
        classify(&d1, &do_status),
        ReconcileOutcome::DoNewerRevoke { do_revoked_at: 220 },
    );
}

#[test]
fn do_newer_revoke_when_d1_has_stale_timestamp() {
    // Pathological: both think revoked, but with
    // different timestamps. Could happen if a manual
    // SQL edit set D1's revoked_at to a bogus value.
    // DO is authoritative; reconcile adopts DO's.
    let d1 = d1_active(Some(150));  // wrong
    let do_status = SessionStatus::Revoked(do_state(Some(200)));
    assert_eq!(
        classify(&d1, &do_status),
        ReconcileOutcome::DoNewerRevoke { do_revoked_at: 200 },
    );
}

// =====================================================================
// AnomalousD1RevokedDoActive — the impossible direction
// =====================================================================

#[test]
fn anomalous_when_d1_revoked_do_active() {
    // No production code path produces this — every
    // revoke writes DO first, then mirrors to D1. The
    // reverse drift implies a manual SQL edit or
    // something out of process. Reconcile flags it
    // separately so operators investigate rather than
    // auto-repair.
    let d1 = d1_active(Some(200));
    let do_status = SessionStatus::Active(do_state(None));
    assert_eq!(classify(&d1, &do_status), ReconcileOutcome::AnomalousD1RevokedDoActive);
}

// =====================================================================
// Defensive: malformed inputs
// =====================================================================

#[test]
fn defensive_active_variant_with_revoked_at_set_treated_as_do_newer_revoke() {
    // A `SessionStatus::Active` whose inner state has
    // `revoked_at = Some(...)` is a store bug — the
    // variant promises active. Reconcile treats it as
    // DoNewerRevoke (closing the drift window) rather
    // than panicking; production logs would still
    // surface the underlying store bug via other
    // signals.
    let d1 = d1_active(None);
    let weird_state = do_state(Some(190));
    let do_status = SessionStatus::Active(weird_state);
    assert_eq!(
        classify(&d1, &do_status),
        ReconcileOutcome::DoNewerRevoke { do_revoked_at: 190 },
    );
}

#[test]
fn defensive_revoked_variant_with_no_revoked_at_falls_back_to_created_at() {
    // A `Revoked` variant whose state.revoked_at is
    // None is a store bug. Reconcile uses created_at as
    // the fallback timestamp so the outcome is still
    // usable; the row is still classified as drift so
    // the operator sees something is off.
    let d1 = d1_active(None);
    let mut state = do_state(None);
    state.created_at = 50;
    let do_status = SessionStatus::Revoked(state);
    assert_eq!(
        classify(&d1, &do_status),
        ReconcileOutcome::DoNewerRevoke { do_revoked_at: 50 },
    );
}
