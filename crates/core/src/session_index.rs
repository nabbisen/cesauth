//! D1-DO session index reconciliation (v0.40.0, ADR-012 §Q1).
//!
//! ## Background
//!
//! Sessions live in the `ActiveSession` Durable Object,
//! keyed by `session_id`. The DO is source of truth. A
//! denormalized D1 mirror at `user_sessions(session_id,
//! user_id, created_at, revoked_at, auth_method,
//! client_id)` exists so the user-facing
//! `/me/security/sessions` page can answer "what sessions
//! does this user have" without a DO namespace iteration
//! (which Cloudflare doesn't support).
//!
//! D1 mirror writes are best-effort: a successful DO
//! write whose D1 mirror failed is left as drift rather
//! than failing the user-visible operation. The
//! invariants the mirror is supposed to satisfy:
//!
//! 1. **Forward-active**: every D1 row with `revoked_at IS
//!    NULL` should correspond to a DO with `revoked_at IS
//!    NULL`. (D1 thinks active, DO confirms active.)
//! 2. **Forward-revoked**: every D1 row with `revoked_at`
//!    set should correspond to a DO that's revoked or
//!    gone.
//! 3. **DO-vanished**: a DO that's been deleted (e.g., by
//!    sweep cascade after absolute timeout) has no
//!    requirement on D1 — the row may linger. Operators
//!    notice these as "phantom" entries the user can't
//!    revoke. Reconcile detects them.
//!
//! ## What this module is, and isn't
//!
//! **This module is**: the pure classification logic.
//! Given one D1 row and one DO state, return one of four
//! [`ReconcileOutcome`] variants. No I/O, no side
//! effects. Trivially unit-testable.
//!
//! **This module isn't**: a runner. The cron job that
//! walks D1 + queries DO + emits audit events lives in
//! the worker (see `cesauth_worker::session_index_audit`).
//! The repair tool — D1 update / D1 delete — is deferred
//! to a future release (ADR-012 §Q1.5).
//!
//! ## Limitation: orphan DOs
//!
//! This reconciliation cannot detect a DO that exists but
//! has no D1 row. Cloudflare doesn't support enumerating
//! DOs in a namespace — without that, "give me every
//! ActiveSession DO" is unanswerable. Pre-v0.35.0
//! sessions (started before the D1 mirror existed) and
//! sessions whose D1 mirror write failed at start time
//! are invisible to this approach. Documented in
//! ADR-012's open questions; tracked as Q5.

use crate::ports::store::SessionStatus;

/// Projection of a `user_sessions` D1 row needed for
/// classification. We don't import the row's `auth_method`
/// or `client_id` because those don't participate in the
/// drift logic (they're informational mirrors); reconcile
/// would not repair them even if they drifted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D1SessionRow {
    pub session_id: String,
    pub user_id:    String,
    pub created_at: i64,
    /// `None` if D1 thinks the session is active; `Some(unix)`
    /// if D1 thinks it's revoked.
    pub revoked_at: Option<i64>,
}

/// One of four classifications for a D1 row + DO state pair.
///
/// "InSync" is the dominant case in practice; the other
/// three are the operationally-interesting drift cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// D1 and DO agree. No-op.
    InSync,

    /// D1 says the session is active; DO has no record
    /// (likely deleted by a sweep cascade after absolute
    /// timeout). The user sees a phantom row in their
    /// list. Repair: delete the D1 row.
    DoVanished,

    /// DO is revoked but D1 still thinks active, OR D1's
    /// `revoked_at` is older than DO's. The user-facing
    /// page would render this as still-active and offer a
    /// no-op revoke button. Repair: update D1's
    /// `revoked_at` to match DO.
    DoNewerRevoke {
        /// The `revoked_at` the DO has (and D1 should
        /// adopt). Always populated when this variant is
        /// returned.
        do_revoked_at: i64,
    },

    /// D1 says revoked but DO says active. This direction
    /// is anomalous — the only paths that revoke a session
    /// write to the DO first, then mirror to D1, so the
    /// reverse drift implies either a manual SQL edit or
    /// something deeper went wrong. Surfaced separately
    /// from the other two so operators can investigate
    /// rather than blindly repair.
    AnomalousD1RevokedDoActive,
}

/// Classify one D1 row + DO status pair.
///
/// `do_status` is what `ActiveSessionStore::status(...)`
/// returned. We intentionally accept the wide
/// `SessionStatus` enum (rather than a narrowed
/// `Option<SessionState>`) because the classification
/// distinguishes `IdleExpired` and `AbsoluteExpired` from
/// `Revoked` — they're all revoked from the user's
/// perspective, but the DO surfaces them as distinct so the
/// audit chain can attribute the cause. For reconcile, all
/// three are treated the same way (DO is in a
/// terminal-revoked state).
pub fn classify(d1: &D1SessionRow, do_status: &SessionStatus) -> ReconcileOutcome {
    match do_status {
        SessionStatus::NotStarted => {
            // DO has no record. If D1 thinks the session
            // is revoked, the row is at a terminal state
            // already (a sweep that deleted the DO is the
            // final stage; D1 just hasn't been pruned).
            // Either way, "DoVanished" is the actionable
            // signal — repair is "delete the D1 row" in
            // both cases.
            //
            // We could split `D1ActiveDoVanished` from
            // `D1RevokedDoVanished`, but the repair
            // action is the same and the operator
            // doesn't need to distinguish for routine
            // monitoring. Keep one variant.
            ReconcileOutcome::DoVanished
        }

        SessionStatus::Active(state) => {
            // DO is active. D1 should also be active.
            match d1.revoked_at {
                None => {
                    // Sanity: the DO state's revoked_at
                    // should also be None.
                    if state.revoked_at.is_none() {
                        ReconcileOutcome::InSync
                    } else {
                        // Defensive: shouldn't happen
                        // (Active variant implies
                        // revoked_at == None) but handle
                        // it as DoNewerRevoke so
                        // reconciliation closes the
                        // window.
                        ReconcileOutcome::DoNewerRevoke {
                            do_revoked_at: state.revoked_at.unwrap(),
                        }
                    }
                }
                Some(_) => ReconcileOutcome::AnomalousD1RevokedDoActive,
            }
        }

        SessionStatus::Revoked(state)
        | SessionStatus::IdleExpired(state)
        | SessionStatus::AbsoluteExpired(state) => {
            // DO is in a terminal-revoked state. D1 should
            // match.
            let do_at = state.revoked_at.unwrap_or_else(|| {
                // Defensive: a Revoked variant whose
                // state.revoked_at is None is a store
                // bug. Fall back to created_at so the
                // outcome carries a usable timestamp;
                // operators see the row at all because
                // we still classify it as drift, and the
                // mismatch will surface in followup
                // queries.
                state.created_at
            });
            match d1.revoked_at {
                None => ReconcileOutcome::DoNewerRevoke { do_revoked_at: do_at },
                Some(d1_at) if d1_at == do_at => ReconcileOutcome::InSync,
                Some(_) => {
                    // D1 has a revoked_at but it's
                    // different from the DO's. Treat as
                    // DoNewerRevoke if DO's is later
                    // (DO is the truth), otherwise still
                    // call it DoNewerRevoke and adopt
                    // the DO value — DO is authoritative
                    // unconditionally.
                    ReconcileOutcome::DoNewerRevoke { do_revoked_at: do_at }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
