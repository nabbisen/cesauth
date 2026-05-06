//! Port for the user_sessions D1 mirror — the **read+repair**
//! side of the v0.40.0 session-index audit (ADR-012 §Q1)
//! and the v0.49.0 D1 repair tool (ADR-012 §Q1.5).
//!
//! ## Why a separate port from `ActiveSessionStore`
//!
//! `ActiveSessionStore` is the DO-backed live-state interface
//! used by hot paths (login/start, refresh, revoke). Its
//! implementation in the Cloudflare adapter routes RPC calls
//! to a per-session DO and updates the D1 mirror **as a
//! side-effect** of writes.
//!
//! `SessionIndexRepo` is the **D1-only** interface used by
//! the daily reconcile cron and the v0.49.0 repair pass.
//! These are bulk operations against the mirror, not the
//! authoritative session state. Splitting the port keeps
//! the hot-path interface small and makes the reconcile
//! pass's contract explicit: it does NOT call the DO via
//! this port.
//!
//! ## v0.49.0 — `delete_row` and `mark_revoked`
//!
//! Two new methods cover the two repairable drift cases
//! from `cesauth_core::session_index::ReconcileOutcome`:
//!
//! - `DoVanished` → `delete_row` (D1 says active, DO has
//!   no record; sweep cascade deleted the DO; D1 row is
//!   stale and should be deleted).
//! - `DoNewerRevoke` → `mark_revoked` (DO has a revoke
//!   timestamp newer than D1; D1 row needs the revoke
//!   timestamp set to match).
//!
//! `AnomalousD1RevokedDoActive` deliberately has no repair
//! method on this port — automated repair would mask
//! whatever upstream bug produced it. ADR-012 §Q1 paragraph
//! discusses this in detail.
//!
//! Both methods are **idempotent**: calling twice with the
//! same arguments produces the same final state. The
//! repair pass relies on this for retry safety.

use crate::ports::PortResult;
use serde::{Deserialize, Serialize};

/// View of a user_sessions row as the D1 mirror sees it.
/// Same shape as `cesauth_core::session_index::D1SessionRow`
/// (re-exported here for ergonomic use alongside the trait).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionIndexRow {
    pub session_id: String,
    pub user_id:    String,
    pub created_at: i64,
    /// `None` if D1 thinks the session is active;
    /// `Some(unix)` if D1 thinks it's revoked.
    pub revoked_at: Option<i64>,
}

pub trait SessionIndexRepo {
    /// List the currently-active rows in the D1 mirror, up
    /// to `limit`, ordered by `created_at` ASC. Used by the
    /// reconcile cron and the repair pass — both want the
    /// oldest-first ordering so that long-pending drifts
    /// surface even on a busy deployment.
    async fn list_active(&self, limit: u32) -> PortResult<Vec<SessionIndexRow>>;

    /// **v0.49.0** — Delete the D1 row for `session_id`.
    /// Used to repair `DoVanished` drifts: the DO has no
    /// record (sweep cascade deleted it), so the D1 row
    /// is a stale reference that should be removed.
    ///
    /// Idempotent: deleting a non-existent row is `Ok(())`.
    /// The reconcile-then-repair pipeline reads the D1
    /// table once at the start of a pass, so concurrent
    /// writes between read and repair are possible; an
    /// already-deleted row produces no error.
    async fn delete_row(&self, session_id: &str) -> PortResult<()>;

    /// **v0.49.0** — Set the D1 row's `revoked_at` to the
    /// supplied timestamp. Used to repair `DoNewerRevoke`
    /// drifts: the DO recorded a revoke that the mirror
    /// write side missed.
    ///
    /// Idempotent: calling twice with the same timestamp
    /// is a no-op. If `revoked_at` is already set to a
    /// DIFFERENT timestamp on the row, the implementation
    /// MUST NOT overwrite it — the existing revoked_at is
    /// the canonical first-revoke timestamp and a repair
    /// pass should not rewrite history. Implementations
    /// surface this guard via a `WHERE revoked_at IS NULL`
    /// SQL clause (the v0.49.0 D1 adapter uses exactly
    /// this).
    async fn mark_revoked(&self, session_id: &str, revoked_at: i64) -> PortResult<()>;
}
