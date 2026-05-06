//! Per-user session bulk operations (v0.45.0,
//! ADR-012 §Q4 Resolved).
//!
//! ## What this module is
//!
//! Pure orchestration on top of `ActiveSessionStore`.
//! Each function is a single composition of
//! `list_for_user` + per-row `revoke`, reduced to a
//! count + per-row error tally for the worker handler
//! to surface as a flash banner.
//!
//! ## Why bulk revoke needs its own service
//!
//! It would be tempting to inline the loop in the
//! worker handler. Two reasons not to:
//!
//! 1. **Testability.** The cesauth pattern (v0.40.0
//!    `session_index::classify`, v0.42.0 `revoke`,
//!    v0.43.0 `check_introspection_rate_limit`) is
//!    pure-service-in-core + worker-glue. The pure
//!    service gets full unit-test coverage; the
//!    worker glue is integration territory. Inlining
//!    the loop in the worker would push the test
//!    burden onto a workers-rs harness we don't yet
//!    have.
//! 2. **The "skip current session" rule has subtle
//!    edge cases.** Current session might already be
//!    revoked (cookie still valid in the user's
//!    browser but the DO got swept); current session
//!    might not appear in the list at all (D1 mirror
//!    drift, the v0.40.0 §Q5 limitation); the list
//!    might include non-`Active` rows the worker
//!    shouldn't try to revoke. Centralizing the
//!    "what to revoke" filter in core means we test
//!    those edges once, not at every callsite.
//!
//! ## What this module isn't
//!
//! Not a concurrent runner. The loop is sequential
//! per row. cesauth deployments have at most 50
//! sessions per user (`/me/security/sessions` page
//! limit), so even with one DO RPC per row the
//! latency budget is manageable; concurrency would
//! complicate error attribution and produce minor
//! gain.

use crate::error::CoreResult;
use crate::ports::store::{ActiveSessionStore, SessionStatus};

/// Outcome of a bulk-revoke pass. Counts are
/// surfaced to the worker so the flash banner can
/// say "Signed out 3 other devices" or "Couldn't
/// sign out 1 device — try again".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BulkRevokeOutcome {
    /// How many sessions were successfully revoked.
    /// Zero is the legitimate result when the user
    /// has no other active sessions.
    pub revoked: u32,
    /// How many per-row revoke calls failed (DO
    /// unreachable, etc.). The bulk operation is
    /// best-effort: we DON'T abort the whole batch
    /// on one failure, because the alternative — the
    /// user clicking the button, getting an error,
    /// and being unable to determine which sessions
    /// were revoked vs left alone — is worse than
    /// "most got revoked, retry the button for the
    /// rest". Operators see the per-row failures in
    /// audit logs.
    pub errors:  u32,
    /// How many entries in the list were skipped
    /// because they're the current session. Always
    /// 0 or 1 in practice — `current_session_id`
    /// either matches one row or none. Surfaced
    /// purely for diagnostic clarity.
    pub skipped_current: u32,
}

/// Revoke every active session for `user_id` EXCEPT
/// the one whose `session_id` equals
/// `current_session_id`. Returns a count summary.
///
/// **Best-effort.** A per-row revoke failure
/// increments `errors` but does NOT abort the
/// remaining iterations. This matches the cesauth
/// failure-isolation pattern (cron passes,
/// audit-write best-effort, etc.) and gives the
/// user the most actionable result: "most are gone;
/// the few that aren't, retry".
///
/// `now_unix` is the timestamp passed to each
/// `revoke` call. Using a single value across the
/// batch means all revoked sessions share a
/// `revoked_at` — which makes audit forensics
/// easier ("user pressed bulk-revoke at T; here
/// are all the rows with revoked_at = T").
pub async fn revoke_all_other_sessions<S>(
    store:              &S,
    user_id:            &str,
    current_session_id: &str,
    now_unix:           i64,
) -> CoreResult<BulkRevokeOutcome>
where
    S: ActiveSessionStore,
{
    // Match the user-facing page's cap (50). If
    // there are more than 50 active sessions for one
    // user that's already a degenerate case worth
    // its own investigation; the bulk button isn't
    // the right tool there.
    const PER_USER_CAP: u32 = 50;

    let listed = store
        .list_for_user(user_id, /* include_revoked = */ false, PER_USER_CAP)
        .await
        .map_err(|_| crate::error::CoreError::Internal)?;

    let mut out = BulkRevokeOutcome {
        revoked: 0, errors: 0, skipped_current: 0,
    };

    for row in listed {
        // Skip the current session. The string
        // comparison is exact — session_ids are
        // opaque tokens, no canonicalization needed.
        if row.session_id == current_session_id {
            out.skipped_current += 1;
            continue;
        }
        // Defensive: list_for_user with
        // include_revoked=false is supposed to
        // filter to active rows, but a race between
        // the listing and the revoke call could
        // surface a row that's already revoked. We
        // could check `row.revoked_at.is_none()`
        // here, but the simpler approach is to call
        // `revoke` and treat its idempotent
        // semantics — revoking an already-revoked
        // session is a no-op — as the gate.
        match store.revoke(&row.session_id, now_unix).await {
            Ok(SessionStatus::Revoked(_))
            | Ok(SessionStatus::IdleExpired(_))
            | Ok(SessionStatus::AbsoluteExpired(_)) => {
                // Counted regardless of WHICH terminal
                // state revoke landed in. From the
                // user's perspective they pressed the
                // button and the session is gone.
                out.revoked += 1;
            }
            Ok(SessionStatus::Active(_)) => {
                // Shouldn't happen — `revoke` is
                // supposed to be terminal. Treat as
                // an error rather than a success;
                // surfaces a store bug in the audit
                // counter.
                out.errors += 1;
            }
            Ok(SessionStatus::NotStarted) => {
                // Race: the DO got swept between the
                // list and the revoke. From the
                // user's perspective the row is
                // already gone, which is what they
                // wanted; count as revoked (matches
                // their mental model).
                out.revoked += 1;
            }
            Err(_) => {
                out.errors += 1;
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests;
