//! Unit tests for `service::sessions::revoke_all_other_sessions`.

use super::*;
use crate::ports::PortResult;
use crate::ports::store::{
    ActiveSessionStore, AuthMethod, SessionState, SessionStatus,
};
use std::cell::RefCell;
use std::collections::HashMap;

// =====================================================================
// Stub
// =====================================================================

#[derive(Default)]
struct StubSessionStore {
    sessions:        RefCell<HashMap<String, SessionState>>,
    revoke_calls:    RefCell<Vec<String>>,
    /// If a session_id is in this set, `revoke` returns
    /// PortError::Unavailable instead of mutating state.
    /// Used to test the per-row best-effort failure path.
    revoke_failures: RefCell<std::collections::HashSet<String>>,
    /// If a session_id is in this set, `revoke` returns
    /// `Ok(SessionStatus::NotStarted)` to simulate a race
    /// where the DO got swept between list and revoke.
    revoke_vanished: RefCell<std::collections::HashSet<String>>,
    /// If true, list_for_user itself fails. Tests the
    /// CoreError::Internal mapping.
    list_fails: RefCell<bool>,
}

impl StubSessionStore {
    fn install(&self, session_id: &str, user_id: &str, revoked: bool) {
        let mut s = self.sessions.borrow_mut();
        s.insert(session_id.to_owned(), SessionState {
            session_id:   session_id.to_owned(),
            user_id:      user_id.to_owned(),
            client_id:    "client_demo".into(),
            scopes:       vec!["openid".into()],
            auth_method:  AuthMethod::Passkey,
            created_at:   100,
            last_seen_at: 200,
            revoked_at:   if revoked { Some(150) } else { None },
        });
    }
    fn fail_revoke_for(&self, session_id: &str) {
        self.revoke_failures.borrow_mut().insert(session_id.into());
    }
    fn vanish_on_revoke(&self, session_id: &str) {
        self.revoke_vanished.borrow_mut().insert(session_id.into());
    }
}

impl ActiveSessionStore for StubSessionStore {
    async fn start(&self, _: &SessionState) -> PortResult<()> {
        unimplemented!("revoke_all_other_sessions must not call start")
    }
    async fn touch(&self, _: &str, _: i64, _: i64, _: i64) -> PortResult<SessionStatus> {
        unimplemented!("revoke_all_other_sessions must not call touch")
    }
    async fn status(&self, _: &str) -> PortResult<SessionStatus> {
        unimplemented!("revoke_all_other_sessions must not call status")
    }

    async fn revoke(&self, session_id: &str, now_unix: i64) -> PortResult<SessionStatus> {
        self.revoke_calls.borrow_mut().push(session_id.to_owned());

        if self.revoke_failures.borrow().contains(session_id) {
            return Err(crate::ports::PortError::Unavailable);
        }
        if self.revoke_vanished.borrow().contains(session_id) {
            return Ok(SessionStatus::NotStarted);
        }

        let mut s = self.sessions.borrow_mut();
        match s.get_mut(session_id) {
            Some(state) => {
                state.revoked_at = Some(now_unix);
                Ok(SessionStatus::Revoked(state.clone()))
            }
            None => Ok(SessionStatus::NotStarted),
        }
    }

    async fn list_for_user(&self, user_id: &str, include_revoked: bool, _limit: u32) -> PortResult<Vec<SessionState>> {
        if *self.list_fails.borrow() {
            return Err(crate::ports::PortError::Unavailable);
        }
        let s = self.sessions.borrow();
        let mut out: Vec<SessionState> = s.values()
            .filter(|st| st.user_id == user_id)
            .filter(|st| include_revoked || st.revoked_at.is_none())
            .cloned()
            .collect();
        // Stable order for tests.
        out.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        Ok(out)
    }
}

// =====================================================================
// Happy paths
// =====================================================================

#[tokio::test]
async fn revokes_all_other_active_sessions_keeps_current() {
    let store = StubSessionStore::default();
    store.install("s_current", "user_a", false);
    store.install("s_phone",   "user_a", false);
    store.install("s_laptop",  "user_a", false);
    store.install("s_tablet",  "user_a", false);

    let outcome = revoke_all_other_sessions(
        &store, "user_a", "s_current", 500,
    ).await.unwrap();

    assert_eq!(outcome, BulkRevokeOutcome {
        revoked: 3,
        errors: 0,
        skipped_current: 1,
    });

    // Current session NOT in revoke calls.
    let calls = store.revoke_calls.borrow();
    assert!(!calls.contains(&"s_current".to_owned()),
        "current session must not be revoked: {calls:?}");
    assert_eq!(calls.len(), 3);

    // Current session still active in store.
    let still_active = store.sessions.borrow();
    assert!(still_active.get("s_current").unwrap().revoked_at.is_none());
}

#[tokio::test]
async fn no_other_active_sessions_is_zero_count_no_calls() {
    // User has only the current session. Bulk revoke
    // is a legitimate no-op.
    let store = StubSessionStore::default();
    store.install("s_only", "user_a", false);

    let outcome = revoke_all_other_sessions(
        &store, "user_a", "s_only", 500,
    ).await.unwrap();

    assert_eq!(outcome, BulkRevokeOutcome {
        revoked: 0,
        errors: 0,
        skipped_current: 1,
    });
    assert!(store.revoke_calls.borrow().is_empty());
}

#[tokio::test]
async fn user_with_no_sessions_is_zero_count_zero_skipped() {
    // Edge case: caller passed a current_session_id
    // that doesn't appear in the user's list (e.g.,
    // race with a sweep that removed it just before
    // the bulk call). Result: no revokes, no skips.
    let store = StubSessionStore::default();
    // No sessions for this user.

    let outcome = revoke_all_other_sessions(
        &store, "user_phantom", "s_phantom", 500,
    ).await.unwrap();

    assert_eq!(outcome, BulkRevokeOutcome {
        revoked: 0,
        errors: 0,
        skipped_current: 0,
    });
}

#[tokio::test]
async fn current_session_not_in_user_list_revokes_all_listed() {
    // The "current_session_id" is for user_a, but the
    // list returns a different set (D1 mirror drift,
    // or current session's row got swept). The bulk
    // revoke should still revoke every listed session
    // — none of them is the current one by string
    // comparison.
    let store = StubSessionStore::default();
    store.install("s_phone",  "user_a", false);
    store.install("s_laptop", "user_a", false);

    let outcome = revoke_all_other_sessions(
        &store, "user_a", "s_current_unlisted", 500,
    ).await.unwrap();

    assert_eq!(outcome.revoked,         2);
    assert_eq!(outcome.errors,          0);
    assert_eq!(outcome.skipped_current, 0,
        "no row matched the current_session_id, so skipped_current is 0");
}

#[tokio::test]
async fn does_not_touch_other_users_sessions() {
    // Multi-tenant correctness: bulk revoke for
    // user_a must not affect user_b's sessions.
    let store = StubSessionStore::default();
    store.install("s_a_current", "user_a", false);
    store.install("s_a_phone",   "user_a", false);
    store.install("s_b_phone",   "user_b", false);
    store.install("s_b_laptop",  "user_b", false);

    let _outcome = revoke_all_other_sessions(
        &store, "user_a", "s_a_current", 500,
    ).await.unwrap();

    // user_b's sessions untouched.
    let s = store.sessions.borrow();
    assert!(s.get("s_b_phone").unwrap().revoked_at.is_none(),
        "user_b's session must not be revoked by user_a's bulk");
    assert!(s.get("s_b_laptop").unwrap().revoked_at.is_none());

    // Only user_a's non-current was revoked.
    let calls = store.revoke_calls.borrow();
    assert_eq!(*calls, vec!["s_a_phone".to_owned()]);
}

#[tokio::test]
async fn already_revoked_sessions_are_filtered_by_list() {
    // list_for_user with include_revoked=false skips
    // already-revoked rows. The bulk service relies
    // on this — it doesn't double-check.
    let store = StubSessionStore::default();
    store.install("s_current",      "user_a", false);
    store.install("s_zombie",       "user_a", true);   // already revoked
    store.install("s_active_other", "user_a", false);

    let outcome = revoke_all_other_sessions(
        &store, "user_a", "s_current", 500,
    ).await.unwrap();

    assert_eq!(outcome.revoked, 1, "only s_active_other counts");
    let calls = store.revoke_calls.borrow();
    assert!(!calls.contains(&"s_zombie".to_owned()),
        "already-revoked session must not be re-revoked");
}

// =====================================================================
// Failure paths
// =====================================================================

#[tokio::test]
async fn per_row_failure_increments_errors_does_not_abort() {
    let store = StubSessionStore::default();
    store.install("s_current", "user_a", false);
    store.install("s_ok1",     "user_a", false);
    store.install("s_broken",  "user_a", false);
    store.install("s_ok2",     "user_a", false);
    store.fail_revoke_for("s_broken");

    let outcome = revoke_all_other_sessions(
        &store, "user_a", "s_current", 500,
    ).await.unwrap();

    assert_eq!(outcome.revoked,         2);
    assert_eq!(outcome.errors,          1);
    assert_eq!(outcome.skipped_current, 1);

    // s_ok1 and s_ok2 are revoked; s_broken left as-is
    // because revoke errored.
    let s = store.sessions.borrow();
    assert!(s.get("s_ok1").unwrap().revoked_at.is_some());
    assert!(s.get("s_ok2").unwrap().revoked_at.is_some());
    assert!(s.get("s_broken").unwrap().revoked_at.is_none());
}

#[tokio::test]
async fn list_failure_propagates_as_internal_error() {
    let store = StubSessionStore::default();
    store.install("s_current", "user_a", false);
    *store.list_fails.borrow_mut() = true;

    let result = revoke_all_other_sessions(
        &store, "user_a", "s_current", 500,
    ).await;

    assert!(matches!(result, Err(crate::error::CoreError::Internal)),
        "list failure must surface as Internal: {result:?}");
}

#[tokio::test]
async fn revoke_returning_notstarted_counts_as_revoked() {
    // Race: another session got swept between list
    // and revoke. From the user's perspective the
    // row is already gone, which is what they wanted.
    // Count as revoked.
    let store = StubSessionStore::default();
    store.install("s_current", "user_a", false);
    store.install("s_racey",   "user_a", false);
    store.vanish_on_revoke("s_racey");

    let outcome = revoke_all_other_sessions(
        &store, "user_a", "s_current", 500,
    ).await.unwrap();

    assert_eq!(outcome.revoked, 1,
        "vanished-on-revoke is a user-visible success");
    assert_eq!(outcome.errors, 0);
}

// =====================================================================
// Determinism / idempotence
// =====================================================================

#[tokio::test]
async fn second_call_after_first_is_zero_count() {
    // After a bulk revoke, calling again is a no-op
    // (all the other sessions are already revoked,
    // list_for_user filters them out).
    let store = StubSessionStore::default();
    store.install("s_current", "user_a", false);
    store.install("s_phone",   "user_a", false);

    let first = revoke_all_other_sessions(
        &store, "user_a", "s_current", 500,
    ).await.unwrap();
    assert_eq!(first.revoked, 1);

    let second = revoke_all_other_sessions(
        &store, "user_a", "s_current", 600,
    ).await.unwrap();
    assert_eq!(second, BulkRevokeOutcome {
        revoked: 0,
        errors: 0,
        skipped_current: 1,
    });
}
