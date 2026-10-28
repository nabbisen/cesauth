//! User deletion request service — RFC 044 / GDPR Article 17.
//!
//! Implements the two-stage "request → execute" deletion flow:
//!
//! 1. `schedule_deletion` — user (self) or admin submits a request;
//!    physical delete is deferred by a configurable grace period.
//! 2. `execute_deletion` — called by the cron sweep (or admin) after
//!    `scheduled_at`; calls `UserRepository::delete_by_id` which triggers
//!    ON DELETE CASCADE (RFC 021) across all child tables.
//! 3. `cancel_deletion` — cancels a pending request before execution.
//!
//! The `deletion_requests` row is **retained after execution** as a
//! compliance audit trail; only the `users` row (and cascaded data) is
//! physically removed.
//!
//! ## Grace period
//!
//! `DEFAULT_GRACE_SECS` is 30 days.  Configurable per call.  The grace
//! period exists to:
//! - Give operators time to hold data for legal/compliance review.
//! - Allow admins to cancel accidental self-deletion requests.
//!
//! ## Sweep
//!
//! The daily cron pass calls `cesauth_backend::sweep::sweep_pending_deletions`
//! (RFC 147 cycle 2), which itself lists every request where
//! `scheduled_at <= now` and `status = 'pending'` via
//! [`DeletionRequestRepository::list_due`] and calls [`execute_deletion`] for
//! each, updating the row. Before cycle 2 this function existed and was
//! correct but nothing called it — RFC 147 §13 records that no deletion had
//! ever executed in cesauth by any path.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, CoreResult};
use crate::invitation::InvitationRepository;
use crate::ports::{PortError, PortResult};
use crate::ports::repo::UserRepository;
use crate::types::UnixSeconds;

// ---------------------------------------------------------------------------
// Default grace period
// ---------------------------------------------------------------------------

/// Default grace period before physical deletion: 30 days.
pub const DEFAULT_GRACE_SECS: i64 = 30 * 24 * 3600;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// A deletion request as persisted to the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionRequest {
    pub id:           String,
    pub user_id:      String,
    pub tenant_id:    String,
    pub requested_at: UnixSeconds,
    pub requested_by: String,
    pub reason:       Option<String>,
    pub scheduled_at: UnixSeconds,
    pub executed_at:  Option<UnixSeconds>,
    pub executed_by:  Option<String>,
    pub cancelled_at: Option<UnixSeconds>,
    pub cancelled_by: Option<String>,
    pub status:       DeletionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeletionStatus {
    Pending,
    Executed,
    Cancelled,
}

impl DeletionRequest {
    /// True when the request is pending and past its scheduled time.
    pub fn is_due(&self, now: UnixSeconds) -> bool {
        self.status == DeletionStatus::Pending && now >= self.scheduled_at
    }
}

// ---------------------------------------------------------------------------
// Port
// ---------------------------------------------------------------------------

pub trait DeletionRequestRepository {
    async fn create(&self, req: &DeletionRequest) -> PortResult<()>;
    async fn find_by_id(&self, id: &str) -> PortResult<Option<DeletionRequest>>;
    async fn find_pending_by_user(&self, user_id: &str) -> PortResult<Option<DeletionRequest>>;
    async fn list_due(&self, now: UnixSeconds) -> PortResult<Vec<DeletionRequest>>;
    /// All pending requests for a tenant, for the tenant-admin queue page
    /// (RFC 147 cycle 2 D3). `list_due` is time-scoped, not tenant-scoped,
    /// so it cannot serve that page.
    async fn list_pending_by_tenant(&self, tenant_id: &str) -> PortResult<Vec<DeletionRequest>>;
    async fn mark_executed(&self, id: &str, executed_by: &str, now: UnixSeconds) -> PortResult<()>;
    async fn mark_cancelled(&self, id: &str, cancelled_by: &str, now: UnixSeconds) -> PortResult<()>;
}

// ---------------------------------------------------------------------------
// Service functions
// ---------------------------------------------------------------------------

/// Schedule a user for deletion.
///
/// Returns `Err(CoreError::Conflict)` when a pending deletion request already
/// exists for `user_id`.
///
/// `requested_by` may equal `user_id` (self-service) or be an admin user_id.
pub async fn schedule_deletion<DR>(
    repo:         &DR,
    user_id:      &str,
    tenant_id:    &str,
    requested_by: &str,
    reason:       Option<&str>,
    grace_secs:   i64,
    now:          UnixSeconds,
) -> CoreResult<DeletionRequest>
where
    DR: DeletionRequestRepository,
{
    // One-pending-per-user guard.
    if let Ok(Some(_)) = repo.find_pending_by_user(user_id).await {
        return Err(CoreError::Conflict);
    }

    let req = DeletionRequest {
        id:           Uuid::new_v4().to_string(),
        user_id:      user_id.to_owned(),
        tenant_id:    tenant_id.to_owned(),
        requested_at: now,
        requested_by: requested_by.to_owned(),
        reason:       reason.map(str::to_owned),
        scheduled_at: now + grace_secs,
        executed_at:  None,
        executed_by:  None,
        cancelled_at: None,
        cancelled_by: None,
        status:       DeletionStatus::Pending,
    };

    repo.create(&req).await.map_err(|e| match e {
        PortError::Conflict => CoreError::Conflict,
        _                   => CoreError::Internal,
    })?;

    Ok(req)
}

/// Execute a pending deletion request.
///
/// Hard-deletes the user via `UserRepository::delete_by_id`.  On DELETE
/// CASCADE (RFC 021) removes all child rows.  The `deletion_requests` row
/// is retained with `status = 'executed'` for audit.
///
/// **RFC 148.** `invitation_tokens` holds no foreign key to `users(id)`,
/// so `ON DELETE CASCADE` does not reach it — a deleted user's invitation
/// rows would otherwise keep their email address forever. The address is
/// read *before* the physical delete (it is gone from `users` afterward)
/// and the matching `invitation_tokens` rows are scrubbed *after* it,
/// best-effort: a scrub failure must not be reported as a failure to
/// delete the user, since the user row is already gone by that point.
///
/// Returns `Err(CoreError::InvalidRequest)` if the request does not exist
/// or is not in `Pending` state.
pub async fn execute_deletion<DR, UR, IR>(
    del_repo:        &DR,
    user_repo:       &UR,
    invitation_repo: &IR,
    request_id:      &str,
    executed_by:     &str,
    now:             UnixSeconds,
) -> CoreResult<()>
where
    DR: DeletionRequestRepository,
    UR: UserRepository,
    IR: InvitationRepository,
{
    let req = del_repo
        .find_by_id(request_id)
        .await
        .map_err(|_| CoreError::Internal)?
        .ok_or(CoreError::InvalidRequest("deletion request not found"))?;

    if req.status != DeletionStatus::Pending {
        return Err(CoreError::InvalidRequest("deletion request is not pending"));
    }

    let email = user_repo
        .find_by_id(&req.user_id)
        .await
        .ok()
        .flatten()
        .and_then(|u| u.email);

    // Physical delete.  ON DELETE CASCADE handles all child tables.
    user_repo.delete_by_id(&req.user_id).await.map_err(|_| CoreError::Internal)?;

    if let Some(email) = email {
        invitation_repo.scrub_email(&email, request_id).await.ok();
    }

    // Mark the request as executed (for audit trail).
    del_repo
        .mark_executed(request_id, executed_by, now)
        .await
        .map_err(|_| CoreError::Internal)?;

    Ok(())
}

/// Cancel a pending deletion request.
pub async fn cancel_deletion<DR>(
    repo:         &DR,
    request_id:   &str,
    cancelled_by: &str,
    now:          UnixSeconds,
) -> CoreResult<()>
where
    DR: DeletionRequestRepository,
{
    let req = repo
        .find_by_id(request_id)
        .await
        .map_err(|_| CoreError::Internal)?
        .ok_or(CoreError::InvalidRequest("deletion request not found"))?;

    if req.status != DeletionStatus::Pending {
        return Err(CoreError::InvalidRequest("only pending requests can be cancelled"));
    }

    repo.mark_cancelled(request_id, cancelled_by, now)
        .await
        .map_err(|_| CoreError::Internal)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invitation::{invitation_tombstone, Invitation};
    use std::cell::RefCell;
    use std::collections::HashMap;

    // ── Stub ──────────────────────────────────────────────────────────────

    #[derive(Default)]
    struct StubDelRepo(RefCell<HashMap<String, DeletionRequest>>);

    impl DeletionRequestRepository for StubDelRepo {
        async fn create(&self, req: &DeletionRequest) -> PortResult<()> {
            self.0.borrow_mut().insert(req.id.clone(), req.clone());
            Ok(())
        }
        async fn find_by_id(&self, id: &str) -> PortResult<Option<DeletionRequest>> {
            Ok(self.0.borrow().get(id).cloned())
        }
        async fn find_pending_by_user(&self, user_id: &str) -> PortResult<Option<DeletionRequest>> {
            Ok(self.0.borrow().values()
                .find(|r| r.user_id == user_id && r.status == DeletionStatus::Pending)
                .cloned())
        }
        async fn list_due(&self, now: i64) -> PortResult<Vec<DeletionRequest>> {
            Ok(self.0.borrow().values()
                .filter(|r| r.is_due(now))
                .cloned()
                .collect())
        }
        async fn list_pending_by_tenant(&self, tenant_id: &str) -> PortResult<Vec<DeletionRequest>> {
            Ok(self.0.borrow().values()
                .filter(|r| r.tenant_id == tenant_id && r.status == DeletionStatus::Pending)
                .cloned()
                .collect())
        }
        async fn mark_executed(&self, id: &str, by: &str, now: i64) -> PortResult<()> {
            if let Some(r) = self.0.borrow_mut().get_mut(id) {
                r.status = DeletionStatus::Executed;
                r.executed_at = Some(now);
                r.executed_by = Some(by.to_owned());
            }
            Ok(())
        }
        async fn mark_cancelled(&self, id: &str, by: &str, now: i64) -> PortResult<()> {
            if let Some(r) = self.0.borrow_mut().get_mut(id) {
                r.status = DeletionStatus::Cancelled;
                r.cancelled_at = Some(now);
                r.cancelled_by = Some(by.to_owned());
            }
            Ok(())
        }
    }

    // Stub UserRepository. `users` lets a test seed an email so
    // `execute_deletion`'s RFC 148 scrub has something to read before the
    // user row disappears.
    #[derive(Default)]
    struct StubUserRepo {
        deleted: RefCell<Vec<String>>,
        users:   RefCell<HashMap<String, crate::types::User>>,
    }
    impl StubUserRepo {
        fn seed(&self, user: crate::types::User) {
            self.users.borrow_mut().insert(user.id.clone(), user);
        }
    }
    impl crate::ports::repo::UserRepository for StubUserRepo {
        async fn find_by_id(&self, id: &str) -> crate::ports::PortResult<Option<crate::types::User>> {
            Ok(self.users.borrow().get(id).cloned())
        }
        async fn find_by_email(&self, _: &str) -> crate::ports::PortResult<Option<crate::types::User>> { Ok(None) }
        async fn create(&self, _: &crate::types::User) -> crate::ports::PortResult<()> { Ok(()) }
        async fn update(&self, _: &crate::types::User) -> crate::ports::PortResult<()> { Ok(()) }
        async fn list_by_tenant(&self, _: &str) -> crate::ports::PortResult<Vec<crate::types::User>> { Ok(vec![]) }
        async fn list_anonymous_expired(&self, _: i64) -> crate::ports::PortResult<Vec<crate::types::User>> { Ok(vec![]) }
        async fn delete_by_id(&self, id: &str) -> crate::ports::PortResult<()> {
            self.deleted.borrow_mut().push(id.to_owned());
            Ok(())
        }
    }

    fn stub_user(id: &str, tenant_id: &str, email: &str) -> crate::types::User {
        crate::types::User {
            id:             id.to_owned(),
            tenant_id:      tenant_id.to_owned(),
            email:          Some(email.to_owned()),
            email_verified: true,
            display_name:   None,
            account_type:   crate::tenancy::AccountType::HumanUser,
            status:         crate::types::UserStatus::Active,
            created_at:     NOW,
            updated_at:     NOW,
        }
    }

    // Stub InvitationRepository — only `scrub_email` and `find_by_id` are
    // exercised by this module's tests; the rest exist to satisfy the trait.
    #[derive(Default)]
    struct StubInvitationRepo(RefCell<HashMap<String, Invitation>>);
    impl StubInvitationRepo {
        fn seed(&self, inv: Invitation) {
            self.0.borrow_mut().insert(inv.id.clone(), inv);
        }
    }
    impl crate::invitation::InvitationRepository for StubInvitationRepo {
        async fn create(&self, inv: &Invitation) -> PortResult<()> {
            self.0.borrow_mut().insert(inv.id.clone(), inv.clone());
            Ok(())
        }
        async fn find_by_id(&self, id: &str) -> PortResult<Option<Invitation>> {
            Ok(self.0.borrow().get(id).cloned())
        }
        async fn find_pending_by_tenant_email(&self, _: &str, _: &str, _: i64) -> PortResult<Option<Invitation>> { Ok(None) }
        async fn mark_accepted(&self, _: &str, _: &str, _: i64) -> PortResult<()> { Ok(()) }
        async fn mark_revoked(&self, _: &str, _: &str, _: i64) -> PortResult<()> { Ok(()) }
        async fn list_pending_by_tenant(&self, _: &str, _: i64) -> PortResult<Vec<Invitation>> { Ok(vec![]) }
        async fn scrub_email(&self, email: &str, deletion_request_id: &str) -> PortResult<()> {
            for inv in self.0.borrow_mut().values_mut() {
                if inv.email.eq_ignore_ascii_case(email) {
                    inv.email = invitation_tombstone(deletion_request_id, &inv.id);
                }
            }
            Ok(())
        }
    }

    const NOW: i64 = 1_700_000_000;

    #[tokio::test]
    async fn schedule_creates_pending_request() {
        let dr = StubDelRepo::default();
        let req = schedule_deletion(&dr, "u-1", "t-1", "u-1", None, DEFAULT_GRACE_SECS, NOW).await.unwrap();
        assert_eq!(req.status, DeletionStatus::Pending);
        assert_eq!(req.scheduled_at, NOW + DEFAULT_GRACE_SECS);
        assert!(!req.is_due(NOW)); // not due yet (grace period)
    }

    #[tokio::test]
    async fn schedule_conflict_when_pending_exists() {
        let dr = StubDelRepo::default();
        schedule_deletion(&dr, "u-1", "t-1", "u-1", None, DEFAULT_GRACE_SECS, NOW).await.unwrap();
        let result = schedule_deletion(&dr, "u-1", "t-1", "u-1", None, DEFAULT_GRACE_SECS, NOW).await;
        assert!(matches!(result, Err(CoreError::Conflict)));
    }

    #[tokio::test]
    async fn execute_deletes_user_and_marks_executed() {
        let dr = StubDelRepo::default();
        let ur = StubUserRepo::default();
        let ir = StubInvitationRepo::default();
        ur.seed(stub_user("u-exec", "t-1", "exec@example.com"));
        // Schedule with 0 grace so it's immediately due.
        let req = schedule_deletion(&dr, "u-exec", "t-1", "u-exec", None, 0, NOW).await.unwrap();
        execute_deletion(&dr, &ur, &ir, &req.id, "sweep", NOW).await.unwrap();

        // User repo received the delete call.
        assert!(ur.deleted.borrow().contains(&"u-exec".to_owned()),
            "delete_by_id must be called on user");

        // Request row is marked executed.
        let updated = dr.find_by_id(&req.id).await.unwrap().unwrap();
        assert_eq!(updated.status, DeletionStatus::Executed);
    }

    #[tokio::test]
    async fn execute_non_pending_returns_error() {
        let dr = StubDelRepo::default();
        let ur = StubUserRepo::default();
        let ir = StubInvitationRepo::default();
        let req = schedule_deletion(&dr, "u-x", "t-1", "u-x", None, 0, NOW).await.unwrap();
        cancel_deletion(&dr, &req.id, "admin", NOW + 1).await.unwrap();
        // Trying to execute a cancelled request should fail.
        let result = execute_deletion(&dr, &ur, &ir, &req.id, "sweep", NOW + 2).await;
        assert!(matches!(result, Err(CoreError::InvalidRequest(_))));
    }

    /// RFC 148. `execute_deletion` has no foreign key to lean on for
    /// `invitation_tokens` — it must read the user's email before the
    /// physical delete and scrub it afterward. Demonstrated to fail if
    /// the scrub call is removed: reverting the `scrub_email` call in
    /// `execute_deletion` leaves this row's email untouched and this
    /// assertion fails (see the fires/does-not-fire evidence log).
    #[tokio::test]
    async fn execute_deletion_scrubs_the_deleted_users_invitation_email() {
        let dr = StubDelRepo::default();
        let ur = StubUserRepo::default();
        let ir = StubInvitationRepo::default();
        ur.seed(stub_user("u-inv", "t-1", "invitee@example.com"));
        ir.seed(Invitation {
            id: "inv-1".into(), tenant_id: "t-1".into(), email: "invitee@example.com".into(),
            role: "tenant_member".into(), issued_by: "admin-1".into(),
            issued_at: NOW - 1000, expires_at: NOW + 1000,
            accepted_at: Some(NOW - 500), accepted_by: Some("pending-registration".into()),
            revoked_at: None, revoked_by: None,
        });

        let req = schedule_deletion(&dr, "u-inv", "t-1", "u-inv", None, 0, NOW).await.unwrap();
        execute_deletion(&dr, &ur, &ir, &req.id, "sweep", NOW).await.unwrap();

        let scrubbed = ir.0.borrow().get("inv-1").cloned().unwrap();
        assert_eq!(scrubbed.email, invitation_tombstone(&req.id, "inv-1"));
        assert_eq!(scrubbed.issued_by, "admin-1", "the administrative record must survive");
        assert_eq!(scrubbed.accepted_by.as_deref(), Some("pending-registration"));
        assert_eq!(scrubbed.accepted_at, Some(NOW - 500));
    }

    /// A user with no email on file (anonymous-account edge case) must
    /// not make `execute_deletion` fail — there is nothing to scrub.
    #[tokio::test]
    async fn execute_deletion_with_no_user_email_does_not_fail() {
        let dr = StubDelRepo::default();
        let ur = StubUserRepo::default();
        let ir = StubInvitationRepo::default();
        // No `ur.seed(...)` call: `find_by_id` returns `None`.
        let req = schedule_deletion(&dr, "u-anon", "t-1", "u-anon", None, 0, NOW).await.unwrap();
        let result = execute_deletion(&dr, &ur, &ir, &req.id, "sweep", NOW).await;
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn cancel_marks_cancelled() {
        let dr = StubDelRepo::default();
        let req = schedule_deletion(&dr, "u-c", "t-1", "u-c", None, DEFAULT_GRACE_SECS, NOW).await.unwrap();
        cancel_deletion(&dr, &req.id, "admin", NOW + 1).await.unwrap();
        let updated = dr.find_by_id(&req.id).await.unwrap().unwrap();
        assert_eq!(updated.status, DeletionStatus::Cancelled);
        assert_eq!(updated.cancelled_by.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn cancel_non_pending_returns_error() {
        let dr = StubDelRepo::default();
        let ur = StubUserRepo::default();
        let ir = StubInvitationRepo::default();
        let req = schedule_deletion(&dr, "u-y", "t-1", "u-y", None, 0, NOW).await.unwrap();
        execute_deletion(&dr, &ur, &ir, &req.id, "sweep", NOW).await.unwrap();
        let result = cancel_deletion(&dr, &req.id, "admin", NOW + 1).await;
        assert!(matches!(result, Err(CoreError::InvalidRequest(_))),
            "cancelling an executed request must fail");
    }

    #[tokio::test]
    async fn is_due_after_grace_period() {
        let req = DeletionRequest {
            id: "r".into(), user_id: "u".into(), tenant_id: "t".into(),
            requested_at: NOW, requested_by: "u".into(), reason: None,
            scheduled_at: NOW + 100, executed_at: None, executed_by: None,
            cancelled_at: None, cancelled_by: None,
            status: DeletionStatus::Pending,
        };
        assert!(!req.is_due(NOW + 99), "not due before scheduled_at");
        assert!(req.is_due(NOW + 100), "due exactly at scheduled_at");
        assert!(req.is_due(NOW + 101), "due after scheduled_at");
    }

    /// RFC 147 cycle 2 §7.1 — the property that has never held in this
    /// codebase: a request `request_self` (via `schedule_deletion`) creates
    /// is found by `list_due` once its schedule passes. Before cycle 2,
    /// nothing called `list_due` at all (§13).
    #[tokio::test]
    async fn scheduled_request_is_found_by_list_due_once_due() {
        let dr = StubDelRepo::default();
        let req = schedule_deletion(&dr, "u-due", "t-1", "u-due", None, 100, NOW).await.unwrap();
        assert!(dr.list_due(NOW).await.unwrap().is_empty(), "not due yet");
        let due = dr.list_due(NOW + 100).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, req.id);
    }

    /// RFC 147 cycle 2 §7.6 — cancelling a pending request removes it from
    /// `list_due`, so a later sweep pass cannot execute it.
    #[tokio::test]
    async fn cancelled_request_is_not_listed_as_due() {
        let dr = StubDelRepo::default();
        let req = schedule_deletion(&dr, "u-cancel-due", "t-1", "u-cancel-due", None, 0, NOW).await.unwrap();
        cancel_deletion(&dr, &req.id, "admin", NOW + 1).await.unwrap();
        assert!(dr.list_due(NOW + 2).await.unwrap().is_empty(),
            "a cancelled request must not be listed as due");
    }

    /// RFC 147 cycle 2 D3 — `list_pending_by_tenant` serves the tenant-admin
    /// queue page; only pending requests for the named tenant are returned.
    #[tokio::test]
    async fn list_pending_by_tenant_filters_tenant_and_status() {
        let dr = StubDelRepo::default();
        schedule_deletion(&dr, "u-a", "t-1", "u-a", None, DEFAULT_GRACE_SECS, NOW).await.unwrap();
        let other_tenant = schedule_deletion(&dr, "u-b", "t-2", "u-b", None, DEFAULT_GRACE_SECS, NOW).await.unwrap();
        let cancelled = schedule_deletion(&dr, "u-c", "t-1", "u-c", None, DEFAULT_GRACE_SECS, NOW).await.unwrap();
        cancel_deletion(&dr, &cancelled.id, "admin", NOW + 1).await.unwrap();

        let pending_t1 = dr.list_pending_by_tenant("t-1").await.unwrap();
        assert_eq!(pending_t1.len(), 1, "only the still-pending t-1 request");
        assert_eq!(pending_t1[0].user_id, "u-a");

        let pending_t2 = dr.list_pending_by_tenant("t-2").await.unwrap();
        assert_eq!(pending_t2.len(), 1);
        assert_eq!(pending_t2[0].id, other_tenant.id);
    }

    #[tokio::test]
    async fn schedule_allowed_after_cancellation() {
        let dr = StubDelRepo::default();
        let req = schedule_deletion(&dr, "u-re", "t-1", "u-re", None, DEFAULT_GRACE_SECS, NOW).await.unwrap();
        cancel_deletion(&dr, &req.id, "admin", NOW + 1).await.unwrap();
        // After cancellation, a new request should be possible.
        let req2 = schedule_deletion(&dr, "u-re", "t-1", "u-re", None, DEFAULT_GRACE_SECS, NOW + 2).await;
        assert!(req2.is_ok(), "re-scheduling after cancel must succeed: {req2:?}");
    }
}
