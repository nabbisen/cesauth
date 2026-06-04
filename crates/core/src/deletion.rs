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
//! The daily cron pass calls `sweep_pending_deletions` which returns all
//! requests where `scheduled_at <= now` and `status = 'pending'`.  The
//! caller executes each and updates the row.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, CoreResult};
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
/// Returns `Err(CoreError::InvalidRequest)` if the request does not exist
/// or is not in `Pending` state.
pub async fn execute_deletion<DR, UR>(
    del_repo:    &DR,
    user_repo:   &UR,
    request_id:  &str,
    executed_by: &str,
    now:         UnixSeconds,
) -> CoreResult<()>
where
    DR: DeletionRequestRepository,
    UR: UserRepository,
{
    let req = del_repo
        .find_by_id(request_id)
        .await
        .map_err(|_| CoreError::Internal)?
        .ok_or(CoreError::InvalidRequest("deletion request not found"))?;

    if req.status != DeletionStatus::Pending {
        return Err(CoreError::InvalidRequest("deletion request is not pending"));
    }

    // Physical delete.  ON DELETE CASCADE handles all child tables.
    user_repo.delete_by_id(&req.user_id).await.map_err(|_| CoreError::Internal)?;

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

    // Stub UserRepository
    #[derive(Default)]
    struct StubUserRepo(RefCell<Vec<String>>);
    impl crate::ports::repo::UserRepository for StubUserRepo {
        async fn find_by_id(&self, _: &str) -> crate::ports::PortResult<Option<crate::types::User>> { Ok(None) }
        async fn find_by_email(&self, _: &str) -> crate::ports::PortResult<Option<crate::types::User>> { Ok(None) }
        async fn create(&self, _: &crate::types::User) -> crate::ports::PortResult<()> { Ok(()) }
        async fn update(&self, _: &crate::types::User) -> crate::ports::PortResult<()> { Ok(()) }
        async fn list_by_tenant(&self, _: &str) -> crate::ports::PortResult<Vec<crate::types::User>> { Ok(vec![]) }
        async fn list_anonymous_expired(&self, _: i64) -> crate::ports::PortResult<Vec<crate::types::User>> { Ok(vec![]) }
        async fn delete_by_id(&self, id: &str) -> crate::ports::PortResult<()> {
            self.0.borrow_mut().push(id.to_owned());
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
        // Schedule with 0 grace so it's immediately due.
        let req = schedule_deletion(&dr, "u-exec", "t-1", "u-exec", None, 0, NOW).await.unwrap();
        execute_deletion(&dr, &ur, &req.id, "sweep", NOW).await.unwrap();

        // User repo received the delete call.
        assert!(ur.0.borrow().contains(&"u-exec".to_owned()),
            "delete_by_id must be called on user");

        // Request row is marked executed.
        let updated = dr.find_by_id(&req.id).await.unwrap().unwrap();
        assert_eq!(updated.status, DeletionStatus::Executed);
    }

    #[tokio::test]
    async fn execute_non_pending_returns_error() {
        let dr = StubDelRepo::default();
        let ur = StubUserRepo::default();
        let req = schedule_deletion(&dr, "u-x", "t-1", "u-x", None, 0, NOW).await.unwrap();
        cancel_deletion(&dr, &req.id, "admin", NOW + 1).await.unwrap();
        // Trying to execute a cancelled request should fail.
        let result = execute_deletion(&dr, &ur, &req.id, "sweep", NOW + 2).await;
        assert!(matches!(result, Err(CoreError::InvalidRequest(_))));
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
        let req = schedule_deletion(&dr, "u-y", "t-1", "u-y", None, 0, NOW).await.unwrap();
        execute_deletion(&dr, &ur, &req.id, "sweep", NOW).await.unwrap();
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
