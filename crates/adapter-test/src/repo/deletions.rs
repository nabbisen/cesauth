//! In-memory `DeletionRequestRepository` implementation for tests.

use std::sync::{Arc, Mutex};
use std::collections::HashMap;

use cesauth_core::deletion::{DeletionRequest, DeletionRequestRepository, DeletionStatus};
use cesauth_core::ports::PortResult;
use cesauth_core::types::UnixSeconds;

/// Thread-safe in-memory deletion request store for integration tests.
#[derive(Debug, Default, Clone)]
pub struct InMemoryDeletionRequestRepository {
    rows: Arc<Mutex<HashMap<String, DeletionRequest>>>,
}

impl DeletionRequestRepository for InMemoryDeletionRequestRepository {
    async fn create(&self, req: &DeletionRequest) -> PortResult<()> {
        self.rows.lock().unwrap().insert(req.id.clone(), req.clone());
        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> PortResult<Option<DeletionRequest>> {
        Ok(self.rows.lock().unwrap().get(id).cloned())
    }

    async fn find_pending_by_user(&self, user_id: &str) -> PortResult<Option<DeletionRequest>> {
        Ok(self.rows.lock().unwrap().values()
            .find(|r| r.user_id == user_id && r.status == DeletionStatus::Pending)
            .cloned())
    }

    async fn list_due(&self, now: UnixSeconds) -> PortResult<Vec<DeletionRequest>> {
        Ok(self.rows.lock().unwrap().values()
            .filter(|r| r.is_due(now))
            .cloned()
            .collect())
    }

    async fn mark_executed(
        &self,
        id:          &str,
        executed_by: &str,
        now:         UnixSeconds,
    ) -> PortResult<()> {
        if let Some(r) = self.rows.lock().unwrap().get_mut(id) {
            r.status      = DeletionStatus::Executed;
            r.executed_at = Some(now);
            r.executed_by = Some(executed_by.to_owned());
        }
        Ok(())
    }

    async fn mark_cancelled(
        &self,
        id:           &str,
        cancelled_by: &str,
        now:          UnixSeconds,
    ) -> PortResult<()> {
        if let Some(r) = self.rows.lock().unwrap().get_mut(id) {
            r.status       = DeletionStatus::Cancelled;
            r.cancelled_at = Some(now);
            r.cancelled_by = Some(cancelled_by.to_owned());
        }
        Ok(())
    }
}
