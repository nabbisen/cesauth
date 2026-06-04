//! `DeletionRequestRepository` D1 adapter — RFC 047.

use cesauth_core::deletion::{DeletionRequest, DeletionRequestRepository, DeletionStatus};
use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::types::UnixSeconds;
use serde::Deserialize;
use worker::Env;

use super::{d1_int, db, run_err};

pub struct CloudflareDeletionRequestRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareDeletionRequestRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareDeletionRequestRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareDeletionRequestRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct DelRow {
    id:           String,
    user_id:      String,
    tenant_id:    String,
    requested_at: i64,
    requested_by: String,
    #[serde(default)]
    reason:       Option<String>,
    scheduled_at: i64,
    #[serde(default)]
    executed_at:  Option<i64>,
    #[serde(default)]
    executed_by:  Option<String>,
    #[serde(default)]
    cancelled_at: Option<i64>,
    #[serde(default)]
    cancelled_by: Option<String>,
    status:       String,
}

impl DelRow {
    fn into_domain(self) -> DeletionRequest {
        DeletionRequest {
            id:           self.id,
            user_id:      self.user_id,
            tenant_id:    self.tenant_id,
            requested_at: self.requested_at,
            requested_by: self.requested_by,
            reason:       self.reason,
            scheduled_at: self.scheduled_at,
            executed_at:  self.executed_at,
            executed_by:  self.executed_by,
            cancelled_at: self.cancelled_at,
            cancelled_by: self.cancelled_by,
            status: match self.status.as_str() {
                "executed"  => DeletionStatus::Executed,
                "cancelled" => DeletionStatus::Cancelled,
                _           => DeletionStatus::Pending,
            },
        }
    }
}

impl DeletionRequestRepository for CloudflareDeletionRequestRepository<'_> {
    async fn create(&self, req: &DeletionRequest) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare(
            "INSERT INTO deletion_requests \
             (id, user_id, tenant_id, requested_at, requested_by, reason, scheduled_at, status) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending')"
        )
        .bind(&[
            req.id.clone().into(),
            req.user_id.clone().into(),
            req.tenant_id.clone().into(),
            d1_int(req.requested_at),
            req.requested_by.clone().into(),
            req.reason.clone().map(|s| s.into()).unwrap_or(worker::wasm_bindgen::JsValue::NULL),
            d1_int(req.scheduled_at),
        ])
        .map_err(|e| run_err("deletion_requests.create bind", e))?
        .run()
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("UNIQUE") { PortError::Conflict } else { run_err("deletion_requests.create run", e) }
        })?;
        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> PortResult<Option<DeletionRequest>> {
        let db = db(self.env)?;
        let row = db
            .prepare("SELECT * FROM deletion_requests WHERE id = ?1")
            .bind(&[id.into()])
            .map_err(|e| run_err("deletion.find_by_id bind", e))?
            .first::<DelRow>(None)
            .await
            .map_err(|e| run_err("deletion.find_by_id query", e))?;
        Ok(row.map(DelRow::into_domain))
    }

    async fn find_pending_by_user(&self, user_id: &str) -> PortResult<Option<DeletionRequest>> {
        let db = db(self.env)?;
        let row = db
            .prepare(
                "SELECT * FROM deletion_requests \
                 WHERE user_id = ?1 AND status = 'pending' LIMIT 1"
            )
            .bind(&[user_id.into()])
            .map_err(|e| run_err("deletion.find_pending bind", e))?
            .first::<DelRow>(None)
            .await
            .map_err(|e| run_err("deletion.find_pending query", e))?;
        Ok(row.map(DelRow::into_domain))
    }

    async fn list_due(&self, now: UnixSeconds) -> PortResult<Vec<DeletionRequest>> {
        let db = db(self.env)?;
        let results = db
            .prepare(
                "SELECT * FROM deletion_requests \
                 WHERE status = 'pending' AND scheduled_at <= ?1 \
                 ORDER BY scheduled_at ASC"
            )
            .bind(&[d1_int(now)])
            .map_err(|e| run_err("deletion.list_due bind", e))?
            .all()
            .await
            .map_err(|e| run_err("deletion.list_due query", e))?;
        results
            .results::<DelRow>()
            .map(|rows| rows.into_iter().map(DelRow::into_domain).collect())
            .map_err(|e| run_err("deletion.list_due deserialize", e))
    }

    async fn mark_executed(&self, id: &str, executed_by: &str, now: UnixSeconds) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare(
            "UPDATE deletion_requests \
             SET status = 'executed', executed_at = ?1, executed_by = ?2 \
             WHERE id = ?3"
        )
        .bind(&[d1_int(now), executed_by.into(), id.into()])
        .map_err(|e| run_err("deletion.mark_executed bind", e))?
        .run()
        .await
        .map_err(|e| run_err("deletion.mark_executed run", e))?;
        Ok(())
    }

    async fn mark_cancelled(&self, id: &str, cancelled_by: &str, now: UnixSeconds) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare(
            "UPDATE deletion_requests \
             SET status = 'cancelled', cancelled_at = ?1, cancelled_by = ?2 \
             WHERE id = ?3"
        )
        .bind(&[d1_int(now), cancelled_by.into(), id.into()])
        .map_err(|e| run_err("deletion.mark_cancelled bind", e))?
        .run()
        .await
        .map_err(|e| run_err("deletion.mark_cancelled run", e))?;
        Ok(())
    }
}
