//! `CostSnapshotRepository` D1 adapter.
//!
//! Per-hour dedup is achieved by using `<service>:<hour_bucket>` as the
//! row id and `INSERT OR REPLACE`. The trait contract requires that
//! repeated `put()` calls in the same (service, hour) bucket are
//! idempotent; this row-id scheme makes that contract a property of
//! the schema rather than application-level coordination.

use cesauth_core::admin::ports::CostSnapshotRepository;
use cesauth_core::admin::types::{CostSnapshot, Metric, ServiceId};
use cesauth_core::ports::{PortError, PortResult};
use serde::Deserialize;
use worker::Env;

use crate::ports::repo::{d1_int, db, run_err};

pub struct CloudflareCostSnapshotRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareCostSnapshotRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareCostSnapshotRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareCostSnapshotRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct SnapshotRow {
    taken_at: i64,
    service:  String,
    metrics:  String,
}

fn service_from_str(s: &str) -> Option<ServiceId> {
    match s {
        "workers"        => Some(ServiceId::Workers),
        "d1"             => Some(ServiceId::D1),
        "durable_objects"=> Some(ServiceId::DurableObjects),
        "kv"             => Some(ServiceId::Kv),
        "r2"             => Some(ServiceId::R2),
        "turnstile"      => Some(ServiceId::Turnstile),
        _ => None,
    }
}

impl SnapshotRow {
    fn into_domain(self) -> PortResult<CostSnapshot> {
        let service = service_from_str(&self.service)
            .ok_or(PortError::Serialization)?;
        let metrics: Vec<Metric> = serde_json::from_str(&self.metrics)
            .map_err(|_| PortError::Serialization)?;
        Ok(CostSnapshot { service, taken_at: self.taken_at, metrics })
    }
}

impl CostSnapshotRepository for CloudflareCostSnapshotRepository<'_> {
    async fn put(&self, snapshot: &CostSnapshot) -> PortResult<()> {
        let db = db(self.env)?;
        let hour_bucket = snapshot.taken_at / 3600;
        let id = format!("{}:{hour_bucket}", snapshot.service.as_str());
        let metrics_json = serde_json::to_string(&snapshot.metrics)
            .map_err(|_| PortError::Serialization)?;

        db.prepare(
            "INSERT OR REPLACE INTO cost_snapshots (id, taken_at, service, metrics) \
             VALUES (?1, ?2, ?3, ?4)"
        )
            .bind(&[
                id.into(),
                d1_int(snapshot.taken_at),
                snapshot.service.as_str().into(),
                metrics_json.into(),
            ])
            .map_err(|e| run_err("cost_snapshots.put bind", e))?
            .run().await.map_err(|e| run_err("cost_snapshots.put run", e))?;
        Ok(())
    }

    async fn latest(&self, service: ServiceId) -> PortResult<Option<CostSnapshot>> {
        let db = db(self.env)?;
        let rows = db.prepare(
            "SELECT taken_at, service, metrics FROM cost_snapshots \
             WHERE service = ?1 ORDER BY taken_at DESC LIMIT 1"
        )
            .bind(&[service.as_str().into()])
            .map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<SnapshotRow> = rows.results().map_err(|_| PortError::Serialization)?;
        match rows.into_iter().next() {
            Some(r) => Ok(Some(r.into_domain()?)),
            None    => Ok(None),
        }
    }

    async fn recent(&self, service: ServiceId, limit: u32) -> PortResult<Vec<CostSnapshot>> {
        let db = db(self.env)?;
        let rows = db.prepare(
            "SELECT taken_at, service, metrics FROM cost_snapshots \
             WHERE service = ?1 ORDER BY taken_at DESC LIMIT ?2"
        )
            .bind(&[service.as_str().into(), d1_int(limit as i64)])
            .map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<SnapshotRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(SnapshotRow::into_domain).collect()
    }
}
