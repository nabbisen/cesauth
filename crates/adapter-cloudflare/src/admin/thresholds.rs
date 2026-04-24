//! `ThresholdRepository` D1 adapter.

use cesauth_core::admin::ports::ThresholdRepository;
use cesauth_core::admin::types::Threshold;
use cesauth_core::ports::{PortError, PortResult};
use serde::Deserialize;
use worker::Env;

use crate::ports::repo::{d1_int, db, run_err};

pub struct CloudflareThresholdRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareThresholdRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareThresholdRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareThresholdRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct ThresholdRow {
    name:        String,
    value:       i64,
    unit:        String,
    description: Option<String>,
    updated_at:  i64,
}

impl ThresholdRow {
    fn into_domain(self) -> Threshold {
        Threshold {
            name: self.name, value: self.value, unit: self.unit,
            description: self.description, updated_at: self.updated_at,
        }
    }
}

impl ThresholdRepository for CloudflareThresholdRepository<'_> {
    async fn list(&self) -> PortResult<Vec<Threshold>> {
        let db = db(self.env)?;
        let rows = db.prepare(
            "SELECT name, value, unit, description, updated_at \
             FROM admin_thresholds ORDER BY name"
        ).all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<ThresholdRow> = rows.results().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().map(ThresholdRow::into_domain).collect())
    }

    async fn get(&self, name: &str) -> PortResult<Option<Threshold>> {
        let db = db(self.env)?;
        let rows = db.prepare(
            "SELECT name, value, unit, description, updated_at \
             FROM admin_thresholds WHERE name = ?1"
        )
            .bind(&[name.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<ThresholdRow> = rows.results().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().next().map(ThresholdRow::into_domain))
    }

    async fn update(
        &self,
        name:      &str,
        new_value: i64,
        now_unix:  i64,
    ) -> PortResult<Threshold> {
        let db = db(self.env)?;
        db.prepare("UPDATE admin_thresholds SET value = ?2, updated_at = ?3 WHERE name = ?1")
            .bind(&[name.into(), d1_int(new_value), d1_int(now_unix)])
            .map_err(|e| run_err("threshold.update bind", e))?
            .run().await.map_err(|e| run_err("threshold.update run", e))?;
        ThresholdRepository::get(self, name).await?.ok_or(PortError::NotFound)
    }
}
