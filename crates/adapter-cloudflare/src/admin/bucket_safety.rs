//! `BucketSafetyRepository` D1 adapter.
//!
//! Row layout matches migration 0002's `bucket_safety_state`. All the
//! 0/1 columns are attested state, not live CF config.

use cesauth_core::admin::ports::BucketSafetyRepository;
use cesauth_core::admin::types::{BucketSafetyChange, BucketSafetyState};
use cesauth_core::ports::{PortError, PortResult};
use serde::Deserialize;
use worker::wasm_bindgen::JsValue;
use worker::Env;

use crate::ports::repo::{d1_int, db, run_err};

pub struct CloudflareBucketSafetyRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareBucketSafetyRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareBucketSafetyRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareBucketSafetyRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct BucketRow {
    bucket:                String,
    public:                i64,
    cors_configured:       i64,
    bucket_lock:           i64,
    lifecycle_configured:  i64,
    event_notifications:   i64,
    notes:                 Option<String>,
    last_verified_at:      Option<i64>,
    last_verified_by:      Option<String>,
    updated_at:            i64,
}

impl BucketRow {
    fn into_domain(self) -> BucketSafetyState {
        BucketSafetyState {
            bucket:               self.bucket,
            public:               self.public != 0,
            cors_configured:      self.cors_configured != 0,
            bucket_lock:          self.bucket_lock != 0,
            lifecycle_configured: self.lifecycle_configured != 0,
            event_notifications:  self.event_notifications != 0,
            notes:                self.notes,
            last_verified_at:     self.last_verified_at,
            last_verified_by:     self.last_verified_by,
            updated_at:           self.updated_at,
        }
    }
}

impl BucketSafetyRepository for CloudflareBucketSafetyRepository<'_> {
    async fn list(&self) -> PortResult<Vec<BucketSafetyState>> {
        let db = db(self.env)?;
        let rows = db.prepare(
            "SELECT bucket, public, cors_configured, bucket_lock, \
                    lifecycle_configured, event_notifications, notes, \
                    last_verified_at, last_verified_by, updated_at \
             FROM bucket_safety_state ORDER BY bucket"
        )
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<BucketRow> = rows.results().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().map(BucketRow::into_domain).collect())
    }

    async fn get(&self, bucket: &str) -> PortResult<Option<BucketSafetyState>> {
        let db = db(self.env)?;
        let rows = db.prepare(
            "SELECT bucket, public, cors_configured, bucket_lock, \
                    lifecycle_configured, event_notifications, notes, \
                    last_verified_at, last_verified_by, updated_at \
             FROM bucket_safety_state WHERE bucket = ?1"
        )
            .bind(&[bucket.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<BucketRow> = rows.results().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().next().map(BucketRow::into_domain))
    }

    async fn verify(
        &self,
        bucket:   &str,
        now_unix: i64,
        verifier: &str,
    ) -> PortResult<BucketSafetyState> {
        let db = db(self.env)?;
        db.prepare(
            "UPDATE bucket_safety_state \
             SET last_verified_at = ?2, last_verified_by = ?3, updated_at = ?2 \
             WHERE bucket = ?1"
        )
            .bind(&[bucket.into(), d1_int(now_unix), verifier.into()])
            .map_err(|e| run_err("bucket_safety.verify bind", e))?
            .run().await.map_err(|e| run_err("bucket_safety.verify run", e))?;

        BucketSafetyRepository::get(self, bucket).await?
            .ok_or(PortError::NotFound)
    }

    async fn apply_change(
        &self,
        change:   &BucketSafetyChange,
        now_unix: i64,
        verifier: &str,
    ) -> PortResult<(BucketSafetyState, BucketSafetyState)> {
        let before = BucketSafetyRepository::get(self, &change.bucket).await?
            .ok_or(PortError::NotFound)?;

        let db = db(self.env)?;
        db.prepare(
            "UPDATE bucket_safety_state SET \
                public = ?2, cors_configured = ?3, bucket_lock = ?4, \
                lifecycle_configured = ?5, event_notifications = ?6, \
                notes = ?7, last_verified_at = ?8, last_verified_by = ?9, \
                updated_at = ?8 \
             WHERE bucket = ?1"
        )
            .bind(&[
                change.bucket.clone().into(),
                d1_int(change.public as i64),
                d1_int(change.cors_configured as i64),
                d1_int(change.bucket_lock as i64),
                d1_int(change.lifecycle_configured as i64),
                d1_int(change.event_notifications as i64),
                match &change.notes {
                    Some(s) => s.clone().into(),
                    None    => JsValue::NULL,
                },
                d1_int(now_unix),
                verifier.into(),
            ])
            .map_err(|e| run_err("bucket_safety.apply bind", e))?
            .run().await.map_err(|e| run_err("bucket_safety.apply run", e))?;

        let after = BucketSafetyRepository::get(self, &change.bucket).await?
            .ok_or(PortError::NotFound)?;
        Ok((before, after))
    }
}
