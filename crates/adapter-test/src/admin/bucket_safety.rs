//! In-memory `BucketSafetyRepository` for tests.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::admin::ports::BucketSafetyRepository;
use cesauth_core::admin::types::{BucketSafetyChange, BucketSafetyState};
use cesauth_core::ports::{PortError, PortResult};

#[derive(Debug, Default)]
pub struct InMemoryBucketSafetyRepository {
    inner: Mutex<HashMap<String, BucketSafetyState>>,
}

impl InMemoryBucketSafetyRepository {
    pub fn seed(&self, states: Vec<BucketSafetyState>) {
        let mut m = self.inner.lock().unwrap();
        m.clear();
        for s in states {
            m.insert(s.bucket.clone(), s);
        }
    }
}

impl BucketSafetyRepository for InMemoryBucketSafetyRepository {
    async fn list(&self) -> PortResult<Vec<BucketSafetyState>> {
        let m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        let mut out: Vec<_> = m.values().cloned().collect();
        out.sort_by(|a, b| a.bucket.cmp(&b.bucket));
        Ok(out)
    }

    async fn get(&self, bucket: &str) -> PortResult<Option<BucketSafetyState>> {
        let m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.get(bucket).cloned())
    }

    async fn verify(
        &self,
        bucket:   &str,
        now_unix: i64,
        verifier: &str,
    ) -> PortResult<BucketSafetyState> {
        let mut m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        let s = m.get_mut(bucket).ok_or(PortError::NotFound)?;
        s.last_verified_at = Some(now_unix);
        s.last_verified_by = Some(verifier.to_owned());
        s.updated_at       = now_unix;
        Ok(s.clone())
    }

    async fn apply_change(
        &self,
        change:   &BucketSafetyChange,
        now_unix: i64,
        verifier: &str,
    ) -> PortResult<(BucketSafetyState, BucketSafetyState)> {
        let mut m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        let before = m.get(&change.bucket).ok_or(PortError::NotFound)?.clone();
        let after  = BucketSafetyState {
            bucket:               change.bucket.clone(),
            public:               change.public,
            cors_configured:      change.cors_configured,
            bucket_lock:          change.bucket_lock,
            lifecycle_configured: change.lifecycle_configured,
            event_notifications:  change.event_notifications,
            notes:                change.notes.clone(),
            last_verified_at:     Some(now_unix),
            last_verified_by:     Some(verifier.to_owned()),
            updated_at:           now_unix,
        };
        m.insert(change.bucket.clone(), after.clone());
        Ok((before, after))
    }
}
