//! In-memory `CostSnapshotRepository` for tests.

use std::sync::Mutex;

use cesauth_core::admin::ports::CostSnapshotRepository;
use cesauth_core::admin::types::{CostSnapshot, ServiceId};
use cesauth_core::ports::{PortError, PortResult};

#[derive(Debug, Default)]
pub struct InMemoryCostSnapshotRepository {
    inner: Mutex<Vec<CostSnapshot>>,
}

impl CostSnapshotRepository for InMemoryCostSnapshotRepository {
    async fn put(&self, snapshot: &CostSnapshot) -> PortResult<()> {
        let mut v = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        // Per-hour dedup matches the D1 adapter contract. A second put()
        // in the same (service, hour) bucket overwrites the existing row.
        let bucket = snapshot.taken_at / 3600;
        if let Some(existing) = v
            .iter_mut()
            .find(|s| s.service == snapshot.service && s.taken_at / 3600 == bucket)
        {
            *existing = snapshot.clone();
        } else {
            v.push(snapshot.clone());
        }
        Ok(())
    }

    async fn latest(&self, service: ServiceId) -> PortResult<Option<CostSnapshot>> {
        let v = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        Ok(v.iter()
            .filter(|s| s.service == service)
            .max_by_key(|s| s.taken_at)
            .cloned())
    }

    async fn recent(&self, service: ServiceId, limit: u32) -> PortResult<Vec<CostSnapshot>> {
        let v = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        let mut out: Vec<_> = v.iter().filter(|s| s.service == service).cloned().collect();
        out.sort_by(|a, b| b.taken_at.cmp(&a.taken_at));
        out.truncate(limit as usize);
        Ok(out)
    }
}
