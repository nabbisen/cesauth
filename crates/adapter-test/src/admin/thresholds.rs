//! In-memory `ThresholdRepository` for tests.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::admin::ports::ThresholdRepository;
use cesauth_core::admin::types::Threshold;
use cesauth_core::ports::{PortError, PortResult};

#[derive(Debug, Default)]
pub struct InMemoryThresholdRepository {
    inner: Mutex<HashMap<String, Threshold>>,
}

impl InMemoryThresholdRepository {
    pub fn seed(&self, rows: Vec<Threshold>) {
        let mut m = self.inner.lock().unwrap();
        m.clear();
        for r in rows {
            m.insert(r.name.clone(), r);
        }
    }
}

impl ThresholdRepository for InMemoryThresholdRepository {
    async fn list(&self) -> PortResult<Vec<Threshold>> {
        let m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        let mut out: Vec<_> = m.values().cloned().collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn get(&self, name: &str) -> PortResult<Option<Threshold>> {
        let m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.get(name).cloned())
    }

    async fn update(
        &self,
        name:      &str,
        new_value: i64,
        now_unix:  i64,
    ) -> PortResult<Threshold> {
        let mut m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        let t = m.get_mut(name).ok_or(PortError::NotFound)?;
        t.value      = new_value;
        t.updated_at = now_unix;
        Ok(t.clone())
    }
}
