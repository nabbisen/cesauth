//! In-memory `UsageMetricsSource` for tests.
//!
//! Tests seed a fixture map of (ServiceId -> Vec<Metric>); each
//! `snapshot()` call returns those metrics with `taken_at` stamped
//! from the passed-in `now_unix`. If a service has no fixture,
//! `snapshot()` returns an empty metric list (not an error) - matching
//! the cloudflare adapter behaviour where an unbound service reports
//! zeros rather than failing.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::admin::ports::UsageMetricsSource;
use cesauth_core::admin::types::{CostSnapshot, Metric, ServiceId};
use cesauth_core::ports::{PortError, PortResult};

#[derive(Debug, Default)]
pub struct InMemoryUsageMetricsSource {
    inner: Mutex<HashMap<ServiceId, Vec<Metric>>>,
}

impl InMemoryUsageMetricsSource {
    pub fn seed(&self, service: ServiceId, metrics: Vec<Metric>) {
        self.inner.lock().unwrap().insert(service, metrics);
    }
}

impl UsageMetricsSource for InMemoryUsageMetricsSource {
    async fn snapshot(&self, service: ServiceId, now_unix: i64) -> PortResult<CostSnapshot> {
        let m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        let metrics = m.get(&service).cloned().unwrap_or_default();
        Ok(CostSnapshot { service, taken_at: now_unix, metrics })
    }
}
