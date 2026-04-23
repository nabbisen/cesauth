//! In-memory audit sink. Records go into a Vec the test can inspect.

use std::sync::Mutex;

use cesauth_core::ports::audit::{AuditRecord, AuditSink};
use cesauth_core::ports::{PortError, PortResult};

#[derive(Debug, Default)]
pub struct InMemoryAuditSink {
    events: Mutex<Vec<(String, serde_json::Value)>>,
}

impl InMemoryAuditSink {
    /// Snapshot of everything recorded so far. Useful in tests to
    /// assert that the expected events fired.
    pub fn events(&self) -> Vec<(String, serde_json::Value)> {
        self.events.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

impl AuditSink for InMemoryAuditSink {
    async fn write(&self, record: &AuditRecord<'_>) -> PortResult<()> {
        let mut v = self.events.lock().map_err(|_| PortError::Unavailable)?;
        v.push((record.kind.to_owned(), record.body.clone()));
        Ok(())
    }
}
