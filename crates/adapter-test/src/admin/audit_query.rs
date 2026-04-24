//! In-memory `AuditQuerySource` for tests.

use std::sync::Mutex;

use cesauth_core::admin::ports::AuditQuerySource;
use cesauth_core::admin::types::{AdminAuditEntry, AuditQuery};
use cesauth_core::ports::{PortError, PortResult};

#[derive(Debug, Default)]
pub struct InMemoryAuditQuerySource {
    inner: Mutex<Vec<AdminAuditEntry>>,
}

impl InMemoryAuditQuerySource {
    pub fn seed(&self, entries: Vec<AdminAuditEntry>) {
        *self.inner.lock().unwrap() = entries;
    }

    pub fn push(&self, entry: AdminAuditEntry) {
        self.inner.lock().unwrap().push(entry);
    }
}

impl AuditQuerySource for InMemoryAuditQuerySource {
    async fn search(&self, q: &AuditQuery) -> PortResult<Vec<AdminAuditEntry>> {
        let v = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        let mut out: Vec<AdminAuditEntry> = v
            .iter()
            .filter(|e| match &q.kind_contains {
                Some(s) => e.kind.contains(s.as_str()),
                None    => true,
            })
            .filter(|e| match &q.subject_contains {
                Some(s) => e.subject.as_deref().map(|x| x.contains(s.as_str())).unwrap_or(false),
                None    => true,
            })
            .cloned()
            .collect();
        // Newest-first for deterministic test output.
        out.sort_by(|a, b| b.ts.cmp(&a.ts));
        if let Some(lim) = q.limit {
            out.truncate(lim as usize);
        }
        Ok(out)
    }
}
