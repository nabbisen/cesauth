//! In-memory `AuditChainCheckpointStore` for tests
//! (Phase 2 of ADR-010, v0.33.0).
//!
//! Holds the two records (checkpoint + last result) under a
//! Mutex. Tests construct one alongside an
//! `InMemoryAuditEventRepository` and exercise the verifier
//! end-to-end.

use std::sync::Mutex;

use cesauth_core::ports::audit_chain::{
    AuditChainCheckpoint, AuditChainCheckpointStore,
    AuditVerificationResult,
};
use cesauth_core::ports::{PortError, PortResult};

#[derive(Debug, Default)]
pub struct InMemoryAuditChainCheckpointStore {
    checkpoint:  Mutex<Option<AuditChainCheckpoint>>,
    last_result: Mutex<Option<AuditVerificationResult>>,
}

impl InMemoryAuditChainCheckpointStore {
    pub fn new() -> Self { Self::default() }

    /// Pre-seed a checkpoint. Useful for testing the
    /// "wholesale-rewrite detection" path: park a checkpoint,
    /// then mutate the audit_events table behind the verifier's
    /// back, run verify_chain, observe `checkpoint_consistent =
    /// false`.
    pub fn with_checkpoint(cp: AuditChainCheckpoint) -> Self {
        let me = Self::default();
        *me.checkpoint.lock().unwrap() = Some(cp);
        me
    }
}

impl AuditChainCheckpointStore for InMemoryAuditChainCheckpointStore {
    async fn read_checkpoint(&self) -> PortResult<Option<AuditChainCheckpoint>> {
        self.checkpoint.lock().map(|g| g.clone()).map_err(|_| PortError::Unavailable)
    }
    async fn write_checkpoint(&self, cp: &AuditChainCheckpoint) -> PortResult<()> {
        let mut g = self.checkpoint.lock().map_err(|_| PortError::Unavailable)?;
        *g = Some(cp.clone());
        Ok(())
    }
    async fn read_last_result(&self) -> PortResult<Option<AuditVerificationResult>> {
        self.last_result.lock().map(|g| g.clone()).map_err(|_| PortError::Unavailable)
    }
    async fn write_last_result(&self, r: &AuditVerificationResult) -> PortResult<()> {
        let mut g = self.last_result.lock().map_err(|_| PortError::Unavailable)?;
        *g = Some(r.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests;
