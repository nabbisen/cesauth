//! In-memory `AuditEventRepository` for tests (v0.32.0).
//!
//! Stores rows in a `Mutex<Vec<AuditEventRow>>`. Provides the
//! same chain semantics as the D1 adapter: `append` reads the
//! tail, computes the new row's hashes, pushes the row. Tests
//! can inspect the chain via [`InMemoryAuditEventRepository::rows`].
//!
//! Concurrency: the in-memory store serializes appends through
//! the Mutex, so the chain integrity is preserved automatically.
//! The D1 adapter has to retry on contention, but the in-memory
//! one doesn't — single-threaded test access wraps under a lock.
//!
//! Genesis: callers can pre-seed a genesis row via
//! [`InMemoryAuditEventRepository::with_genesis`]; otherwise the
//! first `append` chains from `GENESIS_HASH` directly. The
//! genesis-row case mirrors the D1 schema exactly.

use std::sync::Mutex;

use cesauth_core::audit::chain::{compute_chain_hash, GENESIS_HASH};
use cesauth_core::ports::audit::{
    AuditEventRepository, AuditEventRow, AuditSearch, NewAuditEvent,
};
use cesauth_core::ports::{PortError, PortResult};

#[derive(Debug, Default)]
pub struct InMemoryAuditEventRepository {
    rows: Mutex<Vec<AuditEventRow>>,
}

impl InMemoryAuditEventRepository {
    /// Empty repository. The first append chains directly from
    /// `GENESIS_HASH` and lands at `seq=1`. For tests that need
    /// to mirror the D1 schema's genesis row, use
    /// [`Self::with_genesis`] instead.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a repository pre-seeded with a genesis-style row at
    /// `seq=1`. Subsequent appends start from `seq=2` and chain
    /// from the genesis row's `chain_hash` (which by convention
    /// is `GENESIS_HASH`).
    pub fn with_genesis() -> Self {
        let genesis = AuditEventRow {
            seq:           1,
            id:            "genesis-test".to_owned(),
            ts:            0,
            kind:          "ChainGenesis".to_owned(),
            subject:       None,
            client_id:     None,
            ip:            None,
            user_agent:    None,
            reason:        None,
            payload:       "{}".to_owned(),
            payload_hash:
                "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
                    .to_owned(),
            previous_hash: GENESIS_HASH.to_owned(),
            chain_hash:    GENESIS_HASH.to_owned(),
            created_at:    0,
        };
        let me = Self::default();
        me.rows.lock().unwrap().push(genesis);
        me
    }

    /// Snapshot of every row in seq-ascending order.
    pub fn rows(&self) -> Vec<AuditEventRow> {
        self.rows.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

impl AuditEventRepository for InMemoryAuditEventRepository {
    async fn append(&self, ev: &NewAuditEvent<'_>) -> PortResult<AuditEventRow> {
        let mut guard = self.rows.lock().map_err(|_| PortError::Unavailable)?;

        let (next_seq, prev_hash) = match guard.last() {
            Some(tail) => (tail.seq + 1, tail.chain_hash.clone()),
            None       => (1, GENESIS_HASH.to_owned()),
        };

        let chain_hash = compute_chain_hash(
            &prev_hash,
            ev.payload_hash,
            next_seq,
            ev.ts,
            ev.kind,
            ev.id,
        );

        let row = AuditEventRow {
            seq:           next_seq,
            id:            ev.id.to_owned(),
            ts:            ev.ts,
            kind:          ev.kind.to_owned(),
            subject:       ev.subject.map(str::to_owned),
            client_id:     ev.client_id.map(str::to_owned),
            ip:            ev.ip.map(str::to_owned),
            user_agent:    ev.user_agent.map(str::to_owned),
            reason:        ev.reason.map(str::to_owned),
            payload:       ev.payload.to_owned(),
            payload_hash:  ev.payload_hash.to_owned(),
            previous_hash: prev_hash,
            chain_hash,
            created_at:    ev.created_at,
        };
        guard.push(row.clone());
        Ok(row)
    }

    async fn tail(&self) -> PortResult<Option<AuditEventRow>> {
        let guard = self.rows.lock().map_err(|_| PortError::Unavailable)?;
        Ok(guard.last().cloned())
    }

    async fn search(&self, q: &AuditSearch) -> PortResult<Vec<AuditEventRow>> {
        let guard = self.rows.lock().map_err(|_| PortError::Unavailable)?;
        let mut matches: Vec<AuditEventRow> = guard
            .iter()
            .filter(|r| {
                if let Some(k) = q.kind.as_deref() {
                    if r.kind != k { return false; }
                }
                if let Some(s) = q.subject.as_deref() {
                    if r.subject.as_deref() != Some(s) { return false; }
                }
                if let Some(since) = q.since {
                    if r.ts < since { return false; }
                }
                if let Some(until) = q.until {
                    if r.ts > until { return false; }
                }
                true
            })
            .cloned()
            .collect();
        // Newest first.
        matches.sort_by(|a, b| b.seq.cmp(&a.seq));
        if let Some(limit) = q.limit {
            matches.truncate(limit as usize);
        }
        Ok(matches)
    }
}

#[cfg(test)]
mod tests;
