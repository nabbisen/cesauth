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

    // ---------------------------------------------------------
    // Tamper helpers — for testing the chain verifier ONLY.
    //
    // These bypass the chain semantics that `append()` enforces.
    // A test simulates an attacker modifying the underlying
    // table behind the chain by calling these — the verifier
    // should then surface the mismatch.
    //
    // Production code MUST NOT call these. They aren't gated
    // with `#[cfg(test)]` because cross-crate test consumers
    // (e.g., `cesauth_core::audit::verifier::tests`) need to
    // call them, and `#[cfg(test)]` is per-crate. Document
    // intent via the function name + module-level rule: only
    // tests touch `tamper_*`.
    // ---------------------------------------------------------

    /// Replace the `payload` field at `seq` (does NOT update
    /// `payload_hash` or `chain_hash`). Simulates an attacker
    /// editing audit content without recomputing the chain.
    pub fn tamper_set_payload(&self, seq: i64, new_payload: &str) {
        let mut g = self.rows.lock().unwrap();
        if let Some(row) = g.iter_mut().find(|r| r.seq == seq) {
            row.payload = new_payload.to_owned();
        }
    }

    /// Replace the `chain_hash` at `seq`. Simulates an attacker
    /// who flipped bits in the integrity column directly.
    pub fn tamper_set_chain_hash(&self, seq: i64, new_hash: String) {
        let mut g = self.rows.lock().unwrap();
        if let Some(row) = g.iter_mut().find(|r| r.seq == seq) {
            row.chain_hash = new_hash;
        }
    }

    /// Replace the `previous_hash` at `seq`. Simulates an
    /// attacker who edited the chain-link column (most useful
    /// against the genesis row's sentinel).
    pub fn tamper_set_previous_hash(&self, seq: i64, new_hash: String) {
        let mut g = self.rows.lock().unwrap();
        if let Some(row) = g.iter_mut().find(|r| r.seq == seq) {
            row.previous_hash = new_hash;
        }
    }

    /// Remove the row at `seq`. Simulates an intermediate-row
    /// deletion attack.
    pub fn tamper_delete_seq(&self, seq: i64) {
        let mut g = self.rows.lock().unwrap();
        g.retain(|r| r.seq != seq);
    }

    /// Empty the chain. Simulates wholesale rewrite — the test
    /// then re-appends a different chain with `append()`.
    pub fn tamper_clear_all(&self) {
        let mut g = self.rows.lock().unwrap();
        g.clear();
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

    async fn fetch_after_seq(&self, from_seq: i64, limit: u32) -> PortResult<Vec<AuditEventRow>> {
        let guard = self.rows.lock().map_err(|_| PortError::Unavailable)?;
        let mut out: Vec<AuditEventRow> = guard.iter()
            .filter(|r| r.seq > from_seq)
            .cloned()
            .collect();
        // Ascending seq for the chain walk.
        out.sort_by(|a, b| a.seq.cmp(&b.seq));
        out.truncate(limit as usize);
        Ok(out)
    }

    async fn delete_below_seq(
        &self,
        floor_seq:   i64,
        older_than:  i64,
        kind_filter: cesauth_core::audit::retention::AuditRetentionKindFilter,
    ) -> PortResult<u32> {
        use cesauth_core::audit::retention::AuditRetentionKindFilter as F;
        let mut guard = self.rows.lock().map_err(|_| PortError::Unavailable)?;
        let before = guard.len();
        guard.retain(|r| {
            // Genesis row (seq=1) is the chain anchor —
            // never prune it regardless of other gates.
            if r.seq <= 1 {
                return true;
            }
            let seq_gate  = r.seq < floor_seq;
            let age_gate  = r.ts  < older_than;
            let kind_gate = match &kind_filter {
                F::OnlyKinds(kinds)    => kinds.iter().any(|k| k == &r.kind),
                F::ExcludeKinds(kinds) => !kinds.iter().any(|k| k == &r.kind),
            };
            // Predicate: row MATCHES the delete filter ⇒ remove.
            // retain keeps !match.
            !(seq_gate && age_gate && kind_gate)
        });
        Ok((before - guard.len()) as u32)
    }
}

#[cfg(test)]
mod tests;
