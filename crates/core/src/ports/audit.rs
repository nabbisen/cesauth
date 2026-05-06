//! Audit log persistence (ADR-010, v0.32.0).
//!
//! v0.32.0 replaced the original R2-backed fire-and-forget
//! `AuditSink` with a D1-backed chain-extending repository.
//! The chain is the source of integrity: each row carries a
//! SHA-256 over its own payload, plus a chain hash that
//! incorporates the previous row's chain hash. Tampering with
//! any past row invalidates every later row's chain hash.
//!
//! The trait shape reflects three responsibilities:
//!
//! 1. **Append** an event, extending the chain. Implementations
//!    are expected to: read the tail row, compute the new row's
//!    hashes (via [`crate::audit::chain`]), insert atomically,
//!    retry on a `seq` collision (concurrent writers).
//!
//! 2. **Search** by an admin query, returning the indexed
//!    metadata fields. Used by the admin overview and the
//!    audit search UI.
//!
//! 3. **Read** the chain tail (Phase 2 verifier needs this).
//!    The verifier walks ascending; the writer reads only the
//!    tail.
//!
//! Errors are PortError as elsewhere. Unlike the v0.31.x
//! `AuditSink`, errors here MAY be surfaced — failing to write
//! an audit row no longer silently moves on. The worker layer
//! still treats it as best-effort (logging + continuing) but
//! the trait is honest about failure modes.

use super::PortResult;
use serde::{Deserialize, Serialize};

/// One row in `audit_events`. Carries the full chain metadata
/// plus the indexed fields plus the canonical payload bytes.
///
/// Adapters return this from [`AuditEventRepository::search`]
/// and [`AuditEventRepository::tail`]. The worker layer
/// projects it down to the admin-search shape via
/// `cesauth_core::admin::types::AdminAuditEntry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEventRow {
    pub seq:           i64,
    pub id:            String,
    pub ts:            i64,
    pub kind:          String,
    pub subject:       Option<String>,
    pub client_id:     Option<String>,
    pub ip:            Option<String>,
    pub user_agent:    Option<String>,
    pub reason:        Option<String>,
    pub payload:       String,
    pub payload_hash:  String,
    pub previous_hash: String,
    pub chain_hash:    String,
    pub created_at:    i64,
}

/// What the writer hands the repository to append. The
/// repository fills in `seq`, `previous_hash`, `chain_hash`,
/// and (if not already set) `created_at` based on the current
/// chain tail.
///
/// `payload_hash` is computed by the writer (it has the
/// canonical bytes anyway), keeping the repository free of
/// SHA-256 imports. The repository can verify by recomputing
/// in tests; production trusts the caller because tampering
/// here would only hurt the same caller's chain.
#[derive(Debug, Clone)]
pub struct NewAuditEvent<'a> {
    pub id:           &'a str,
    pub ts:           i64,
    pub kind:         &'a str,
    pub subject:      Option<&'a str>,
    pub client_id:    Option<&'a str>,
    pub ip:           Option<&'a str>,
    pub user_agent:   Option<&'a str>,
    pub reason:       Option<&'a str>,
    pub payload:      &'a str,
    pub payload_hash: &'a str,
    pub created_at:   i64,
}

/// Search filter for the admin query path. `kind` filters by
/// event kind (snake_case); `subject` filters by user/principal
/// id. `since` and `until` are Unix-seconds inclusive bounds.
/// `limit` caps the result count.
///
/// All fields are optional. The default returns the most recent
/// `limit` rows across all kinds. Returning order is `seq`
/// descending (newest first) — the chain ascends, the search
/// reads the head.
#[derive(Debug, Clone, Default)]
pub struct AuditSearch {
    pub kind:    Option<String>,
    pub subject: Option<String>,
    pub since:   Option<i64>,
    pub until:   Option<i64>,
    pub limit:   Option<u32>,
}

pub trait AuditEventRepository {
    /// Append a chain-extended row. Returns the inserted row,
    /// including its assigned `seq`, `previous_hash`, and
    /// `chain_hash`. Concurrent writers contending on the same
    /// tail are resolved by retry inside the implementation up
    /// to a small budget.
    async fn append(&self, ev: &NewAuditEvent<'_>) -> PortResult<AuditEventRow>;

    /// Read the current tail row (highest `seq`). Used by Phase
    /// 2 verifiers and any operation that needs to know "what
    /// has been logged through here".
    ///
    /// Returns `None` only on a freshly-migrated database where
    /// the genesis row hasn't been inserted; production
    /// deployments always have at least the genesis row.
    async fn tail(&self) -> PortResult<Option<AuditEventRow>>;

    /// Search by an admin filter. See [`AuditSearch`].
    async fn search(&self, q: &AuditSearch) -> PortResult<Vec<AuditEventRow>>;

    /// Fetch up to `limit` rows whose `seq > from_seq`, in
    /// **ascending seq order**. Used by the chain verifier
    /// (Phase 2 of ADR-010) to walk the chain forward in pages.
    ///
    /// The verifier walks ascending, not descending, because:
    ///
    /// - The chain ordering is `prev → curr`, so verification has
    ///   to know `prev.chain_hash` before checking `curr`.
    /// - Incremental verification stores a checkpoint at the
    ///   last-verified seq and resumes the walk above it. With
    ///   `search` (which is newest-first for admin views) the
    ///   walk would have to flip to ascending in memory; pushing
    ///   the order down to SQL keeps memory and pagination
    ///   bounded.
    ///
    /// `from_seq = 0` (or any value below the genesis seq=1)
    /// returns the chain from the genesis row inclusive on the
    /// first page. The verifier uses that on a cold start (no
    /// checkpoint yet).
    ///
    /// If fewer than `limit` rows exist past `from_seq`, returns
    /// what's available — callers detect "end of chain" by an
    /// empty (or sub-page) result.
    async fn fetch_after_seq(&self, from_seq: i64, limit: u32) -> PortResult<Vec<AuditEventRow>>;
}
