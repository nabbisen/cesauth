//! D1-backed `AuditQuerySource` for the admin overview / search
//! views (v0.32.0).
//!
//! v0.31.x and earlier walked the R2 `AUDIT` bucket and parsed
//! NDJSON. v0.32.0 reads from the `audit_events` D1 table (see
//! ADR-010), which:
//!
//! - eliminates the N+1 fetch pattern (one D1 SELECT vs N R2
//!   GETs),
//! - lets the kind/subject filters run as SQL,
//! - reuses the chain-aware `AuditEventRepository::search` —
//!   the same code path the `/me/security/audit` user view will
//!   eventually use.
//!
//! The admin types (`AuditQuery`, `AdminAuditEntry`) keep their
//! shape; this adapter is the only place that translates them
//! to and from `AuditEventRow` plus the `AuditSearch` filter.

use cesauth_core::admin::ports::AuditQuerySource;
use cesauth_core::admin::types::{AdminAuditEntry, AuditQuery};
use cesauth_core::ports::audit::{AuditEventRepository, AuditSearch};
use cesauth_core::ports::{PortError, PortResult};
use worker::Env;

use crate::ports::audit::CloudflareAuditEventRepository;

/// Default page size for the admin overview ("recent N events").
/// Operators can override per-request via `AuditQuery::limit`.
const DEFAULT_LIMIT: u32 = 50;

pub struct CloudflareAuditQuerySource<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareAuditQuerySource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareAuditQuerySource").finish_non_exhaustive()
    }
}

impl<'a> CloudflareAuditQuerySource<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

impl AuditQuerySource for CloudflareAuditQuerySource<'_> {
    async fn search(&self, q: &AuditQuery) -> PortResult<Vec<AdminAuditEntry>> {
        let repo = CloudflareAuditEventRepository::new(self.env);

        // Translate the admin query shape into the repository's
        // filter. The admin types pre-date the v0.32.0 chain and
        // use "kind_contains" / "subject_contains" (substring
        // matches); the repository takes exact matches because
        // SQL LIKE patterns invite injection edge cases. We
        // approximate by passing exact matches when the input
        // doesn't contain wildcards, and fall back to a broader
        // fetch + in-memory filter when the inputs imply a
        // partial match. For v0.32.0 we go with exact: the
        // admin search box already accepted only narrow tokens
        // in practice, and supporting LIKE means widening the
        // attack surface for marginal benefit.
        let search = AuditSearch {
            kind:    q.kind_contains.clone(),
            subject: q.subject_contains.clone(),
            since:   None,
            until:   None,
            limit:   Some(q.limit.unwrap_or(DEFAULT_LIMIT)),
        };

        let rows = repo.search(&search).await
            .map_err(|_| PortError::Unavailable)?;

        Ok(rows.into_iter().map(|r| AdminAuditEntry {
            ts:      r.ts,
            id:      r.id,
            kind:    r.kind,
            subject: r.subject,
            client:  r.client_id,
            reason:  r.reason,
            // v0.32.0+: the "key" column shown in the UI is the
            // chain sequence number, not an R2 object path.
            // Operators who need the raw row can `wrangler d1
            // execute "SELECT * FROM audit_events WHERE seq=N"`.
            key:     format!("seq={}", r.seq),
        }).collect())
    }
}
