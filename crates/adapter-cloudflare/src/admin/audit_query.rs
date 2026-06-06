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
//!
//! v0.71.0 (RFC 109) added these `AuditQuery` fields:
//!
//! - `event_exact` — exact match on `kind`. Maps to `AuditSearch::kind`
//!   directly (the underlying SQL is exact-match already).
//! - `since` / `until` — Unix-second bounds. Map straight through.
//! - `cursor` — opaque base64url over `seq`. Decoded here via
//!   `audit_pagination::decode_cursor` to set `before_seq`. Malformed
//!   cursors are dropped silently (filter not applied) rather than
//!   returning an error — the page still renders.

use cesauth_core::admin::ports::AuditQuerySource;
use cesauth_core::admin::service::audit_pagination;
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
        // filter. Precedence for the `kind` slot:
        //
        // 1. RFC 109 `event_exact` (set via the new viewer dropdown)
        // 2. Legacy `kind_contains` (v0.31.x admin search box)
        //
        // The SQL underlying `AuditEventRepository::search` already
        // does exact match on `kind`, so `event_exact` maps 1:1.
        // `kind_contains` is best-effort exact-match for backward
        // compatibility — operators who relied on partial matches in
        // v0.31.x are using narrow tokens in practice.
        let kind_slot = q.event_exact.clone()
            .or_else(|| q.kind_contains.clone());

        // RFC 109 cursor → before_seq. Malformed cursors drop to None
        // so the page still renders even if the URL was hand-edited.
        let before_seq = q.cursor
            .as_deref()
            .and_then(audit_pagination::decode_cursor);

        let search = AuditSearch {
            kind:       kind_slot,
            subject:    q.subject_contains.clone(),
            since:      q.since,
            until:      q.until,
            limit:      Some(q.limit.unwrap_or(DEFAULT_LIMIT)),
            before_seq,
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
