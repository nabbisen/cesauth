//! Cloudflare-backed `AuditQuerySource`.
//!
//! Walks the `AUDIT` R2 bucket's date-partitioned NDJSON objects,
//! parses each record into an `AdminAuditEntry`, and applies the
//! caller's filters in the adapter.
//!
//! Scope and cost:
//!
//! * Listing is bounded by `prefix` (defaults to today's UTC day) and
//!   `limit` (defaults to 50, hard-capped at 200). The cap exists so
//!   one admin-console page load can never fan out to thousands of R2
//!   `GET`s.
//! * Each listed object is fetched in sequence. For very high-volume
//!   days this will be slow; the admin UI mitigates by preferring
//!   narrower prefixes (e.g. `audit/2026/04/24/`) and smaller limits.
//! * A parse failure on any one object is tolerated: we log once and
//!   skip. This matches the spec's "設定取得不能時も画面全体を壊さない"
//!   (partial-failure tolerance, §11).

use cesauth_core::admin::ports::AuditQuerySource;
use cesauth_core::admin::types::{AdminAuditEntry, AuditQuery};
use cesauth_core::ports::{PortError, PortResult};
use serde::Deserialize;
use time::OffsetDateTime;
use worker::Env;

/// Hard cap on how many objects we will fetch per search call.
const LIMIT_CAP: u32 = 200;

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

/// Shape the `worker::audit::Event` writer produces. Kept local so
/// the admin adapter does not depend on the worker crate.
#[derive(Deserialize)]
struct StoredEvent {
    ts:        i64,
    id:        String,
    kind:      String,
    #[serde(default)]
    subject:   Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    reason:    Option<String>,
}

fn today_prefix() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "audit/{:04}/{:02}/{:02}/",
        now.year(), u8::from(now.month()), now.day(),
    )
}

impl AuditQuerySource for CloudflareAuditQuerySource<'_> {
    async fn search(&self, q: &AuditQuery) -> PortResult<Vec<AdminAuditEntry>> {
        let bucket = self.env.bucket("AUDIT").map_err(|_| PortError::Unavailable)?;

        let prefix = q.prefix.clone().unwrap_or_else(today_prefix);
        let limit  = q.limit.unwrap_or(50).min(LIMIT_CAP);

        let listing = bucket
            .list()
            .prefix(prefix)
            .limit(limit)
            .execute()
            .await
            .map_err(|_| PortError::Unavailable)?;

        let mut out: Vec<AdminAuditEntry> = Vec::new();
        for obj in listing.objects() {
            let key = obj.key();

            // Fetch each object and parse its JSON body. NDJSON here
            // is always single-line so the whole body is one object;
            // if we ever batch, swap to a line-by-line split.
            let body = match bucket.get(&key).execute().await {
                Ok(Some(got)) => match got.body() {
                    Some(b) => b.text().await.ok(),
                    None    => None,
                },
                _ => None,
            };
            let Some(text) = body else { continue; };
            let ev: StoredEvent = match serde_json::from_str(text.trim()) {
                Ok(e)  => e,
                Err(_) => continue,    // tolerate malformed lines
            };

            // Apply in-adapter filters. Doing this here (rather than
            // letting the service layer filter) saves a second pass
            // and keeps the hot path narrower when the operator has
            // searched for something specific.
            if let Some(k) = q.kind_contains.as_deref() {
                if !ev.kind.contains(k) { continue; }
            }
            if let Some(s) = q.subject_contains.as_deref() {
                match ev.subject.as_deref() {
                    Some(v) if v.contains(s) => {}
                    _ => continue,
                }
            }

            out.push(AdminAuditEntry {
                ts:      ev.ts,
                id:      ev.id,
                kind:    ev.kind,
                subject: ev.subject,
                client:  ev.client_id,
                reason:  ev.reason,
                key,
            });
        }

        // Newest first. R2 listings are lexicographic by key; the UUID
        // suffix in the key is not time-sortable, so sort by parsed ts.
        out.sort_by(|a, b| b.ts.cmp(&a.ts));
        Ok(out)
    }
}
