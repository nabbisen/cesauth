//! `UsageMetricsSource` CF adapter.
//!
//! What we can reach from inside a Worker:
//!
//! | Service           | Reachable?                                   |
//! |-------------------|----------------------------------------------|
//! | Workers requests  | Only a self-maintained counter in KV.        |
//! | D1 usage          | `SELECT COUNT(*) FROM ...` on owned tables.  |
//! | Durable Objects   | NOT enumerable from Workers. Deliberately empty. |
//! | KV usage          | `list` at a small prefix - returns key count. |
//! | R2 storage        | `bucket.list()` + sum sizes.                 |
//! | Turnstile verifies| Only a self-maintained counter in KV.        |
//!
//! The "self-maintained counter" keys live under a reserved KV prefix
//! `counter:` so operators browsing the KV namespace can recognize them.
//! Workers/Turnstile keys use the pattern `counter:<service>:<day>`
//! where day is `YYYY-MM-DD`. The `snapshot()` here sums the last 7
//! days and exposes the total as one metric; maintaining the counters
//! themselves is the worker's per-request responsibility (see the v0.3
//! admin-console chapter of the mdBook).
//!
//! For Durable Objects the snapshot returns an empty metric list; the
//! core policy layer pairs this with a fixed `note` pointing operators
//! at the Cloudflare dashboard for authoritative numbers.

use cesauth_core::admin::ports::UsageMetricsSource;
use cesauth_core::admin::types::{CostSnapshot, Metric, MetricUnit, ServiceId};
use cesauth_core::ports::{PortError, PortResult};
use time::OffsetDateTime;
use worker::Env;

use crate::ports::repo::db;

pub struct CloudflareUsageMetricsSource<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareUsageMetricsSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareUsageMetricsSource").finish_non_exhaustive()
    }
}

impl<'a> CloudflareUsageMetricsSource<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

/// Tables we care about for D1 row-count metrics. v0.32.0 added
/// `audit_events` (when audit moved from R2 to D1, ADR-010); the
/// row count is the closest analog to the R2 object count this
/// snapshot used to surface for the AUDIT bucket.
const D1_COUNTED_TABLES: &[&str] = &[
    "users",
    "authenticators",
    "oidc_clients",
    "grants",
    "jwt_signing_keys",
    "admin_tokens",
    "bucket_safety_state",
    "cost_snapshots",
    "audit_events",
];

async fn count_d1_table(env: &Env, table: &str) -> PortResult<u64> {
    // Table name is a hard-coded literal from D1_COUNTED_TABLES; we
    // cannot bind identifiers in SQL, and whitelist-via-constant-slice
    // is the idiomatic safe approach. Do NOT make this function take
    // a caller-controlled string.
    let sql = format!("SELECT COUNT(*) AS c FROM {table}");
    let db = db(env)?;
    #[derive(serde::Deserialize)]
    struct Row { c: i64 }
    let rows = db.prepare(&sql).all().await.map_err(|_| PortError::Unavailable)?;
    let rows: Vec<Row> = rows.results().map_err(|_| PortError::Serialization)?;
    Ok(rows.into_iter().next().map(|r| r.c.max(0) as u64).unwrap_or(0))
}

async fn d1_metrics(env: &Env) -> PortResult<Vec<Metric>> {
    let mut out = Vec::with_capacity(D1_COUNTED_TABLES.len());
    for t in D1_COUNTED_TABLES {
        // One bad table (e.g. migration not applied yet) must not
        // blank the whole service. Record what we can and move on.
        match count_d1_table(env, t).await {
            Ok(n)  => out.push(Metric {
                key: format!("row_count.{t}"), value: n, unit: MetricUnit::Count,
            }),
            Err(_) => {}
        }
    }
    Ok(out)
}

/// Sum the self-maintained per-day counters under `counter:<prefix>:*`
/// for the last 7 UTC days (including today). Returns 0 if the counter
/// hasn't been started - a brand-new deployment legitimately has no
/// signal here.
async fn sum_kv_counter_last_7d(
    env:    &Env,
    prefix: &str,
    now:    OffsetDateTime,
) -> u64 {
    let Ok(kv) = env.kv("CACHE") else { return 0; };
    let mut total: u64 = 0;
    for days_ago in 0..7 {
        let d = now.saturating_sub(time::Duration::days(days_ago));
        let key = format!(
            "counter:{prefix}:{:04}-{:02}-{:02}",
            d.year(), u8::from(d.month()), d.day(),
        );
        match kv.get(&key).text().await {
            Ok(Some(s)) => {
                if let Ok(n) = s.parse::<u64>() { total = total.saturating_add(n); }
            }
            _ => {}
        }
    }
    total
}

async fn kv_metrics(env: &Env) -> PortResult<Vec<Metric>> {
    // Report total counter entries under `counter:*` as a cheap KV
    // usage indicator. A real KV read/write count would need a
    // self-maintained meta-counter; we don't ship that in 0.3.0.
    let Ok(kv) = env.kv("CACHE") else { return Ok(Vec::new()); };
    match kv.list().prefix("counter:".into()).execute().await {
        Ok(r)  => Ok(vec![Metric {
            key: "counter_entries".into(),
            value: r.keys.len() as u64,
            unit: MetricUnit::Count,
        }]),
        Err(_) => Ok(Vec::new()),
    }
}

impl UsageMetricsSource for CloudflareUsageMetricsSource<'_> {
    async fn snapshot(&self, service: ServiceId, now_unix: i64) -> PortResult<CostSnapshot> {
        let now = OffsetDateTime::from_unix_timestamp(now_unix)
            .unwrap_or_else(|_| OffsetDateTime::now_utc());

        let metrics = match service {
            ServiceId::D1 => d1_metrics(self.env).await.unwrap_or_default(),
            // v0.32.0: cesauth no longer uses R2 (audit moved to D1
            // per ADR-010). The R2 metric used to count AUDIT
            // bucket objects; with audit on D1 the corresponding
            // signal is `row_count.audit_events` reported under
            // ServiceId::D1. We return empty here rather than
            // remove the variant so existing dashboards that probe
            // this service get a consistent "no signal" answer
            // until the next admin-console iteration drops the
            // R2 panel from the UI entirely.
            ServiceId::R2 => Vec::new(),
            ServiceId::Kv => kv_metrics(self.env).await.unwrap_or_default(),
            ServiceId::Workers => vec![Metric {
                key: "requests_last_7d".into(),
                value: sum_kv_counter_last_7d(self.env, "workers:requests", now).await,
                unit: MetricUnit::Count,
            }],
            ServiceId::Turnstile => vec![
                Metric {
                    key: "verified_last_7d".into(),
                    value: sum_kv_counter_last_7d(self.env, "turnstile:verified", now).await,
                    unit: MetricUnit::Count,
                },
                Metric {
                    key: "rejected_last_7d".into(),
                    value: sum_kv_counter_last_7d(self.env, "turnstile:rejected", now).await,
                    unit: MetricUnit::Count,
                },
            ],
            // DO: deliberately empty - Workers can't enumerate DO
            // instances at runtime. The policy layer surfaces a note
            // telling the operator to check the CF dashboard.
            ServiceId::DurableObjects => Vec::new(),
        };

        Ok(CostSnapshot { service, taken_at: now_unix, metrics })
    }
}
