//! D1-backed `AuditEventRepository` (v0.32.0, ADR-010).
//!
//! Replaces the v0.31.x `CloudflareAuditSink` (R2-only). Audit
//! events now live in the `audit_events` D1 table with a SHA-256
//! hash chain over their rows. The R2 `AUDIT` bucket is no
//! longer written to by cesauth.
//!
//! ## Concurrency
//!
//! D1 is serializable for single-statement transactions. The
//! append path runs SELECT-tail then INSERT. If two writers race
//! and both pick the same predecessor:
//!
//! - The first INSERT lands at `seq=N+1`.
//! - The second INSERT also computes `seq=N+1` (from the same
//!   tail read) but D1's UNIQUE constraint on `seq` rejects it.
//! - The second writer retries: re-reads the tail (which is now
//!   the first writer's row), recomputes the chain hash with the
//!   new predecessor, and INSERTs at `seq=N+2`.
//!
//! The retry budget is small (3 attempts). Sustained high-rate
//! contention is not the deployment shape cesauth targets, and
//! 3 attempts cover normal racing well past any realistic
//! Workers-instance simultaneity.
//!
//! ## Why not D1 batch
//!
//! `db.batch([SELECT, INSERT])` doesn't help here: D1 batches run
//! statements serially within a transaction, but the INSERT
//! parameters depend on the SELECT result. The transaction
//! semantics save us when the chain-input bytes themselves
//! collide (very rare), but the retry-on-UNIQUE-violation path
//! is what carries the load.

use cesauth_core::audit::chain::{compute_chain_hash, GENESIS_HASH};
use cesauth_core::ports::audit::{
    AuditEventRepository, AuditEventRow, AuditSearch, NewAuditEvent,
};
use cesauth_core::ports::{PortError, PortResult};
use serde::Deserialize;
use worker::wasm_bindgen::JsValue;
use worker::Env;

use crate::ports::repo::{d1_int, db, run_err};

/// How many times to retry an append on a UNIQUE-seq collision
/// (concurrent writers picked the same predecessor).
const APPEND_RETRY_BUDGET: u32 = 3;

pub struct CloudflareAuditEventRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareAuditEventRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareAuditEventRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareAuditEventRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct DbRow {
    seq:           i64,
    id:            String,
    ts:            i64,
    kind:          String,
    #[serde(default)]
    subject:       Option<String>,
    #[serde(default)]
    client_id:     Option<String>,
    #[serde(default)]
    ip:            Option<String>,
    #[serde(default)]
    user_agent:    Option<String>,
    #[serde(default)]
    reason:        Option<String>,
    payload:       String,
    payload_hash:  String,
    previous_hash: String,
    chain_hash:    String,
    created_at:    i64,
}

impl DbRow {
    fn into_domain(self) -> AuditEventRow {
        AuditEventRow {
            seq:           self.seq,
            id:            self.id,
            ts:            self.ts,
            kind:          self.kind,
            subject:       self.subject,
            client_id:     self.client_id,
            ip:            self.ip,
            user_agent:    self.user_agent,
            reason:        self.reason,
            payload:       self.payload,
            payload_hash:  self.payload_hash,
            previous_hash: self.previous_hash,
            chain_hash:    self.chain_hash,
            created_at:    self.created_at,
        }
    }
}

const SELECT_COLUMNS: &str =
    "seq, id, ts, kind, subject, client_id, ip, user_agent, reason, \
     payload, payload_hash, previous_hash, chain_hash, created_at";

impl AuditEventRepository for CloudflareAuditEventRepository<'_> {
    async fn append(&self, ev: &NewAuditEvent<'_>) -> PortResult<AuditEventRow> {
        let db = db(self.env)?;

        for _attempt in 0..APPEND_RETRY_BUDGET {
            // Read tail.
            let tail_sql = format!(
                "SELECT {SELECT_COLUMNS} FROM audit_events ORDER BY seq DESC LIMIT 1"
            );
            let tail_stmt = db.prepare(&tail_sql);
            let tail = match tail_stmt.first::<DbRow>(None).await {
                Ok(Some(row)) => Some(row.into_domain()),
                Ok(None)      => None,
                Err(_)        => return Err(PortError::Unavailable),
            };
            let (next_seq, prev_hash) = match tail {
                Some(t) => (t.seq + 1, t.chain_hash),
                None    => (1, GENESIS_HASH.to_owned()),
            };

            // Compute the chain hash with the freshly-read predecessor.
            let chain_hash = compute_chain_hash(
                &prev_hash,
                ev.payload_hash,
                next_seq,
                ev.ts,
                ev.kind,
                ev.id,
            );

            // Attempt INSERT. The seq is set explicitly (not relying
            // on AUTOINCREMENT) so a UNIQUE collision means a racing
            // writer beat us; we retry.
            let stmt = db.prepare(
                "INSERT INTO audit_events (\
                    seq, id, ts, kind, \
                    subject, client_id, ip, user_agent, reason, \
                    payload, payload_hash, previous_hash, chain_hash, created_at\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)"
            )
                .bind(&[
                    d1_int(next_seq),
                    ev.id.into(),
                    d1_int(ev.ts),
                    ev.kind.into(),
                    ev.subject.map(|s| s.into()).unwrap_or(JsValue::NULL),
                    ev.client_id.map(|s| s.into()).unwrap_or(JsValue::NULL),
                    ev.ip.map(|s| s.into()).unwrap_or(JsValue::NULL),
                    ev.user_agent.map(|s| s.into()).unwrap_or(JsValue::NULL),
                    ev.reason.map(|s| s.into()).unwrap_or(JsValue::NULL),
                    ev.payload.into(),
                    ev.payload_hash.into(),
                    prev_hash.clone().into(),
                    chain_hash.clone().into(),
                    d1_int(ev.created_at),
                ])
                .map_err(|e| run_err("audit_events.append bind", e))?;

            match stmt.run().await {
                Ok(_) => {
                    return Ok(AuditEventRow {
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
                    });
                }
                Err(e) => {
                    let msg = format!("{e}");
                    // UNIQUE-violation on `seq` or `id`: a concurrent
                    // writer beat us. Retry with the new tail. The id
                    // case is a duplicate event_id from the caller —
                    // shouldn't happen with UUIDs, but treat as
                    // permanent failure rather than retry storm.
                    if msg.contains("UNIQUE") || msg.contains("constraint") {
                        if msg.contains(".id") || msg.contains("audit_events.id") {
                            return Err(PortError::Conflict);
                        }
                        // seq collision → retry.
                        continue;
                    }
                    return Err(PortError::Unavailable);
                }
            }
        }

        // Exhausted the retry budget. Persistent contention or a
        // deeper D1 problem; surface as Unavailable.
        Err(PortError::Unavailable)
    }

    async fn tail(&self) -> PortResult<Option<AuditEventRow>> {
        let db = db(self.env)?;
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM audit_events ORDER BY seq DESC LIMIT 1"
        );
        let stmt = db.prepare(&sql);
        match stmt.first::<DbRow>(None).await {
            Ok(Some(row)) => Ok(Some(row.into_domain())),
            Ok(None)      => Ok(None),
            Err(_)        => Err(PortError::Unavailable),
        }
    }

    async fn search(&self, q: &AuditSearch) -> PortResult<Vec<AuditEventRow>> {
        let db = db(self.env)?;

        // Build the WHERE clause from the present filters. We
        // bind every value through `?N` placeholders to avoid
        // injection — these strings are user-input via the admin
        // search form.
        let mut where_clauses: Vec<String> = Vec::new();
        let mut params: Vec<JsValue> = Vec::new();
        let mut idx = 1usize;

        if let Some(k) = q.kind.as_deref() {
            where_clauses.push(format!("kind = ?{idx}"));
            params.push(k.into());
            idx += 1;
        }
        if let Some(s) = q.subject.as_deref() {
            where_clauses.push(format!("subject = ?{idx}"));
            params.push(s.into());
            idx += 1;
        }
        if let Some(since) = q.since {
            where_clauses.push(format!("ts >= ?{idx}"));
            params.push(d1_int(since));
            idx += 1;
        }
        if let Some(until) = q.until {
            where_clauses.push(format!("ts <= ?{idx}"));
            params.push(d1_int(until));
            idx += 1;
        }
        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", where_clauses.join(" AND "))
        };

        // Cap the limit at a defensive ceiling (1000) so a
        // misconfigured caller can't pull the whole table.
        let limit_val = q.limit.unwrap_or(50).min(1000);
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM audit_events{where_sql} \
             ORDER BY seq DESC LIMIT ?{idx}"
        );
        params.push(d1_int(limit_val as i64));

        let stmt = db.prepare(&sql)
            .bind(&params)
            .map_err(|e| run_err("audit_events.search bind", e))?;
        let result = stmt.all().await.map_err(|_| PortError::Unavailable)?;
        let rows = result.results::<DbRow>().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().map(DbRow::into_domain).collect())
    }

    async fn fetch_after_seq(&self, from_seq: i64, limit: u32) -> PortResult<Vec<AuditEventRow>> {
        let db = db(self.env)?;
        let limit_val = limit.min(1000) as i64;
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM audit_events \
             WHERE seq > ?1 ORDER BY seq ASC LIMIT ?2"
        );
        let stmt = db.prepare(&sql)
            .bind(&[d1_int(from_seq), d1_int(limit_val)])
            .map_err(|e| run_err("audit_events.fetch_after_seq bind", e))?;
        let result = stmt.all().await.map_err(|_| PortError::Unavailable)?;
        let rows = result.results::<DbRow>().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().map(DbRow::into_domain).collect())
    }
}
