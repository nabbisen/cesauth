//! Cloudflare KV-backed `AuditChainCheckpointStore`
//! (Phase 2 of ADR-010, v0.33.0).
//!
//! The chain head checkpoint + last verification result are
//! tiny JSON blobs (a few hundred bytes each), read on every
//! verifier run and written only on success. KV's
//! eventually-consistent reads are acceptable here:
//!
//! - **Cron schedule is daily.** Read-after-write within
//!   seconds isn't required.
//! - **The verifier is the only writer.** No concurrent-write
//!   resolution needed.
//! - **A briefly-stale checkpoint is benign.** It just means
//!   the next incremental run walks a few extra rows.
//!
//! ## Why KV (not D1)
//!
//! Per ADR-010 §"Phase 2 — chain head checkpoint location",
//! the checkpoint MUST live separately from `audit_events`.
//! Co-locating it would defeat the wholesale-rewrite
//! detection: an attacker with write access to `audit_events`
//! would have write access to the checkpoint too. KV is a
//! different binding with a different access pattern, so
//! compromising both stores synchronously is meaningfully
//! harder than just D1.
//!
//! ## Key layout
//!
//! Two keys under the reserved `chain:` prefix in the `CACHE`
//! namespace:
//!
//! - `chain:checkpoint` — JSON-encoded `AuditChainCheckpoint`
//! - `chain:last_result` — JSON-encoded `AuditVerificationResult`
//!
//! No TTL: the checkpoint and result are operational records,
//! not cached values. Only the verifier writes to them; KV
//! holds them indefinitely.

use cesauth_core::ports::audit_chain::{
    AuditChainCheckpoint, AuditChainCheckpointStore,
    AuditVerificationResult,
};
use cesauth_core::ports::{PortError, PortResult};
use worker::Env;

const KEY_CHECKPOINT:  &str = "chain:checkpoint";
const KEY_LAST_RESULT: &str = "chain:last_result";

pub struct CloudflareAuditChainCheckpointStore<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareAuditChainCheckpointStore<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareAuditChainCheckpointStore").finish_non_exhaustive()
    }
}

impl<'a> CloudflareAuditChainCheckpointStore<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

async fn read_json<T: for<'de> serde::Deserialize<'de>>(env: &Env, key: &str) -> PortResult<Option<T>> {
    let ns = env.kv("CACHE").map_err(|_| PortError::Unavailable)?;
    match ns.get(key).text().await {
        Ok(Some(s)) => {
            let parsed = serde_json::from_str::<T>(&s).map_err(|_| PortError::Serialization)?;
            Ok(Some(parsed))
        }
        Ok(None) => Ok(None),
        Err(_)   => Err(PortError::Unavailable),
    }
}

async fn write_json<T: serde::Serialize>(env: &Env, key: &str, v: &T) -> PortResult<()> {
    let ns = env.kv("CACHE").map_err(|_| PortError::Unavailable)?;
    let body = serde_json::to_string(v).map_err(|_| PortError::Serialization)?;
    // No TTL — these are operational records, not cache values.
    ns.put(key, body)
        .map_err(|_| PortError::Unavailable)?
        .execute()
        .await
        .map_err(|_| PortError::Unavailable)?;
    Ok(())
}

impl AuditChainCheckpointStore for CloudflareAuditChainCheckpointStore<'_> {
    async fn read_checkpoint(&self) -> PortResult<Option<AuditChainCheckpoint>> {
        read_json(self.env, KEY_CHECKPOINT).await
    }
    async fn write_checkpoint(&self, cp: &AuditChainCheckpoint) -> PortResult<()> {
        write_json(self.env, KEY_CHECKPOINT, cp).await
    }
    async fn read_last_result(&self) -> PortResult<Option<AuditVerificationResult>> {
        read_json(self.env, KEY_LAST_RESULT).await
    }
    async fn write_last_result(&self, r: &AuditVerificationResult) -> PortResult<()> {
        write_json(self.env, KEY_LAST_RESULT, r).await
    }
}
