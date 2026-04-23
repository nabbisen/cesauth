//! R2-backed audit sink.
//!
//! Each call writes one NDJSON-encoded object to the `AUDIT` bucket.
//! Keys are date-partitioned so R2 lifecycle rules can age entries
//! without body inspection.
//!
//! See `cesauth_worker::audit` for the typed event layer above this.

use cesauth_core::ports::audit::{AuditRecord, AuditSink};
use cesauth_core::ports::{PortError, PortResult};
use time::OffsetDateTime;
use uuid::Uuid;
use worker::Env;

pub struct CloudflareAuditSink<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareAuditSink<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareAuditSink").finish_non_exhaustive()
    }
}

impl<'a> CloudflareAuditSink<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

impl AuditSink for CloudflareAuditSink<'_> {
    async fn write(&self, record: &AuditRecord<'_>) -> PortResult<()> {
        let bucket = self.env.bucket("AUDIT").map_err(|_| PortError::Unavailable)?;

        let now = OffsetDateTime::now_utc();
        let key = format!(
            "audit/{y:04}/{m:02}/{d:02}/{kind}-{id}.ndjson",
            y    = now.year(),
            m    = u8::from(now.month()),
            d    = now.day(),
            kind = record.kind,
            id   = Uuid::new_v4(),
        );

        // One line per object. Even though each file has only one
        // entry right now, keeping the trailing newline means we can
        // later batch events into a single object without changing the
        // format.
        let mut body = serde_json::to_vec(&record.body).map_err(|_| PortError::Serialization)?;
        body.push(b'\n');

        bucket
            .put(&key, body)
            .execute()
            .await
            .map_err(|_| PortError::Unavailable)?;
        Ok(())
    }
}
