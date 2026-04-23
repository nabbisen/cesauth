//! Append-only audit sink.
//!
//! This trait maps to R2 in the Cloudflare adapter. The method is
//! intentionally fire-and-forget from the caller's perspective: it
//! returns `PortResult<()>`, but the worker layer's convention is to
//! log failures and continue. A failed audit write must never take
//! down an authentication request (see spec §6.5 and the
//! `cesauth-worker::audit` docs).

use super::PortResult;
use serde::Serialize;

/// Opaque event payload. Adapters are expected to NDJSON-encode the
/// `serde_json::Value` body and append a single record.
///
/// The trait holds the minimum shape that matters to core: a *kind*
/// tag (for partitioning / classification) and a JSON body. Anything
/// richer - per-event typed fields - is shaped in `cesauth-worker`'s
/// `audit::Event` and serialized into the JSON body here.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord<'a> {
    pub kind: &'a str,
    pub body: serde_json::Value,
}

pub trait AuditSink {
    async fn write(&self, record: &AuditRecord<'_>) -> PortResult<()>;
}
