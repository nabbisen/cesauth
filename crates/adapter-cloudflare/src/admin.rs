//! Cloudflare-backed adapters for the admin console ports.
//!
//! Each submodule implements one port trait from
//! `cesauth_core::admin::ports`. The adapters lean on D1 for everything
//! that needs durable relational queries (admin tokens, bucket safety
//! attestations, thresholds, cost snapshots) and on the R2 `AUDIT`
//! bucket for audit-log reads.
//!
//! Shared D1 helpers (`db`, `d1_int`, `run_err`) are re-used from
//! `crate::ports::repo`, which exposes them `pub(crate)` for sibling
//! modules in this crate.
//!
//! The DO-level RPC helpers (`rpc_request`, `rpc_call`) are not used
//! here: admin-console state is not a per-key serialized state machine,
//! so D1 is the right substrate.

mod audit_query;
mod bucket_safety;
mod cost_snapshots;
mod metrics;
mod principal_resolver;
mod thresholds;
mod tokens;

pub use audit_query::CloudflareAuditQuerySource;
pub use bucket_safety::CloudflareBucketSafetyRepository;
pub use cost_snapshots::CloudflareCostSnapshotRepository;
pub use metrics::CloudflareUsageMetricsSource;
pub use principal_resolver::CloudflareAdminPrincipalResolver;
pub use thresholds::CloudflareThresholdRepository;
pub use tokens::CloudflareAdminTokenRepository;
