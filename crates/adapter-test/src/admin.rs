//! In-memory admin-console adapters.
//!
//! Backs every port from `cesauth_core::admin::ports` with a
//! `Mutex<HashMap>` or `Mutex<Vec>`. Used by host tests and by anyone
//! who wants to exercise the service layer on a plain Rust toolchain.
//!
//! One submodule per port, mirroring the cloudflare adapter's shape.

mod audit_query;
mod bucket_safety;
mod cost_snapshots;
mod metrics;
mod principal_resolver;
mod thresholds;
mod tokens;

pub use audit_query::InMemoryAuditQuerySource;
pub use bucket_safety::InMemoryBucketSafetyRepository;
pub use cost_snapshots::InMemoryCostSnapshotRepository;
pub use metrics::InMemoryUsageMetricsSource;
pub use principal_resolver::InMemoryAdminPrincipalResolver;
pub use thresholds::InMemoryThresholdRepository;
pub use tokens::InMemoryAdminTokenRepository;

#[cfg(test)]
mod tests;
