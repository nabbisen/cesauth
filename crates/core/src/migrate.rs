//! Data-migration dump format (introduced v0.19.0, ADR-005).
//!
//! ## v0.52.1 (RFC 012) — module split
//!
//! The original 2568-line monolith was split into focused submodules.
//! Public API is unchanged — all types are re-exported from this facade.
//!
//! | Submodule | Contents |
//! |---|---|
//! | `error` | `MigrateError`, `RedactionError`, `MigrateResult` |
//! | `types` | `Manifest`, `TableSummary`, `PayloadLine`, `FORMAT_VERSION`, `SCHEMA_VERSION` |
//! | `redaction` | `RedactionProfile`, `RedactionRule`, `RedactionKind`, helpers |
//! | `export` | `ExportSpec`, `ExportSigner`, `Exporter` |
//! | `verify` | `VerifyReport`, `verify` |
//! | `invariants` | `Violation`, `ViolationReport`, `SeenSnapshot`, `InvariantCheckFn`, `default_invariant_checks`, `import` |
//! | `import` | `ImportSink` |

pub mod error;
pub mod export;
pub mod import;
pub mod invariants;
pub mod redaction;
pub mod types;
pub mod verify;

pub use error::*;
pub use export::*;
pub use import::*;
pub use invariants::*;
pub use redaction::*;
pub use types::*;
pub use verify::{VerifyReport, verify as verify_dump};
/// Re-export under the original name for backward compat.
pub use verify::verify;

#[cfg(test)]
mod tests;
