//! Operator-console view models (RFC 034).
//!
//! The operator console is Japanese-only per ADR-013 (RFC 034 §Option JA-only).
//! All operator view models carry text that has already been resolved in
//! Japanese on the server.

use serde::{Deserialize, Serialize};

/// Locale policy for the operator shell.
/// Always `Ja` in production; the workbench may expose a dev-only override.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatorLocalePolicy {
    /// Fixed Japanese — production-safe. Enforces ADR-013.
    Ja,
    /// English preview — workbench dev-only. Must not ship in production.
    #[cfg(feature = "mockup-workbench")]
    EnDevOnly,
}

impl Default for OperatorLocalePolicy {
    fn default() -> Self {
        OperatorLocalePolicy::Ja
    }
}
