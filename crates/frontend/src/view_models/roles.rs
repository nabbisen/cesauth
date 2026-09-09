//! Role view-model types.
//!
//! [`RoleView`] is the production-safe representation of a role used by
//! UI components. The workbench mock module constructs `RoleView` values
//! from its own deterministic data; the production backend constructs them
//! from the domain store.

use serde::{Deserialize, Serialize};

/// A named role with its allowed and denied permission descriptions.
/// Used by [`RoleImpactPreview`] and the roles-catalog screen.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleView {
    pub key: String,
    pub display_name: String,
    pub allowed: Vec<String>,
    pub not_allowed: Vec<String>,
}
