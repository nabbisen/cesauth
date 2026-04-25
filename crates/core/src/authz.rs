//! Authorization — the single decision point for "may this user do
//! this action on this scope?".
//!
//! Spec §9.2 is emphatic that permission checks must be centralized:
//! "権限判定関数を単一のモジュールに集約する。画面側や API 側での
//! 個別判定を増やしすぎない。" This module is that single point.
//!
//! # Model
//!
//! * A [`Permission`] is an atomic capability string:
//!   `"tenant:read"`, `"organization:member:add"`, etc.
//! * A [`Role`] is a named bundle of permissions.
//! * A [`RoleAssignment`] grants one user one role within one
//!   [`Scope`]. Scopes are system / tenant / organization / group /
//!   user (§9.1).
//! * [`check_permission`] folds all of that: given the caller, the
//!   wanted permission, and the wanted scope, either return Allowed
//!   or explain why Denied.
//!
//! # What's NOT here
//!
//! * Identity resolution (who is the caller?). That's in the worker
//!   middleware layer.
//! * Side effects (audit writes). The caller audits; this module is
//!   a pure function over port reads.
//! * Plan-based feature flags. That's `crate::billing`.

pub mod ports;
pub mod service;
pub mod types;

pub use ports::{PermissionRepository, RoleAssignmentRepository, RoleRepository};
pub use service::{check_permission, CheckOutcome, DenyReason};
pub use types::{
    Permission, PermissionCatalog, Role, RoleAssignment, Scope,
    ScopeRef, SystemRole,
};

#[cfg(test)]
mod tests;
