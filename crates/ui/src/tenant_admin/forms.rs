//! Mutation forms for the tenant-scoped admin surface
//! (introduced v0.14.0).
//!
//! Mirrors the v0.9.0 system-admin tenancy_console forms but
//! scoped to one tenant and gated through `check_permission` per
//! ADR-002 + ADR-003. The risk-graded preview/confirm pattern is
//! preserved verbatim — additive operations submit in one click,
//! destructive operations re-render with a diff and a separate
//! Apply button.
//!
//! Forms in 0.14.0 (high-risk first, mirroring v0.9.0):
//!
//! - `organization_create` — additive, one-click submit
//! - `organization_set_status` — preview/confirm
//! - `group_create` — additive, one-click
//! - `group_delete` — preview/confirm
//! - `role_assignment_grant` — preview/confirm (role + scope changes)
//! - `role_assignment_revoke` — preview/confirm
//!
//! Membership add/remove forms (additive, low-risk) are deferred to
//! 0.15.0 — same pattern as v0.9.0 → v0.10.0.

pub mod organization_create;
pub mod organization_set_status;
pub mod group_create;
pub mod group_delete;
pub mod role_assignment_grant;
pub mod role_assignment_revoke;
