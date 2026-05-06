//! Tenant-scoped admin surface (introduced v0.13.0).
//!
//! Sits at `/admin/t/<slug>/...`. Each page is filtered to a single
//! tenant resolved from the URL slug. Per ADR-003, this is a
//! completely separate surface from the system-admin tenancy console
//! at `/admin/tenancy/*` — no shared chrome, no mode switch, no
//! shared auth state. The visual styling matches (so an operator who
//! switches between the two surfaces is not jarred) but every
//! decision the templates make is scoped to one tenant.
//!
//! ## What's here (v0.13.0)
//!
//! Read pages only:
//!
//! - **Overview** — the tenant's own state (status, plan, counts of
//!   organizations / users / groups for *this* tenant only).
//! - **Organizations** — list and detail.
//! - **Users** — list of users belonging to this tenant.
//! - **Role assignments** — per-user drill-in.
//! - **Subscription** — history for this tenant.
//!
//! The pages do not include mutation buttons. Form-driven mutations
//! land in 0.14.0, parallel to the v0.8.0 → v0.9.0 split for the
//! system-admin surface.
//!
//! ## What's NOT here
//!
//! - **System-admin operations.** Per ADR-003, anything that
//!   crosses the tenant boundary (suspend the tenant, change its
//!   plan, change its status) lives at `/admin/tenancy/...` and
//!   requires a system-admin token. There is intentionally no
//!   "elevate" or "switch mode" affordance.
//! - **Token-mint UI.** The `AdminTokenRepository::create_user_bound`
//!   adapter method exists in v0.13.0 (so tokens can be minted in
//!   tests and from the worker layer for bootstrap), but no HTML
//!   form exposes it yet. Lands in 0.14.0.

pub mod frame;
pub mod overview;
pub mod organizations;
pub mod users;
pub mod role_assignments;
pub mod subscription;
pub mod forms;

#[cfg(test)]
mod tests;

pub use frame::{tenant_admin_frame, TenantAdminTab};
pub use overview::{TenantOverviewCounts, overview_page};
pub use organizations::{organizations_page, organization_detail_page};
pub use users::users_page;
pub use role_assignments::{role_assignments_page, TenantUserRoleAssignmentsInput};
pub use subscription::subscription_page;
