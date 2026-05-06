//! Tenancy operator console (introduced v0.8.0, current as of v0.32.0).
//!
//! HTML view of the v0.4.x tenancy-service state for the cesauth
//! deployment's operator staff. Sits at `/admin/tenancy/*`, parallel
//! to (and visually distinct from) the cost / data-safety console at
//! `/admin/console/*`. The two share the admin-bearer auth model
//! but otherwise have no overlap — spec §6 is explicit about
//! keeping operator surfaces compartmentalized.
//!
//! ## What's here
//!
//! - **Read pages** (added in 0.8.0): overview, tenants list, tenant
//!   detail, organization detail, subscription history, user role
//!   assignments. Every read route is open to `ViewTenancy`, which
//!   every authenticated role has.
//! - **Mutation forms** (added in 0.9.0): tenant / organization /
//!   group create + status, group delete, subscription set-plan +
//!   set-status. Risk-graded preview/confirm — additive operations
//!   submit in one click, destructive operations re-render with a
//!   diff and a separate Apply button.
//! - **Membership and role-assignment forms** (added in 0.10.0):
//!   three flavors of membership add/remove plus role-assignment
//!   grant/revoke. Reachable from affordance buttons on the
//!   tenant / organization / user pages.
//!
//! ## What's NOT here
//!
//! - **Tenant-scoped admins** — tenant admins administering their
//!   own tenant rather than the cesauth operator administering all
//!   tenants. The 0.11.0 foundation
//!   (`AdminPrincipal::user_id`, the `admin_tokens.user_id` column)
//!   is in place; the surface itself lands in v0.13.0 at
//!   `/admin/t/<slug>/...` per ADR-001.
//! - **`check_permission` integration** — the routes here gate on
//!   `AdminAction::ManageTenancy` (admin-side capability). The
//!   tenant-scoped surface in 0.13.0 will use `check_permission`
//!   instead, since it has the user_id needed to feed the
//!   spec §9.2 scope walk.
//!
//! ## Naming history
//!
//! This module was named `saas` from its v0.8.0 introduction
//! through v0.11.0. v0.12.0 renamed it to `tenancy_console` (and the
//! URL prefix from `/admin/saas/*` to `/admin/tenancy/*`) to drop
//! marketing-flavored framing in favor of a name that describes
//! what the code does.

pub mod forms;
pub mod frame;
pub mod overview;
pub mod organizations;
pub mod role_assignments;
pub mod subscription;
pub mod tenant_detail;
pub mod tenants;

pub use frame::TenancyConsoleTab;
pub use organizations::organization_detail_page;
pub use overview::overview_page as tenancy_console_overview_page;
pub use role_assignments::user_role_assignments_page;
pub use subscription::subscription_history_page;
pub use tenant_detail::tenant_detail_page;
pub use tenants::tenants_page;

#[cfg(test)]
mod tests;
