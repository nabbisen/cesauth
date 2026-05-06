//! Tenancy operator console (v0.8.0+).
//!
//! HTML view of the v0.4.x tenancy-service state for the cesauth
//! deployment's operator staff. Sits at `/admin/tenancy/*` (the URL
//! prefix is preserved from earlier releases for operator-facing
//! stability; module + URL share the `tenancy_console` /
//! `tenancy` naming since v0.18.0), parallel to
//! (and visually distinct from) the cost / data-safety console at
//! `/admin/console/*`. The two share the admin-bearer auth model
//! but otherwise have no overlap — spec §6 is explicit about
//! keeping operator surfaces compartmentalized.
//!
//! ## What's read-only here
//!
//! Every mutation continues to go through the v0.7.0 JSON API at
//! `/api/v1/...`. This console renders the same data with operator
//! convenience: sortable tables, drill-through links, the
//! subscription history reverse-chronologically. There are no
//! `<form>` POSTs in 0.8.0 — those land in 0.9.0 with the same
//! preview/confirm pattern that 0.4.0 introduced for bucket safety.
//!
//! ## What's NOT here
//!
//! - **Tenant-scoped admins** (tenant admins administering their own
//!   tenant, as opposed to cesauth operators administering all
//!   tenants). That requires user-as-bearer auth which 0.9.0 will
//!   address.
//! - **Mutation forms / preview-confirm flow.** Same release.
//! - **Login → tenant resolution** for tenant-side users.

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
