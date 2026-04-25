//! SaaS operator console (v0.4.3).
//!
//! Read-only HTML view of the v0.4.x tenancy service state for the
//! cesauth deployment's operator staff. Sits at `/admin/saas/*`,
//! parallel to (and visually distinct from) the cost / data-safety
//! console at `/admin/console/*`. The two share the admin-bearer
//! auth model but otherwise have no overlap — spec §6 is explicit
//! about keeping operator surfaces compartmentalized.
//!
//! ## What's read-only here
//!
//! Every mutation continues to go through the v0.4.2 JSON API at
//! `/api/v1/...`. This console renders the same data with operator
//! convenience: sortable tables, drill-through links, the
//! subscription history reverse-chronologically. There are no
//! `<form>` POSTs in 0.4.3 — those land in 0.4.4 with the same
//! preview/confirm pattern that 0.3.1 introduced for bucket safety.
//!
//! ## What's NOT here
//!
//! - **Tenant-scoped admins** (tenant admins administering their own
//!   tenant, as opposed to cesauth operators administering all
//!   tenants). That requires user-as-bearer auth which 0.4.4 will
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

pub use frame::SaasTab;
pub use organizations::organization_detail_page;
pub use overview::overview_page as saas_overview_page;
pub use role_assignments::user_role_assignments_page;
pub use subscription::subscription_history_page;
pub use tenant_detail::tenant_detail_page;
pub use tenants::tenants_page;

#[cfg(test)]
mod tests;
