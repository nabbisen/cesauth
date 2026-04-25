//! `/admin/saas/...` HTML console route handlers (v0.4.3).
//!
//! Read-only operator surface for the v0.4.x tenancy service state.
//! Sits parallel to the v0.3.x cost / data-safety console at
//! `/admin/console/...` — different mental model, different
//! navigation, but the same admin-bearer auth.
//!
//! Every handler resolves the bearer through
//! `crate::routes::admin::auth::resolve_or_respond`, gates on
//! `ViewTenancy` (open to every valid role), and emits HTML through
//! `cesauth_ui::saas::*` templates.
//!
//! Response shaping (CSP / cache-control / frame-deny) re-uses
//! `crate::routes::admin::console::render::html_response`; both
//! consoles want identical baseline security headers.

pub mod organizations;
pub mod overview;
pub mod role_assignments;
pub mod subscription;
pub mod tenant_detail;
pub mod tenants;
