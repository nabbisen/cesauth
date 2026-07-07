//! Worker-side routing for the tenant-scoped admin surface
//! (`/admin/t/<slug>/...`). Introduced v0.13.0.
//!
//! Each handler runs through the same opening sequence:
//!
//! 1. **Resolve the bearer token to an `AdminPrincipal`** via the
//!    existing `auth::resolve_or_respond`.
//! 2. **Run the tenant-admin auth gate**
//!    ([`gate::resolve_or_respond`]) — checks that the principal is
//!    user-bound (ADR-002), the URL slug resolves to a tenant, and
//!    the principal's user belongs to that tenant. Returns a typed
//!    `TenantAdminContext` on success.
//! 3. **Action-level authorization** via
//!    `cesauth_core::authz::check_permission` against the resolved
//!    user_id (the principal carries it now per the v0.11.0
//!    foundation). The system-admin surface continues to use
//!    `auth::ensure_role_allows`; the tenant-scoped surface uses
//!    `check_permission` per ADR-003.
//!
//! 0.13.0 ships read pages only. Mutation forms land in 0.14.0 with
//! the same per-route gate composition.

pub mod gate;
pub mod overview;
pub mod organizations;
pub mod organization_detail;
pub mod users;
pub mod role_assignments;
pub mod subscription;
pub mod forms;
