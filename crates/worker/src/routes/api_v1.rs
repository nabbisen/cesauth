//! Tenancy-service API routes (v0.7.0).
//!
//! These routes wire the v0.5.0/0.6.0 service layer + adapters to a
//! JSON HTTP surface under `/api/v1/`. Authentication is the same
//! admin-bearer mechanism the 0.3.x admin console uses; gating is
//! through the new [`AdminAction::ViewTenancy`] /
//! [`AdminAction::ManageTenancy`] capabilities.
//!
//! ## Why admin-bearer and not user-as-bearer
//!
//! The spec's `check_permission` expects a `user_id` and a scope.
//! cesauth's admin tokens are operator credentials that do not
//! correspond to rows in `users`, and the user-as-bearer path
//! (issuing a JWT/session bearer that the gateway parses into a
//! tenant-scoped request) hasn't landed yet — that work is part of
//! the multi-tenant admin console (0.8.0). So 0.7.0 ships an API
//! surface that the cesauth deployment's *operator staff* uses to
//! provision tenants, and defers self-service tenant operations.
//!
//! The route handlers therefore go through `ensure_role_allows` (an
//! admin-side capability) rather than `check_permission` (a tenancy-
//! side capability). The two converge in 0.8.0+ when we mint user
//! bearers and route them through the same handlers.
//!
//! ## URL shape
//!
//! ```text
//! POST   /api/v1/tenants
//! GET    /api/v1/tenants
//! GET    /api/v1/tenants/:tid
//! PATCH  /api/v1/tenants/:tid                   { display_name? }
//! POST   /api/v1/tenants/:tid/status            { status }
//!
//! POST   /api/v1/tenants/:tid/organizations     { slug, display_name }
//! GET    /api/v1/tenants/:tid/organizations
//! GET    /api/v1/tenants/:tid/organizations/:oid
//!
//! POST   /api/v1/tenants/:tid/groups            { parent_kind, organization_id?, slug, display_name }
//! GET    /api/v1/tenants/:tid/groups            ?organization_id=...
//!
//! POST   /api/v1/tenants/:tid/memberships       { user_id, role }
//! POST   /api/v1/organizations/:oid/memberships { user_id, role }
//! POST   /api/v1/groups/:gid/memberships        { user_id }
//!
//! POST   /api/v1/role_assignments               { user_id, role_id, scope, expires_at? }
//! DELETE /api/v1/role_assignments/:id
//!
//! GET    /api/v1/tenants/:tid/subscription
//! POST   /api/v1/tenants/:tid/subscription/plan { plan_id }
//! POST   /api/v1/tenants/:tid/subscription/status { status }
//! ```
//!
//! Quota enforcement is wired into the user-create / org-create /
//! group-create paths — see `enforce_quota` below.

pub mod anonymous;
pub mod auth;
pub mod groups;
pub mod memberships;
pub mod organizations;
pub mod quota;
pub mod role_assignments;
pub mod subscriptions;
pub mod tenants;
