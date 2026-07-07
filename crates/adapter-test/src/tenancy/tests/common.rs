//! Shared helpers for tenancy test submodules.
//!
//! Split out from the monolithic tests.rs in v0.78.0.

//! Integration tests for the v0.5.0 tenancy-service extension.
//!
//! These exercise the core service layer through the in-memory
//! adapters. They are intentionally located in `adapter-test` rather
//! than `cesauth-core::tenancy::tests` because they need actual port
//! implementations to compose end-to-end flows; the core-side tests
//! focus on pure-function behavior (slug rules, scope-covering
//! lattice, plan/status enums).
//!
//! What this file pins (mapping to spec §16):
//!
//!   * §16.1 data model — every type round-trips through its adapter.
//!   * §16.2 a tenant create → org → group → user → role assignment
//!     end-to-end is one test below.
//!   * §16.3 permission checks honour the scope lattice, expiry, and
//!     missing-permission cases.
//!   * §16.6 negative paths (unknown role id, dup slug, etc.).

pub(super) use cesauth_core::authz::ports::{
    PermissionRepository, RoleAssignmentRepository, RoleRepository,
};
pub(super) use cesauth_core::authz::service::check_permission;
pub(super) use cesauth_core::authz::types::{
    Permission, PermissionCatalog, Role, RoleAssignment, Scope, ScopeRef, SystemRole,
};
pub(super) use cesauth_core::billing::ports::{
    PlanRepository, SubscriptionHistoryRepository, SubscriptionRepository,
};
pub(super) use cesauth_core::billing::types::{
    Plan, PlanCatalog, PlanId, Quota, Subscription, SubscriptionHistoryEntry,
    SubscriptionLifecycle, SubscriptionStatus,
};
pub(super) use cesauth_core::ports::PortError;
pub(super) use cesauth_core::tenancy::ports::{
    MembershipRepository, NewGroupInput, NewTenantInput, TenantRepository,
};
pub(super) use cesauth_core::tenancy::service as ten;
pub(super) use cesauth_core::tenancy::types::{
    GroupParent, OrganizationRole, OrganizationStatus, TenantMembershipRole, TenantStatus,
};

pub(super) use crate::authz::{
    InMemoryPermissionRepository, InMemoryRoleAssignmentRepository, InMemoryRoleRepository,
};
pub(super) use crate::billing::{
    InMemoryPlanRepository, InMemorySubscriptionHistoryRepository, InMemorySubscriptionRepository,
};
pub(super) use crate::tenancy::{
    InMemoryGroupRepository, InMemoryMembershipRepository, InMemoryOrganizationRepository,
    InMemoryTenantRepository,
};

// ---------------------------------------------------------------------
