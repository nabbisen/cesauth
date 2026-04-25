//! Multi-tenancy domain model (v0.4.0).
//!
//! This module implements the top-level boundary concepts from the
//! tenancy service extension spec §3:
//!
//!   * [`Tenant`] — the outermost logical boundary. Every piece of
//!     user-facing data that is not a shared catalog (plans, system
//!     roles) lives inside one tenant.
//!   * [`Organization`] — a business unit *within* a tenant.
//!     Departments, customer sub-accounts, operational teams. An org
//!     belongs to exactly one tenant.
//!   * [`Group`] — a logical unit used for both membership and
//!     authorization. A group lives either directly under a tenant or
//!     under an org (see [`GroupParent`]).
//!
//! Memberships (a user belonging to a tenant / org / group) are
//! **relations**, not attributes. They live in their own tables and
//! are manipulated through explicit service calls, never by setting a
//! field on `User`. This matches spec §2 principle 4 ("所属は属性で
//! はなく関係として表現する").
//!
//! The spec is deliberate about separating concerns: `tenancy` covers
//! who-is-in-what; [`crate::authz`] covers what-can-they-do;
//! [`crate::billing`] covers what-does-the-tenant-pay-for. Those three
//! modules form the tenancy service together.
//!
//! # What's in 0.4.0
//!
//! Types, repository ports, and in-memory/D1 adapter implementations.
//! HTTP routes for CRUD and the migration of existing tables to
//! become tenant-aware are deferred to 0.4.1; today every existing
//! row belongs to the `DEFAULT_TENANT_ID` by convention (see the
//! migration 0003_tenancy.sql).

pub mod ports;
pub mod service;
pub mod types;

pub use ports::{
    GroupRepository, MembershipRepository, OrganizationRepository, TenantRepository,
};
pub use types::{
    AccountType, DEFAULT_TENANT_ID, Group, GroupMembership, GroupParent, GroupStatus,
    Organization, OrganizationMembership, OrganizationStatus, OrganizationRole, Tenant,
    TenantMembership, TenantMembershipRole, TenantStatus,
};

#[cfg(test)]
mod tests;
