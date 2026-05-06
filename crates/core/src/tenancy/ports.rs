//! Repository ports for the tenancy domain.
//!
//! Each trait is the minimum surface the service layer and the
//! authorization engine need. Adapter crates implement these against
//! their chosen storage (in-memory for host tests, D1 for Cloudflare).
//!
//! Delete policy: `delete` sets `status = Deleted` (soft delete); the
//! row remains for audit continuity. A background job purges after
//! retention. The 0.5.0 API exposes only soft delete; hard purge is a
//! separate port added when the retention job lands.

use crate::ports::PortResult;
use crate::types::UnixSeconds;

use super::types::{
    Group, GroupMembership, GroupParent, Organization, OrganizationMembership,
    OrganizationStatus, Tenant, TenantMembership, TenantMembershipRole, TenantStatus,
};

// ---------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------

pub trait TenantRepository {
    /// Insert a new tenant. `Conflict` on duplicate slug.
    async fn create(&self, tenant: &Tenant) -> PortResult<()>;

    async fn get(&self, id: &str) -> PortResult<Option<Tenant>>;
    async fn find_by_slug(&self, slug: &str) -> PortResult<Option<Tenant>>;

    /// List all non-deleted tenants. Pagination is intentionally
    /// omitted for 0.5.0 — the operator surface that consumes this
    /// expects O(10-100) tenants. Pagination lands with the SaaS
    /// control plane.
    async fn list_active(&self) -> PortResult<Vec<Tenant>>;

    async fn set_status(
        &self,
        id: &str,
        status: TenantStatus,
        now_unix: UnixSeconds,
    ) -> PortResult<()>;

    async fn update_display_name(
        &self,
        id: &str,
        display_name: &str,
        now_unix: UnixSeconds,
    ) -> PortResult<()>;
}

// ---------------------------------------------------------------------
// Organizations
// ---------------------------------------------------------------------

pub trait OrganizationRepository {
    async fn create(&self, org: &Organization) -> PortResult<()>;
    async fn get(&self, id: &str) -> PortResult<Option<Organization>>;
    async fn find_by_slug(&self, tenant_id: &str, slug: &str)
        -> PortResult<Option<Organization>>;

    /// Organizations inside one tenant. Active (non-deleted) only.
    async fn list_for_tenant(&self, tenant_id: &str) -> PortResult<Vec<Organization>>;

    async fn set_status(
        &self,
        id: &str,
        status: OrganizationStatus,
        now_unix: UnixSeconds,
    ) -> PortResult<()>;

    async fn update_display_name(
        &self,
        id: &str,
        display_name: &str,
        now_unix: UnixSeconds,
    ) -> PortResult<()>;
}

// ---------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------

pub trait GroupRepository {
    async fn create(&self, group: &Group) -> PortResult<()>;
    async fn get(&self, id: &str) -> PortResult<Option<Group>>;

    /// List groups whose parent is the given tenant directly.
    async fn list_tenant_scoped(&self, tenant_id: &str) -> PortResult<Vec<Group>>;

    /// List groups whose parent is the given organization.
    async fn list_for_organization(&self, org_id: &str) -> PortResult<Vec<Group>>;

    async fn delete(&self, id: &str, now_unix: UnixSeconds) -> PortResult<()>;
}

// ---------------------------------------------------------------------
// Memberships
// ---------------------------------------------------------------------

/// Relation-set between users and tenants/orgs/groups.
///
/// Grouped into one trait (rather than three) because every membership
/// query tends to need cross-table consistency — "what does user X
/// belong to in tenant Y?" — and the service layer frequently
/// needs both. A D1 adapter can still back each method with a single
/// statement; the grouping is for the caller, not the storage.
pub trait MembershipRepository {
    // --- tenant memberships ---
    async fn add_tenant_membership(&self, m: &TenantMembership) -> PortResult<()>;
    async fn remove_tenant_membership(
        &self,
        tenant_id: &str,
        user_id:   &str,
    ) -> PortResult<()>;
    async fn list_tenant_members(
        &self,
        tenant_id: &str,
    ) -> PortResult<Vec<TenantMembership>>;
    async fn list_tenants_for_user(
        &self,
        user_id: &str,
    ) -> PortResult<Vec<TenantMembership>>;

    // --- organization memberships ---
    async fn add_organization_membership(
        &self,
        m: &OrganizationMembership,
    ) -> PortResult<()>;
    async fn remove_organization_membership(
        &self,
        org_id:  &str,
        user_id: &str,
    ) -> PortResult<()>;
    async fn list_organization_members(
        &self,
        org_id: &str,
    ) -> PortResult<Vec<OrganizationMembership>>;
    async fn list_organizations_for_user(
        &self,
        user_id: &str,
    ) -> PortResult<Vec<OrganizationMembership>>;

    // --- group memberships ---
    async fn add_group_membership(&self, m: &GroupMembership) -> PortResult<()>;
    async fn remove_group_membership(
        &self,
        group_id: &str,
        user_id:  &str,
    ) -> PortResult<()>;
    async fn list_group_members(
        &self,
        group_id: &str,
    ) -> PortResult<Vec<GroupMembership>>;
    async fn list_groups_for_user(
        &self,
        user_id: &str,
    ) -> PortResult<Vec<GroupMembership>>;
}

// ---------------------------------------------------------------------
// Helpers (not a port, but co-located for discoverability)
// ---------------------------------------------------------------------

/// Shape accepted by the service's `create_group` helper. Splits the
/// caller-supplied fields from the computed ones.
#[derive(Debug, Clone)]
pub struct NewGroupInput<'a> {
    pub tenant_id:    &'a str,
    pub parent:       GroupParent,
    pub slug:         &'a str,
    pub display_name: &'a str,
}

/// Shape for `create_tenant`.
#[derive(Debug, Clone)]
pub struct NewTenantInput<'a> {
    pub slug:         &'a str,
    pub display_name: &'a str,
    /// The user who becomes the `Owner` of the new tenant. For
    /// operator-provisioned tenants this is a system-operator; for
    /// self-signup (when that lands) it's the signing-up user.
    pub owner_user_id: &'a str,
    /// Role to grant the owner in the membership row. Default is
    /// `Owner`.
    pub owner_role: TenantMembershipRole,
}
