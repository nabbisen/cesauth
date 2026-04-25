//! Tenancy service layer.
//!
//! Each function here takes the ports it needs, composes them into
//! one business operation, and returns a typed result. The service
//! layer is where transaction-shape decisions live: "create a tenant
//! and its owner membership atomically" is one call here, even though
//! the two rows land in two tables.
//!
//! The layer is port-generic, not Cloudflare-specific — it is
//! unit-testable against the in-memory adapters.

use crate::ports::{PortError, PortResult};
use crate::types::UnixSeconds;
use uuid::Uuid;

use super::ports::{
    MembershipRepository, NewGroupInput, NewTenantInput, OrganizationRepository,
    GroupRepository, TenantRepository,
};
use super::types::{
    Group, GroupMembership, GroupStatus, Organization, OrganizationMembership,
    OrganizationRole, OrganizationStatus, Tenant, TenantMembership, TenantStatus,
};

/// Create a tenant plus its owner membership as one operation.
///
/// The new tenant is written first; if that fails, the membership is
/// never written. If the tenant-write succeeds but the membership
/// write fails, the tenant row is left in place (the caller can
/// retry the membership). This mirrors how D1 batch semantics
/// behave: no multi-row transactionality, idempotent retry instead.
pub async fn create_tenant<T, M>(
    tenants:     &T,
    memberships: &M,
    input:       &NewTenantInput<'_>,
    now_unix:    UnixSeconds,
) -> PortResult<Tenant>
where
    T: TenantRepository,
    M: MembershipRepository,
{
    validate_slug(input.slug)?;
    let tenant = Tenant {
        id:           Uuid::new_v4().to_string(),
        slug:         input.slug.to_owned(),
        display_name: input.display_name.to_owned(),
        status:       TenantStatus::Active,
        created_at:   now_unix,
        updated_at:   now_unix,
    };
    tenants.create(&tenant).await?;

    memberships.add_tenant_membership(&TenantMembership {
        tenant_id: tenant.id.clone(),
        user_id:   input.owner_user_id.to_owned(),
        role:      input.owner_role,
        joined_at: now_unix,
    }).await?;

    Ok(tenant)
}

/// Add a user to an existing tenant with the given membership role.
///
/// Returns `Conflict` if the user is already a member of the tenant.
pub async fn add_user_to_tenant<M: MembershipRepository>(
    memberships: &M,
    m:           &TenantMembership,
) -> PortResult<()> {
    memberships.add_tenant_membership(m).await
}

/// Create an organization inside a tenant. The tenant must exist and
/// be active; we check here rather than trusting the caller, because
/// a dangling `tenant_id` in an org row is hard to diagnose later.
pub async fn create_organization<T, O>(
    tenants: &T,
    orgs:    &O,
    tenant_id:    &str,
    slug:         &str,
    display_name: &str,
    now_unix:     UnixSeconds,
) -> PortResult<Organization>
where
    T: TenantRepository,
    O: OrganizationRepository,
{
    validate_slug(slug)?;
    match tenants.get(tenant_id).await? {
        Some(t) if matches!(t.status, TenantStatus::Active)  => {}
        Some(_) => return Err(PortError::Conflict),  // suspended/deleted/pending
        None    => return Err(PortError::NotFound),
    }

    let org = Organization {
        id:                    Uuid::new_v4().to_string(),
        tenant_id:             tenant_id.to_owned(),
        slug:                  slug.to_owned(),
        display_name:          display_name.to_owned(),
        status:                OrganizationStatus::Active,
        parent_organization_id: None,
        created_at:            now_unix,
        updated_at:            now_unix,
    };
    orgs.create(&org).await?;
    Ok(org)
}

/// Add a user to an organization.
///
/// The caller is expected to have already confirmed the user is a
/// tenant member; the service does NOT enforce that here because
/// "must be tenant member first" is an authorization decision, not a
/// data-integrity one.
pub async fn add_user_to_organization<M: MembershipRepository>(
    memberships: &M,
    org_id:      &str,
    user_id:     &str,
    role:        OrganizationRole,
    now_unix:    UnixSeconds,
) -> PortResult<()> {
    memberships.add_organization_membership(&OrganizationMembership {
        organization_id: org_id.to_owned(),
        user_id:         user_id.to_owned(),
        role,
        joined_at:       now_unix,
    }).await
}

/// Create a group under a tenant or organization.
pub async fn create_group<G>(
    groups: &G,
    input:  &NewGroupInput<'_>,
    now_unix: UnixSeconds,
) -> PortResult<Group>
where
    G: GroupRepository,
{
    validate_slug(input.slug)?;
    let group = Group {
        id:                Uuid::new_v4().to_string(),
        tenant_id:         input.tenant_id.to_owned(),
        parent:            input.parent.clone(),
        slug:              input.slug.to_owned(),
        display_name:      input.display_name.to_owned(),
        status:            GroupStatus::Active,
        parent_group_id:   None,
        created_at:        now_unix,
        updated_at:        now_unix,
    };
    groups.create(&group).await?;
    Ok(group)
}

/// Add a user to a group.
pub async fn add_user_to_group<M: MembershipRepository>(
    memberships: &M,
    group_id:    &str,
    user_id:     &str,
    now_unix:    UnixSeconds,
) -> PortResult<()> {
    memberships.add_group_membership(&GroupMembership {
        group_id:  group_id.to_owned(),
        user_id:   user_id.to_owned(),
        joined_at: now_unix,
    }).await
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Slugs are lowercase ASCII, hyphen-separated, 1-63 chars. Reject
/// early so bad data never reaches D1's CHECK constraint and surfaces
/// as a generic "constraint failed".
fn validate_slug(s: &str) -> PortResult<()> {
    if s.is_empty() || s.len() > 63 {
        return Err(PortError::PreconditionFailed("slug length must be 1..=63"));
    }
    if !s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        return Err(PortError::PreconditionFailed("slug must be [a-z0-9-]"));
    }
    // No leading/trailing hyphen.
    if s.starts_with('-') || s.ends_with('-') {
        return Err(PortError::PreconditionFailed("slug must not start/end with '-'"));
    }
    Ok(())
}
