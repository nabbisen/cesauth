//! Originally part of `crates/adapter-test/src/tenancy/tests.rs`.
//! Split into a sibling file in v0.78.0 (test-file modularization track).

use super::super::*;     // reaches `tenancy` (the module under test)
#[allow(unused_imports)]
use super::common::*;    // shared fixtures

// RFC 058 — Tenant onboarding E2E scenario tests (SaaS guide §16.2, §16.6)
// =========================================================================
//
// These tests exercise the complete tenant-provisioning lifecycle that the
// acceptance criteria require (§16.2):
//   "テナント作成からユーザー所属、ロール付与まで一連の操作が可能である"
//
// They combine multiple service layers (tenancy + authz + billing) to
// demonstrate the full onboarding path from a freshly-created tenant all
// the way to enforcing access control on a real API operation.

/// §16.2: Full onboarding flow — create tenant → add user → grant role →
///        verify access control enforces the granted permission.
#[tokio::test]
async fn full_onboarding_create_tenant_grant_role_check_permission() {
    let tenants  = InMemoryTenantRepository::default();
    let orgs     = InMemoryOrganizationRepository::default();
    let members  = InMemoryMembershipRepository::default();
    let roles    = InMemoryRoleRepository::default();
    let asgs     = InMemoryRoleAssignmentRepository::default();
    let now = 1_700_000_000i64;

    // 1. Create tenant with owner.
    let tenant = ten::create_tenant(&tenants, &members, &NewTenantInput {
        slug: "onboard-co", display_name: "Onboard Co",
        owner_user_id: "u-admin", owner_role: TenantMembershipRole::Owner,
    }, now).await.unwrap();

    // 2. Add a regular user to the tenant.
    ten::add_user_to_tenant(&members, &cesauth_core::tenancy::types::TenantMembership {
        tenant_id: tenant.id.clone(),
        user_id:   "u-member".to_owned(),
        role:      TenantMembershipRole::Member,
        joined_at: now + 10,
    }).await.unwrap();

    let tenant_members = members.list_tenant_members(&tenant.id).await.unwrap();
    assert_eq!(tenant_members.len(), 2, "admin + member");

    // 3. Create a tenant_admin role and grant it to the admin user.
    roles.create(&cesauth_core::authz::types::Role {
        id:           "r-tadmin".to_owned(),
        slug:         "tenant_admin".to_owned(),
        tenant_id:    Some(tenant.id.clone()),
        display_name: "Tenant Admin".to_owned(),
        permissions:  vec![
            cesauth_core::authz::types::Permission::new(PermissionCatalog::TENANT_READ),
            cesauth_core::authz::types::Permission::new(PermissionCatalog::USER_READ),
            cesauth_core::authz::types::Permission::new(PermissionCatalog::ORGANIZATION_CREATE),
        ],
        created_at:   now,
        updated_at:   now,
    }).await.unwrap();

    asgs.create(&RoleAssignment {
        id:         "ra-1".to_owned(),
        user_id:    "u-admin".to_owned(),
        role_id:    "r-tadmin".to_owned(),
        scope:      Scope::Tenant { tenant_id: tenant.id.clone() },
        granted_by: "system".to_owned(),
        granted_at: now,
        expires_at: None,
    }).await.unwrap();

    // 4. Verify access control: admin can read the tenant.
    let outcome = check_permission(
        &asgs, &roles, "u-admin",
        PermissionCatalog::TENANT_READ,
        ScopeRef::Tenant { tenant_id: &tenant.id },
        now + 100,
    ).await.unwrap();
    assert!(outcome.is_allowed(), "tenant admin must be able to read tenant");

    // 5. Regular member has no role assignment → denied.
    let member_outcome = check_permission(
        &asgs, &roles, "u-member",
        PermissionCatalog::TENANT_READ,
        ScopeRef::Tenant { tenant_id: &tenant.id },
        now + 100,
    ).await.unwrap();
    assert!(!member_outcome.is_allowed(), "member without role must be denied tenant_read");
}

/// §16.2: Organization + group creation within onboarding.
#[tokio::test]
async fn onboarding_org_and_group_creation() {
    use cesauth_core::tenancy::ports::OrganizationRepository;
    let tenants  = InMemoryTenantRepository::default();
    let orgs     = InMemoryOrganizationRepository::default();
    let groups   = InMemoryGroupRepository::default();
    let members  = InMemoryMembershipRepository::default();
    let now = 1_700_000_000i64;

    let tenant = ten::create_tenant(&tenants, &members, &NewTenantInput {
        slug: "multi-org", display_name: "Multi Org Co",
        owner_user_id: "u-owner", owner_role: TenantMembershipRole::Owner,
    }, now).await.unwrap();

    // Create two organizations.
    let eng = ten::create_organization(&tenants, &orgs, &tenant.id, "eng", "Engineering", now + 10).await.unwrap();
    let ops = ten::create_organization(&tenants, &orgs, &tenant.id, "ops", "Operations", now + 20).await.unwrap();

    let org_list = orgs.list_for_tenant(&tenant.id).await.unwrap();
    assert_eq!(org_list.len(), 2, "tenant should have 2 organizations");

    // Create a group in eng.
    let grp = ten::create_group(&groups, &NewGroupInput {
        tenant_id: &tenant.id,
        parent: GroupParent::Organization { organization_id: eng.id.clone() },
        slug: "backend",
        display_name: "Backend Team",
        organization_tenant_id: Some(&tenant.id),
    }, now + 30).await.unwrap();

    // Add user to org and group.
    ten::add_user_to_organization(&members, &eng.id, "u-dev", OrganizationRole::Member, now + 40).await.unwrap();
    ten::add_user_to_group(&members, &grp.id, "u-dev", now + 50).await.unwrap();

    let dev_orgs   = members.list_organizations_for_user("u-dev").await.unwrap();
    let dev_groups = members.list_groups_for_user("u-dev").await.unwrap();
    assert_eq!(dev_orgs.len(), 1);
    assert_eq!(dev_groups.len(), 1);

    // ops org is separate — u-dev has no membership there.
    let ops_members = members.list_organization_members(&ops.id).await.unwrap();
    assert!(ops_members.is_empty(), "ops org should have no members");
}

/// §16.4: Logical deletion policy — soft-deleted tenant's data is preserved.
#[tokio::test]
async fn soft_deleted_tenant_status_reflects_correctly() {
    use cesauth_core::tenancy::service::{create_tenant, soft_delete_tenant};

    let tenants  = InMemoryTenantRepository::default();
    let members  = InMemoryMembershipRepository::default();
    let now = 1_700_000_000i64;

    let tenant = create_tenant(&tenants, &members, &NewTenantInput {
        slug: "to-delete", display_name: "To Delete",
        owner_user_id: "u-1", owner_role: TenantMembershipRole::Owner,
    }, now).await.unwrap();

    // Soft delete.
    soft_delete_tenant(&tenants, &tenant.id, now + 100).await.unwrap();

    // Row persists (for audit trail).
    let still_exists = tenants.get(&tenant.id).await.unwrap();
    assert!(still_exists.is_some(), "soft-deleted tenant row must persist");
    assert_eq!(still_exists.unwrap().status, TenantStatus::Deleted);

    // Active list excludes it.
    let active = tenants.list_active().await.unwrap();
    assert!(active.iter().all(|t| t.id != tenant.id),
        "deleted tenant must not appear in list_active");
}

/// §16.6: Negative paths — duplicate slug, cross-tenant group, expired role.
#[tokio::test]
async fn negative_paths_duplicate_and_cross_tenant() {
    let tenants  = InMemoryTenantRepository::default();
    let orgs     = InMemoryOrganizationRepository::default();
    let members  = InMemoryMembershipRepository::default();
    let now = 1_700_000_000i64;

    // Create two tenants.
    let t1 = ten::create_tenant(&tenants, &members, &NewTenantInput {
        slug: "t-one", display_name: "T1",
        owner_user_id: "u-a", owner_role: TenantMembershipRole::Owner,
    }, now).await.unwrap();

    let t2 = ten::create_tenant(&tenants, &members, &NewTenantInput {
        slug: "t-two", display_name: "T2",
        owner_user_id: "u-b", owner_role: TenantMembershipRole::Owner,
    }, now).await.unwrap();

    // Duplicate slug within a tenant → conflict.
    ten::create_organization(&tenants, &orgs, &t1.id, "eng", "Engineering", now).await.unwrap();
    let dup_result = ten::create_organization(&tenants, &orgs, &t1.id, "eng", "Duplicate", now).await;
    assert!(matches!(dup_result, Err(PortError::Conflict)),
        "duplicate org slug in same tenant must return Conflict");

    // Same slug in t2 is fine (tenant-scoped).
    let ok = ten::create_organization(&tenants, &orgs, &t2.id, "eng", "Eng in T2", now).await;
    assert!(ok.is_ok(), "same slug is allowed in a different tenant");
}

/// §16.6: Expired role assignment is denied.
#[tokio::test]
async fn expired_role_assignment_is_denied() {
    let roles = InMemoryRoleRepository::default();
    let asgs  = InMemoryRoleAssignmentRepository::default();
    let now = 1_700_000_000i64;

    roles.create(&cesauth_core::authz::types::Role {
        id: "r-exp".to_owned(), slug: "r".to_owned(), tenant_id: None,
        display_name: "R".to_owned(),
        permissions: vec![cesauth_core::authz::types::Permission::new(PermissionCatalog::TENANT_READ)],
        created_at: 0, updated_at: 0,
    }).await.unwrap();

    asgs.create(&RoleAssignment {
        id: "ra-exp".to_owned(), user_id: "u-x".to_owned(), role_id: "r-exp".to_owned(),
        scope: Scope::System,
        granted_by: "system".to_owned(), granted_at: now,
        expires_at: Some(now + 60),   // expires after 60 seconds
    }).await.unwrap();

    // Before expiry: allowed.
    let before = check_permission(
        &asgs, &roles, "u-x",
        PermissionCatalog::TENANT_READ,
        ScopeRef::System,
        now + 59,
    ).await.unwrap();
    assert!(before.is_allowed(), "valid assignment must be allowed before expiry");

    // After expiry: denied.
    let after = check_permission(
        &asgs, &roles, "u-x",
        PermissionCatalog::TENANT_READ,
        ScopeRef::System,
        now + 61,
    ).await.unwrap();
    assert!(!after.is_allowed(), "expired assignment must be denied");
}
