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

use cesauth_core::authz::ports::{
    PermissionRepository, RoleAssignmentRepository, RoleRepository,
};
use cesauth_core::authz::service::check_permission;
use cesauth_core::authz::types::{
    Permission, PermissionCatalog, Role, RoleAssignment, Scope, ScopeRef, SystemRole,
};
use cesauth_core::billing::ports::{
    PlanRepository, SubscriptionHistoryRepository, SubscriptionRepository,
};
use cesauth_core::billing::types::{
    Plan, PlanCatalog, PlanId, Quota, Subscription, SubscriptionHistoryEntry,
    SubscriptionLifecycle, SubscriptionStatus,
};
use cesauth_core::ports::PortError;
use cesauth_core::tenancy::ports::{
    MembershipRepository, NewGroupInput, NewTenantInput, TenantRepository,
};
use cesauth_core::tenancy::service as ten;
use cesauth_core::tenancy::types::{
    GroupParent, OrganizationRole, OrganizationStatus, TenantMembershipRole, TenantStatus,
};

use crate::authz::{
    InMemoryPermissionRepository, InMemoryRoleAssignmentRepository, InMemoryRoleRepository,
};
use crate::billing::{
    InMemoryPlanRepository, InMemorySubscriptionHistoryRepository, InMemorySubscriptionRepository,
};
use crate::tenancy::{
    InMemoryGroupRepository, InMemoryMembershipRepository, InMemoryOrganizationRepository,
    InMemoryTenantRepository,
};

// ---------------------------------------------------------------------
// §16.1, §16.2 — end-to-end tenant → org → group → user
// ---------------------------------------------------------------------

#[tokio::test]
async fn end_to_end_tenant_org_group_membership() {
    let tenants  = InMemoryTenantRepository::default();
    let orgs     = InMemoryOrganizationRepository::default();
    let groups   = InMemoryGroupRepository::default();
    let members  = InMemoryMembershipRepository::default();

    // Create the tenant + owner membership.
    let tenant = ten::create_tenant(&tenants, &members, &NewTenantInput {
        slug: "acme",
        display_name: "Acme Corp",
        owner_user_id: "u-alice",
        owner_role: TenantMembershipRole::Owner,
    }, 1000).await.unwrap();
    assert_eq!(tenant.slug, "acme");
    assert_eq!(tenant.status, TenantStatus::Active);

    // Owner membership exists.
    let owners = members.list_tenant_members(&tenant.id).await.unwrap();
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].user_id, "u-alice");
    assert_eq!(owners[0].role, TenantMembershipRole::Owner);

    // Create an org.
    let eng = ten::create_organization(
        &tenants, &orgs, &tenant.id, "engineering", "Engineering", 1100,
    ).await.unwrap();
    assert_eq!(eng.tenant_id, tenant.id);
    assert_eq!(eng.status, OrganizationStatus::Active);

    // Add Bob to the org.
    ten::add_user_to_organization(
        &members, &eng.id, "u-bob", OrganizationRole::Member, 1200,
    ).await.unwrap();
    let org_members = members.list_organization_members(&eng.id).await.unwrap();
    assert_eq!(org_members.len(), 1);
    assert_eq!(org_members[0].user_id, "u-bob");

    // Create a group under the org.
    let oncall = ten::create_group(&groups, &NewGroupInput {
        tenant_id: &tenant.id,
        parent: GroupParent::Organization { organization_id: eng.id.clone() },
        slug: "oncall",
        display_name: "Engineering On-call",
        organization_tenant_id: Some(&tenant.id),
    }, 1300).await.unwrap();
    assert_eq!(oncall.parent.organization_id(), Some(eng.id.as_str()));

    // Add Bob to the group.
    ten::add_user_to_group(&members, &oncall.id, "u-bob", 1400).await.unwrap();
    let g_for_bob = members.list_groups_for_user("u-bob").await.unwrap();
    assert_eq!(g_for_bob.len(), 1);
}

#[tokio::test]
async fn create_tenant_rejects_invalid_slug() {
    let tenants = InMemoryTenantRepository::default();
    let members = InMemoryMembershipRepository::default();

    let too_long = "a".repeat(64);
    let bad_slugs: &[&str] = &[
        "", "Acme", "acme!", "-acme", "acme-",
        too_long.as_str(),
        "with space",
    ];
    for bad in bad_slugs {
        let r = ten::create_tenant(&tenants, &members, &NewTenantInput {
            slug: bad,
            display_name: "x",
            owner_user_id: "u",
            owner_role: TenantMembershipRole::Owner,
        }, 0).await;
        assert!(matches!(r, Err(PortError::PreconditionFailed(_))),
            "slug {bad:?} must reject as PreconditionFailed, got {r:?}");
    }
}

#[tokio::test]
async fn create_tenant_rejects_duplicate_slug() {
    let tenants = InMemoryTenantRepository::default();
    let members = InMemoryMembershipRepository::default();
    let input = NewTenantInput {
        slug: "acme", display_name: "Acme",
        owner_user_id: "u", owner_role: TenantMembershipRole::Owner,
    };
    ten::create_tenant(&tenants, &members, &input, 0).await.unwrap();
    let err = ten::create_tenant(&tenants, &members, &input, 1).await.unwrap_err();
    assert!(matches!(err, PortError::Conflict));
}

#[tokio::test]
async fn create_organization_in_suspended_tenant_is_rejected() {
    let tenants = InMemoryTenantRepository::default();
    let orgs    = InMemoryOrganizationRepository::default();
    let members = InMemoryMembershipRepository::default();

    let t = ten::create_tenant(&tenants, &members, &NewTenantInput {
        slug: "acme", display_name: "Acme",
        owner_user_id: "u", owner_role: TenantMembershipRole::Owner,
    }, 0).await.unwrap();
    tenants.set_status(&t.id, TenantStatus::Suspended, 100).await.unwrap();

    let r = ten::create_organization(&tenants, &orgs, &t.id, "eng", "Eng", 200).await;
    assert!(matches!(r, Err(PortError::Conflict)),
        "creating an org in a suspended tenant must fail; got {r:?}");
}

// ---------------------------------------------------------------------
// §16.3 — permission checks at full lattice
// ---------------------------------------------------------------------

/// Helper: seed the standard system roles into a roles repo.
async fn seed_system_roles(roles: &InMemoryRoleRepository) {
    roles.create(&Role {
        id: "role-system-admin".into(), tenant_id: None,
        slug: SystemRole::SYSTEM_ADMIN.into(),
        display_name: "System admin".into(),
        permissions: PermissionCatalog::ALL.iter().map(|p| Permission::new(*p)).collect(),
        created_at: 0, updated_at: 0,
    }).await.unwrap();
    roles.create(&Role {
        id: "role-tenant-admin".into(), tenant_id: None,
        slug: SystemRole::TENANT_ADMIN.into(),
        display_name: "Tenant admin".into(),
        permissions: vec![
            Permission::new(PermissionCatalog::TENANT_READ),
            Permission::new(PermissionCatalog::TENANT_UPDATE),
            Permission::new(PermissionCatalog::ORGANIZATION_CREATE),
            Permission::new(PermissionCatalog::ROLE_ASSIGN),
        ],
        created_at: 0, updated_at: 0,
    }).await.unwrap();
    roles.create(&Role {
        id: "role-org-admin".into(), tenant_id: None,
        slug: SystemRole::ORGANIZATION_ADMIN.into(),
        display_name: "Org admin".into(),
        permissions: vec![
            Permission::new(PermissionCatalog::ORGANIZATION_READ),
            Permission::new(PermissionCatalog::GROUP_CREATE),
        ],
        created_at: 0, updated_at: 0,
    }).await.unwrap();
}

#[tokio::test]
async fn tenant_admin_grants_tenant_scoped_permissions() {
    let roles = InMemoryRoleRepository::default();
    let asgs  = InMemoryRoleAssignmentRepository::default();
    seed_system_roles(&roles).await;

    asgs.create(&RoleAssignment {
        id: "a1".into(), user_id: "u-alice".into(),
        role_id: "role-tenant-admin".into(),
        scope: Scope::Tenant { tenant_id: "t-acme".into() },
        granted_by: "system".into(), granted_at: 0, expires_at: None,
    }).await.unwrap();

    // Alice has tenant:update on her tenant.
    let out = check_permission(
        &asgs, &roles, "u-alice",
        PermissionCatalog::TENANT_UPDATE,
        ScopeRef::Tenant { tenant_id: "t-acme" }, 100,
    ).await.unwrap();
    assert!(out.is_allowed());

    // …but not on a different tenant.
    let out = check_permission(
        &asgs, &roles, "u-alice",
        PermissionCatalog::TENANT_UPDATE,
        ScopeRef::Tenant { tenant_id: "t-other" }, 100,
    ).await.unwrap();
    assert!(!out.is_allowed());

    // …and not for a permission outside her role.
    let out = check_permission(
        &asgs, &roles, "u-alice",
        PermissionCatalog::TENANT_DELETE,
        ScopeRef::Tenant { tenant_id: "t-acme" }, 100,
    ).await.unwrap();
    assert!(!out.is_allowed());
}

#[tokio::test]
async fn permission_repository_seeded_with_full_catalog() {
    let perms = InMemoryPermissionRepository::with_default_catalog();
    let listed = perms.list_all().await.unwrap();
    assert_eq!(listed.len(), PermissionCatalog::ALL.len());
    for staple in [
        PermissionCatalog::TENANT_READ,
        PermissionCatalog::AUDIT_READ,
        PermissionCatalog::ROLE_ASSIGN,
    ] {
        assert!(perms.exists(staple).await.unwrap(), "missing {staple}");
    }
    assert!(!perms.exists("not.a.real.permission").await.unwrap());
}

// ---------------------------------------------------------------------
// Billing — round-trip + history append
// ---------------------------------------------------------------------

#[tokio::test]
async fn plan_repository_round_trips_a_seeded_plan() {
    let plans = InMemoryPlanRepository::default();
    plans.insert(Plan {
        id: "plan-pro".into(), slug: PlanId::Pro.slug().into(),
        display_name: "Pro".into(), active: true,
        features: vec![],
        quotas: vec![Quota { name: "max_users".into(), value: 100 }],
        price_description: None,
        created_at: 0, updated_at: 0,
    });
    let got = plans.find_by_slug("pro").await.unwrap().unwrap();
    assert_eq!(got.id, "plan-pro");
    assert_eq!(got.quotas.len(), 1);
    assert!(plans.list_active().await.unwrap().len() == 1);
}

#[tokio::test]
async fn one_active_subscription_per_tenant() {
    let subs = InMemorySubscriptionRepository::default();
    let s1 = Subscription {
        id: "s1".into(), tenant_id: "t-1".into(), plan_id: "plan-free".into(),
        lifecycle: SubscriptionLifecycle::Trial,
        status:    SubscriptionStatus::Active,
        started_at: 0, current_period_end: None, trial_ends_at: Some(1000),
        status_changed_at: 0, updated_at: 0,
    };
    subs.create(&s1).await.unwrap();
    // Second subscription for the same tenant must conflict.
    let s2 = Subscription { id: "s2".into(), ..s1.clone() };
    let err = subs.create(&s2).await.unwrap_err();
    assert!(matches!(err, PortError::Conflict));
}

#[tokio::test]
async fn subscription_history_records_state_changes() {
    let history = InMemorySubscriptionHistoryRepository::default();
    history.append(&SubscriptionHistoryEntry {
        id: "h1".into(), subscription_id: "s1".into(), tenant_id: "t-1".into(),
        event: "plan_changed".into(),
        from_plan_id: Some("plan-trial".into()),
        to_plan_id:   Some("plan-pro".into()),
        from_status: None, to_status: None,
        actor: "u-alice".into(), occurred_at: 1000,
    }).await.unwrap();
    history.append(&SubscriptionHistoryEntry {
        id: "h2".into(), subscription_id: "s1".into(), tenant_id: "t-1".into(),
        event: "status_changed".into(),
        from_plan_id: None, to_plan_id: None,
        from_status: Some(SubscriptionStatus::Active),
        to_status:   Some(SubscriptionStatus::PastDue),
        actor: "system".into(), occurred_at: 2000,
    }).await.unwrap();

    let entries = history.list_for_subscription("s1").await.unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].event, "plan_changed");
    assert_eq!(entries[1].event, "status_changed");
}

#[tokio::test]
async fn plan_catalog_lists_four_builtins() {
    assert_eq!(PlanCatalog::ALL.len(), 4);
}

// ---------------------------------------------------------------------
// Membership negative paths
// ---------------------------------------------------------------------

#[tokio::test]
async fn duplicate_membership_returns_conflict() {
    let members = InMemoryMembershipRepository::default();
    let m = cesauth_core::tenancy::types::TenantMembership {
        tenant_id: "t".into(), user_id: "u".into(),
        role: TenantMembershipRole::Member, joined_at: 0,
    };
    members.add_tenant_membership(&m).await.unwrap();
    let err = members.add_tenant_membership(&m).await.unwrap_err();
    assert!(matches!(err, PortError::Conflict));
}

#[tokio::test]
async fn purge_expired_role_assignments() {
    let asgs = InMemoryRoleAssignmentRepository::default();
    asgs.create(&RoleAssignment {
        id: "a-live".into(), user_id: "u".into(), role_id: "r".into(),
        scope: Scope::System, granted_by: "system".into(),
        granted_at: 0, expires_at: None,
    }).await.unwrap();
    asgs.create(&RoleAssignment {
        id: "a-dead".into(), user_id: "u".into(), role_id: "r".into(),
        scope: Scope::System, granted_by: "system".into(),
        granted_at: 0, expires_at: Some(50),
    }).await.unwrap();

    let purged = asgs.purge_expired(100).await.unwrap();
    assert_eq!(purged, 1);
    let remaining = asgs.list_for_user("u").await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, "a-live");
}

// =========================================================================
// RFC 056 — Soft delete service function tests
// =========================================================================

#[tokio::test]
async fn soft_delete_tenant_sets_deleted_status() {
    use cesauth_core::tenancy::service::{create_tenant, soft_delete_tenant};
    use cesauth_core::tenancy::ports::NewTenantInput;
    use cesauth_core::tenancy::types::{TenantMembershipRole, TenantStatus};

    let tenants  = InMemoryTenantRepository::default();
    let members  = InMemoryMembershipRepository::default();
    let now = 1_700_000_000i64;

    let input = NewTenantInput {
        slug:          "del-tenant",
        display_name:  "To Delete",
        owner_user_id: "u-owner",
        owner_role:    TenantMembershipRole::Owner,
    };
    let tenant = create_tenant(&tenants, &members, &input, now).await.unwrap();
    soft_delete_tenant(&tenants, &tenant.id, now + 1).await.unwrap();

    let found = tenants.get(&tenant.id).await.unwrap().unwrap();
    assert_eq!(found.status, TenantStatus::Deleted,
        "soft_delete_tenant must set status to Deleted");
}

#[tokio::test]
async fn suspend_and_restore_tenant_roundtrip() {
    use cesauth_core::tenancy::service::{create_tenant, suspend_tenant, restore_tenant};
    use cesauth_core::tenancy::ports::NewTenantInput;
    use cesauth_core::tenancy::types::{TenantMembershipRole, TenantStatus};

    let tenants  = InMemoryTenantRepository::default();
    let members  = InMemoryMembershipRepository::default();
    let now = 1_700_000_000i64;

    let input = NewTenantInput {
        slug:          "suspend-restore",
        display_name:  "Suspend Me",
        owner_user_id: "u-s",
        owner_role:    TenantMembershipRole::Owner,
    };
    let tenant = create_tenant(&tenants, &members, &input, now).await.unwrap();

    suspend_tenant(&tenants, &tenant.id, now + 1).await.unwrap();
    let suspended = tenants.get(&tenant.id).await.unwrap().unwrap();
    assert_eq!(suspended.status, TenantStatus::Suspended);

    restore_tenant(&tenants, &tenant.id, now + 2).await.unwrap();
    let restored = tenants.get(&tenant.id).await.unwrap().unwrap();
    assert_eq!(restored.status, TenantStatus::Active);
}

#[tokio::test]
async fn soft_delete_organization_sets_deleted_status() {
    use cesauth_core::tenancy::service::{create_tenant, create_organization, soft_delete_organization};
    use cesauth_core::tenancy::ports::{NewTenantInput, OrganizationRepository};
    use cesauth_core::tenancy::types::{TenantMembershipRole, OrganizationStatus};

    let tenants  = InMemoryTenantRepository::default();
    let orgs     = InMemoryOrganizationRepository::default();
    let members  = InMemoryMembershipRepository::default();
    let now = 1_700_000_000i64;

    let t = create_tenant(&tenants, &members, &NewTenantInput {
        slug: "org-del-t", display_name: "T", owner_user_id: "u", owner_role: TenantMembershipRole::Owner,
    }, now).await.unwrap();

    let org = create_organization(&tenants, &orgs, &t.id, "org-del", "Org", now).await.unwrap();

    soft_delete_organization(&orgs, &org.id, now + 1).await.unwrap();

    let found = orgs.get(&org.id).await.unwrap().unwrap();
    assert_eq!(found.status, OrganizationStatus::Deleted,
        "soft_delete_organization must set status to Deleted");
}

// =========================================================================
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
