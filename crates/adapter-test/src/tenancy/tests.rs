//! Integration tests for the v0.5.0 tenancy extension.
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
