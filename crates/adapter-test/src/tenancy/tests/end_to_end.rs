//! Originally part of `crates/adapter-test/src/tenancy/tests.rs`.
//! Split into a sibling file in v0.78.0 (test-file modularization track).

use super::super::*;     // reaches `tenancy` (the module under test)
#[allow(unused_imports)]
use super::common::*;    // shared fixtures

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
