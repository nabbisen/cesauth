//! Originally part of `crates/adapter-test/src/tenancy/tests.rs`.
//! Split into a sibling file in v0.78.0 (test-file modularization track).

use super::super::*;     // reaches `tenancy` (the module under test)
#[allow(unused_imports)]
use super::common::*;    // shared fixtures

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
