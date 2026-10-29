//! RFC 158 — `create_tenant`'s owner-home assignment, all three
//! `OwnerHomeOutcome` variants, exercised end-to-end through the real
//! service function rather than by calling the private decision step
//! directly.

use cesauth_core::tenancy::service::{create_tenant, OwnerHomeOutcome};
use cesauth_core::tenancy::ports::NewTenantInput;
use cesauth_core::tenancy::types::{TenantMembershipRole, DEFAULT_TENANT_ID};
use cesauth_core::types::{User, UserStatus};
use cesauth_core::tenancy::AccountType;
use cesauth_core::ports::repo::UserRepository;

use super::super::*;
#[allow(unused_imports)]
use super::common::*;

fn user(id: &str, tenant_id: &str) -> User {
    User {
        id:             id.to_owned(),
        tenant_id:      tenant_id.to_owned(),
        email:          None,
        email_verified: false,
        display_name:   None,
        account_type:   AccountType::HumanUser,
        status:         UserStatus::Active,
        created_at:     0,
        updated_at:     0,
    }
}

#[tokio::test]
async fn owner_on_the_default_tenant_gets_assigned() {
    let tenants = InMemoryTenantRepository::default();
    let members = InMemoryMembershipRepository::default();
    let users   = InMemoryUserRepository::default();
    users.create(&user("u-owner", DEFAULT_TENANT_ID)).await.unwrap();

    let outcome = create_tenant(&tenants, &members, &users, &NewTenantInput {
        slug: "acme", display_name: "Acme",
        owner_user_id: "u-owner", owner_role: TenantMembershipRole::Owner,
    }, 1000).await.unwrap();

    assert_eq!(outcome.owner_home, OwnerHomeOutcome::Assigned);
    let owner = users.find_by_id("u-owner").await.unwrap().unwrap();
    assert_eq!(owner.tenant_id, outcome.tenant.id,
        "the owner's home tenant must now be the newly-created tenant");
}

#[tokio::test]
async fn owner_already_homed_elsewhere_keeps_that_home() {
    let tenants = InMemoryTenantRepository::default();
    let members = InMemoryMembershipRepository::default();
    let users   = InMemoryUserRepository::default();

    // The owner already administers a different, non-default tenant.
    let existing_home = create_tenant(&tenants, &members, &users, &NewTenantInput {
        slug: "beta", display_name: "Beta",
        owner_user_id: "u-beta-owner", owner_role: TenantMembershipRole::Owner,
    }, 500).await.unwrap().tenant;
    users.create(&user("u-beta-owner", DEFAULT_TENANT_ID)).await.unwrap();
    // RFC 158: the Beta creation above assigned u-beta-owner's home to
    // Beta already (Assigned). Seed a second owner who is independently
    // homed at Beta — the case this test is actually about: naming an
    // already-homed user as owner of a *second*, unrelated tenant.
    users.create(&user("u-already-homed", &existing_home.id)).await.unwrap();

    let outcome = create_tenant(&tenants, &members, &users, &NewTenantInput {
        slug: "acme", display_name: "Acme",
        owner_user_id: "u-already-homed", owner_role: TenantMembershipRole::Owner,
    }, 1000).await.unwrap();

    assert_eq!(outcome.owner_home, OwnerHomeOutcome::KeptExistingHome);
    let owner = users.find_by_id("u-already-homed").await.unwrap().unwrap();
    assert_eq!(owner.tenant_id, existing_home.id,
        "an owner already homed elsewhere must keep that home, not move to the new tenant");
}

#[tokio::test]
async fn unknown_owner_is_a_failed_outcome_not_a_creation_failure() {
    let tenants = InMemoryTenantRepository::default();
    let members = InMemoryMembershipRepository::default();
    let users   = InMemoryUserRepository::default();
    // No user seeded for "u-ghost" at all.

    let outcome = create_tenant(&tenants, &members, &users, &NewTenantInput {
        slug: "acme", display_name: "Acme",
        owner_user_id: "u-ghost", owner_role: TenantMembershipRole::Owner,
    }, 1000).await.unwrap();

    assert_eq!(outcome.owner_home, OwnerHomeOutcome::Failed);
    // The tenant and its membership exist regardless — a failed
    // owner-home outcome must not be reported as a failure to create
    // the tenant.
    let found = tenants.get(&outcome.tenant.id).await.unwrap();
    assert!(found.is_some(), "the tenant row must exist despite the Failed owner-home outcome");
    let owners = members.list_tenant_members(&outcome.tenant.id).await.unwrap();
    assert_eq!(owners.len(), 1, "the membership row must exist despite the Failed owner-home outcome");
}
