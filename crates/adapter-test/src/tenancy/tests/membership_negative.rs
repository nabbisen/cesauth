//! Originally part of `crates/adapter-test/src/tenancy/tests.rs`.
//! Split into a sibling file in v0.78.0 (test-file modularization track).

use super::super::*;     // reaches `tenancy` (the module under test)
#[allow(unused_imports)]
use super::common::*;    // shared fixtures

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
