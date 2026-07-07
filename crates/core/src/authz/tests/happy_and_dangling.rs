//! Originally part of `crates/core/src/authz/tests.rs`.
//! Split into a sibling file in v0.78.0 (test-file modularization).

use super::common::*;

// Happy path
// ---------------------------------------------------------------------

#[tokio::test]
async fn tenant_admin_may_update_own_tenant() {
    let roles = StubRoles::default();
    roles.create(&role("r", None, SystemRole::TENANT_ADMIN,
        &[PermissionCatalog::TENANT_UPDATE, PermissionCatalog::TENANT_READ])).await.unwrap();
    let asgs = StubAssignments::default();
    asgs.create(&assignment("a", "u-alice", "r",
        Scope::Tenant { tenant_id: "t-1".into() })).await.unwrap();

    let out = check_permission(
        &asgs, &roles, "u-alice",
        PermissionCatalog::TENANT_UPDATE,
        ScopeRef::Tenant { tenant_id: "t-1" },
        100,
    ).await.unwrap();
    match out {
        CheckOutcome::Allowed { role_id, scope } => {
            assert_eq!(role_id, "r");
            assert_eq!(scope, Scope::Tenant { tenant_id: "t-1".into() });
        }
        other => panic!("expected Allowed, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Dangling role id is tolerated
// ---------------------------------------------------------------------

#[tokio::test]
async fn dangling_role_assignment_does_not_crash() {
    // Assignment references a role id that doesn't exist. The check
    // should skip it gracefully and deny, not panic.
    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();
    asgs.create(&assignment("a", "u", "missing",
        Scope::Tenant { tenant_id: "t".into() })).await.unwrap();

    let out = check_permission(
        &asgs, &roles, "u",
        PermissionCatalog::TENANT_READ,
        ScopeRef::Tenant { tenant_id: "t" },
        100,
    ).await.unwrap();
    assert_eq!(out, CheckOutcome::Denied(DenyReason::PermissionMissing));
}

// Unused import suppressor so rustc doesn't warn about `PortError`
// when the test file compiles clean.
#[allow(dead_code)]
fn _unused_error() -> PortError { PortError::NotFound }

// ---------------------------------------------------------------------
