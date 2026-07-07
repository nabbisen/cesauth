//! Originally part of `crates/core/src/authz/tests.rs`.
//! Split into a sibling file in v0.78.0 (test-file modularization).

use super::common::*;

// System role covers everything
// ---------------------------------------------------------------------

#[tokio::test]
async fn system_admin_covers_every_scope() {
    let roles = StubRoles::default();
    roles.create(&role("r-sa", None, SystemRole::SYSTEM_ADMIN,
        PermissionCatalog::ALL)).await.unwrap();
    let asgs = StubAssignments::default();
    asgs.create(&assignment("a1", "u-op", "r-sa", Scope::System)).await.unwrap();

    for scope in [
        ScopeRef::System,
        ScopeRef::Tenant       { tenant_id:       "t-1" },
        ScopeRef::Organization { organization_id: "o-1" },
        ScopeRef::Group        { group_id:        "g-1" },
        ScopeRef::User         { user_id:         "u-other" },
    ] {
        let out = check_permission(
            &asgs, &roles, "u-op",
            PermissionCatalog::TENANT_UPDATE,
            scope, 100,
        ).await.unwrap();
        assert!(out.is_allowed(), "System role must cover scope {scope:?}, got {out:?}");
    }
}

// ---------------------------------------------------------------------
// Scope mismatch
// ---------------------------------------------------------------------

#[tokio::test]
async fn tenant_role_does_not_cover_other_tenant() {
    let roles = StubRoles::default();
    roles.create(&role("r", None, SystemRole::TENANT_ADMIN,
        &[PermissionCatalog::TENANT_UPDATE])).await.unwrap();
    let asgs = StubAssignments::default();
    asgs.create(&assignment("a", "u", "r",
        Scope::Tenant { tenant_id: "t-A".into() })).await.unwrap();

    let out = check_permission(
        &asgs, &roles, "u",
        PermissionCatalog::TENANT_UPDATE,
        ScopeRef::Tenant { tenant_id: "t-B" },
        100,
    ).await.unwrap();
    assert_eq!(out, CheckOutcome::Denied(DenyReason::ScopeMismatch));
}

// ---------------------------------------------------------------------
// Permission missing
// ---------------------------------------------------------------------

#[tokio::test]
async fn correct_scope_wrong_permission_is_permission_missing() {
    let roles = StubRoles::default();
    // Role grants read but not update.
    roles.create(&role("r", None, "readonly",
        &[PermissionCatalog::TENANT_READ])).await.unwrap();
    let asgs = StubAssignments::default();
    asgs.create(&assignment("a", "u", "r",
        Scope::Tenant { tenant_id: "t-1".into() })).await.unwrap();

    let out = check_permission(
        &asgs, &roles, "u",
        PermissionCatalog::TENANT_UPDATE,
        ScopeRef::Tenant { tenant_id: "t-1" },
        100,
    ).await.unwrap();
    assert_eq!(out, CheckOutcome::Denied(DenyReason::PermissionMissing));
}

// ---------------------------------------------------------------------
// Expiration
// ---------------------------------------------------------------------

#[tokio::test]
async fn expired_assignment_is_classified_as_expired_not_scope_mismatch() {
    let roles = StubRoles::default();
    roles.create(&role("r", None, SystemRole::TENANT_ADMIN,
        &[PermissionCatalog::TENANT_UPDATE])).await.unwrap();
    let asgs = StubAssignments::default();
    let mut a = assignment("a", "u", "r", Scope::Tenant { tenant_id: "t-1".into() });
    a.expires_at = Some(50);   // expired at unix 50
    asgs.create(&a).await.unwrap();

    // now_unix = 100 > 50, so the assignment is expired.
    let out = check_permission(
        &asgs, &roles, "u",
        PermissionCatalog::TENANT_UPDATE,
        ScopeRef::Tenant { tenant_id: "t-1" },
        100,
    ).await.unwrap();
    assert_eq!(out, CheckOutcome::Denied(DenyReason::Expired));
}

// ---------------------------------------------------------------------
