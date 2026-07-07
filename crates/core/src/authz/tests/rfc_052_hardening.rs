//! Originally part of `crates/core/src/authz/tests.rs`.
//! Split into a sibling file in v0.78.0 (test-file modularization).

use super::common::*;

// RFC 052 — Authorization hardening tests
// =========================================================================

// ── Cross-tenant rejection ────────────────────────────────────────────────

#[tokio::test]
async fn cross_tenant_access_is_denied() {
    // A role assignment in tenant A must NOT grant access in tenant B.
    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();

    roles.create(&role("r", None, "member", &[PermissionCatalog::TENANT_READ]))
        .await.unwrap();
    asgs.create(&assignment("a", "u", "r",
        Scope::Tenant { tenant_id: "tenant-a".into() }))
        .await.unwrap();

    let out = check_permission(
        &asgs, &roles, "u",
        PermissionCatalog::TENANT_READ,
        ScopeRef::Tenant { tenant_id: "tenant-b" },  // ← different tenant
        100,
    ).await.unwrap();

    assert_eq!(out, CheckOutcome::Denied(DenyReason::ScopeMismatch),
        "assignment in tenant-a must not grant access in tenant-b");
}

// ── System scope covers all tenants ──────────────────────────────────────

#[tokio::test]
async fn system_scope_covers_any_tenant() {
    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();

    // Grant user a System-scoped role that includes TENANT_READ.
    roles.create(&role("sys-r", None, "system_admin", &[
        PermissionCatalog::TENANT_READ,
    ])).await.unwrap();
    asgs.create(&assignment("a", "u", "sys-r", Scope::System))
        .await.unwrap();

    // System scope should cover a Tenant-scoped query.
    let out = check_permission(
        &asgs, &roles, "u",
        PermissionCatalog::TENANT_READ,
        ScopeRef::Tenant { tenant_id: "any-tenant" },
        100,
    ).await.unwrap();

    assert!(out.is_allowed(),
        "System-scoped role must cover Tenant-scoped permission check");
}

// ── Tenant scope covers org/group within that tenant ─────────────────────

// NOTE: ScopeRef::Organization does not carry tenant_id in the current design.
// The scope_covers function therefore cannot infer tenant containment for
// Organization queries — Tenant-scoped grants do NOT automatically cover
// Organization-scoped queries (they must be granted at the Organization scope
// directly).  This is a design decision documented in RFC 052.
//
// If hierarchical tenant→org coverage is desired in future, ScopeRef::Organization
// should be extended to carry tenant_id.

#[tokio::test]
async fn tenant_scope_requires_org_assignment_for_org_query() {
    // Document current behavior: Tenant-scoped role does NOT automatically
    // cover Organization scope (ScopeRef::Organization has no tenant_id).
    // An explicit Organization-scoped assignment is required.
    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();

    roles.create(&role("o-r", None, "org_admin", &[
        PermissionCatalog::ORGANIZATION_UPDATE,
    ])).await.unwrap();

    // Assign directly at Organization scope.
    asgs.create(&assignment("a", "u", "o-r",
        Scope::Organization { organization_id: "org-1".into() }))
        .await.unwrap();

    let out = check_permission(
        &asgs, &roles, "u",
        PermissionCatalog::ORGANIZATION_UPDATE,
        ScopeRef::Organization { organization_id: "org-1" },
        100,
    ).await.unwrap();

    assert!(out.is_allowed(),
        "Organization-scoped role must cover Organization-scoped query with matching id");
}

#[tokio::test]
async fn org_scope_does_not_cover_different_org() {
    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();

    roles.create(&role("o-r", None, "org_admin", &[PermissionCatalog::ORGANIZATION_UPDATE]))
        .await.unwrap();
    asgs.create(&assignment("a", "u", "o-r",
        Scope::Organization { organization_id: "org-1".into() }))
        .await.unwrap();

    let out = check_permission(
        &asgs, &roles, "u",
        PermissionCatalog::ORGANIZATION_UPDATE,
        ScopeRef::Organization { organization_id: "org-2" },
        100,
    ).await.unwrap();

    assert_eq!(out, CheckOutcome::Denied(DenyReason::ScopeMismatch),
        "org-1 grant must not cover org-2 query");
}

// ── system_admin is superset of all built-in permission catalog ───────────

#[tokio::test]
async fn system_admin_role_covers_user_write() {
    // Complement to the migration test: verify at the service layer that
    // system_admin has USER_WRITE.
    let roles  = StubRoles::default();
    let asgs   = StubAssignments::default();

    // Build a system_admin Role with ALL PermissionCatalog permissions.
    let all_perms: Vec<Permission> = PermissionCatalog::ALL
        .iter()
        .map(|s| Permission(s.to_string()))
        .collect();
    roles.create(&Role {
        id:          "sys-admin-r".to_owned(),
        slug:        "system_admin".to_owned(),
        tenant_id:   None,
        display_name: "System Admin".to_owned(),
        permissions: all_perms,
        created_at:  0,
        updated_at:  0,
    }).await.unwrap();

    asgs.create(&assignment("a", "u", "sys-admin-r", Scope::System))
        .await.unwrap();

    for perm in PermissionCatalog::ALL {
        let out = check_permission(
            &asgs, &roles, "u", perm,
            ScopeRef::System,
            100,
        ).await.unwrap();
        assert!(out.is_allowed(),
            "system_admin must grant '{perm}' at System scope");
    }
}

// ── No assignments denies gracefully ─────────────────────────────────────

#[tokio::test]
async fn user_with_no_assignments_is_denied() {
    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();
    // No assignments created.
    let out = check_permission(
        &asgs, &roles, "u-nobody",
        PermissionCatalog::TENANT_READ,
        ScopeRef::System,
        100,
    ).await.unwrap();
    assert_eq!(out, CheckOutcome::Denied(DenyReason::NoAssignments));
}

// ── Scope validation helpers ──────────────────────────────────────────────

#[test]
fn scope_ref_tenant_identity() {
    // A Tenant ScopeRef only covers itself, not a different tenant.
    use super::super::service::scope_covers;
    assert!(scope_covers(
        &Scope::Tenant { tenant_id: "t1".into() },
        &ScopeRef::Tenant { tenant_id: "t1" },
    ), "same tenant must cover itself");
    assert!(!scope_covers(
        &Scope::Tenant { tenant_id: "t1".into() },
        &ScopeRef::Tenant { tenant_id: "t2" },
    ), "different tenant must not cover");
}

#[test]
fn scope_ref_system_covers_all() {
    use super::super::service::scope_covers;
    assert!(scope_covers(&Scope::System, &ScopeRef::System));
    assert!(scope_covers(&Scope::System, &ScopeRef::Tenant { tenant_id: "t" }));
    assert!(scope_covers(
        &Scope::System,
        &ScopeRef::Organization { organization_id: "o" },
    ));
}
