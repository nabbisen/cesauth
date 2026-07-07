//! Originally part of `crates/adapter-test/src/tenancy/tests.rs`.
//! Split into a sibling file in v0.78.0 (test-file modularization track).

use super::super::*;     // reaches `tenancy` (the module under test)
#[allow(unused_imports)]
use super::common::*;    // shared fixtures

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
    let out = check_permission(&asgs, &roles, &cesauth_core::types::UserId::from_storage("u-alice"),
        PermissionCatalog::TENANT_UPDATE,
        ScopeRef::Tenant { tenant_id: "t-acme" }, 100,
    ).await.unwrap();
    assert!(out.is_allowed());

    // …but not on a different tenant.
    let out = check_permission(&asgs, &roles, &cesauth_core::types::UserId::from_storage("u-alice"),
        PermissionCatalog::TENANT_UPDATE,
        ScopeRef::Tenant { tenant_id: "t-other" }, 100,
    ).await.unwrap();
    assert!(!out.is_allowed());

    // …and not for a permission outside her role.
    let out = check_permission(&asgs, &roles, &cesauth_core::types::UserId::from_storage("u-alice"),
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
