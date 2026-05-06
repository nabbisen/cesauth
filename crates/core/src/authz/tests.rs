//! Authorization domain tests.
//!
//! These cover the scope-covering lattice, the permission catalog,
//! and the check-permission state machine against a tiny in-module
//! stub repository. Keeping the stub local avoids a circular
//! dependency between `cesauth-core` and `cesauth-adapter-test`
//! (the latter depends on the former).

use super::ports::{RoleAssignmentRepository, RoleRepository};
use super::service::{check_permission, CheckOutcome, DenyReason};
use super::types::*;
use crate::ports::{PortError, PortResult};
use std::cell::RefCell;

// ---------------------------------------------------------------------
// Tiny in-module stubs. Sync (no async internals); the trait fns are
// async but we just wrap synchronous data.
// ---------------------------------------------------------------------

#[derive(Debug, Default)]
struct StubRoles { rows: RefCell<Vec<Role>> }
impl RoleRepository for StubRoles {
    async fn create(&self, r: &Role) -> PortResult<()> {
        self.rows.borrow_mut().push(r.clone());
        Ok(())
    }
    async fn get(&self, id: &str) -> PortResult<Option<Role>> {
        Ok(self.rows.borrow().iter().find(|r| r.id == id).cloned())
    }
    async fn find_by_slug(&self, tenant: Option<&str>, slug: &str) -> PortResult<Option<Role>> {
        Ok(self.rows.borrow().iter().find(|r|
            r.slug == slug && r.tenant_id.as_deref() == tenant
        ).cloned())
    }
    async fn list_visible_to_tenant(&self, tenant_id: &str) -> PortResult<Vec<Role>> {
        Ok(self.rows.borrow().iter()
           .filter(|r| r.tenant_id.is_none() || r.tenant_id.as_deref() == Some(tenant_id))
           .cloned().collect())
    }
    async fn list_system_roles(&self) -> PortResult<Vec<Role>> {
        Ok(self.rows.borrow().iter()
           .filter(|r| r.tenant_id.is_none()).cloned().collect())
    }
}

#[derive(Debug, Default)]
struct StubAssignments { rows: RefCell<Vec<RoleAssignment>> }
impl RoleAssignmentRepository for StubAssignments {
    async fn create(&self, a: &RoleAssignment) -> PortResult<()> {
        self.rows.borrow_mut().push(a.clone()); Ok(())
    }
    async fn delete(&self, id: &str) -> PortResult<()> {
        self.rows.borrow_mut().retain(|a| a.id != id);
        Ok(())
    }
    async fn list_for_user(&self, user_id: &str) -> PortResult<Vec<RoleAssignment>> {
        Ok(self.rows.borrow().iter()
           .filter(|a| a.user_id == user_id).cloned().collect())
    }
    async fn list_in_scope(&self, s: &Scope) -> PortResult<Vec<RoleAssignment>> {
        Ok(self.rows.borrow().iter()
           .filter(|a| &a.scope == s).cloned().collect())
    }
    async fn purge_expired(&self, now: i64) -> PortResult<u64> {
        let before = self.rows.borrow().len();
        self.rows.borrow_mut().retain(|a| match a.expires_at {
            Some(t) => t > now,
            None    => true,
        });
        Ok((before - self.rows.borrow().len()) as u64)
    }
}

fn role(id: &str, tenant: Option<&str>, slug: &str, perms: &[&str]) -> Role {
    Role {
        id: id.into(), tenant_id: tenant.map(str::to_owned),
        slug: slug.into(), display_name: slug.into(),
        permissions: perms.iter().map(|p| Permission::new(*p)).collect(),
        created_at: 0, updated_at: 0,
    }
}

fn assignment(id: &str, user: &str, role_id: &str, scope: Scope) -> RoleAssignment {
    RoleAssignment {
        id: id.into(), user_id: user.into(), role_id: role_id.into(),
        scope, granted_by: "test".into(), granted_at: 0, expires_at: None,
    }
}

// ---------------------------------------------------------------------
// Catalog shape
// ---------------------------------------------------------------------

#[test]
fn permission_catalog_has_no_duplicates() {
    use std::collections::BTreeSet;
    let set: BTreeSet<_> = PermissionCatalog::ALL.iter().copied().collect();
    assert_eq!(set.len(), PermissionCatalog::ALL.len(),
        "duplicate entry in PermissionCatalog::ALL");
}

#[test]
fn permission_catalog_includes_expected_staples() {
    // Sanity: the catalog should be non-empty and include the
    // headline permissions mentioned in the spec §16.3.
    assert!(PermissionCatalog::ALL.len() >= 20);
    assert!(PermissionCatalog::ALL.contains(&PermissionCatalog::TENANT_READ));
    assert!(PermissionCatalog::ALL.contains(&PermissionCatalog::AUDIT_READ));
}

// ---------------------------------------------------------------------
// No assignments
// ---------------------------------------------------------------------

#[tokio::test]
async fn unassigned_user_is_denied_with_no_assignments() {
    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();
    let out = check_permission(
        &asgs, &roles, "u-ghost",
        PermissionCatalog::TENANT_READ,
        ScopeRef::Tenant { tenant_id: "t-1" },
        100,
    ).await.unwrap();
    assert_eq!(out, CheckOutcome::Denied(DenyReason::NoAssignments));
}

// ---------------------------------------------------------------------
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
// v0.15.0 — check_permissions_batch
// ---------------------------------------------------------------------

#[tokio::test]
async fn batch_with_no_queries_returns_empty_without_io() {
    use super::service::check_permissions_batch;

    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();

    let out = check_permissions_batch(
        &asgs, &roles, "u", &[], 100,
    ).await.unwrap();
    assert!(out.is_empty(),
        "empty queries → empty results, no fall-through");
}

#[tokio::test]
async fn batch_matches_per_query_check_permission_results() {
    // The whole point: batch should produce the same answers as
    // calling `check_permission` once per (slug, scope). If the
    // batch helper diverges, callers using affordance gating
    // would render different UI from what the per-route check
    // would allow.
    use super::service::{check_permission, check_permissions_batch};

    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();
    roles.create(&role("r-admin", None, "admin", &[
        PermissionCatalog::TENANT_READ,
        PermissionCatalog::ORGANIZATION_CREATE,
    ])).await.unwrap();
    asgs.create(&assignment("a", "u", "r-admin",
        Scope::Tenant { tenant_id: "t-acme".into() })).await.unwrap();

    let queries: &[(&str, ScopeRef<'_>)] = &[
        (PermissionCatalog::TENANT_READ,         ScopeRef::Tenant { tenant_id: "t-acme" }),
        (PermissionCatalog::ORGANIZATION_CREATE, ScopeRef::Tenant { tenant_id: "t-acme" }),
        (PermissionCatalog::GROUP_DELETE,        ScopeRef::Tenant { tenant_id: "t-acme" }),
        (PermissionCatalog::TENANT_READ,         ScopeRef::Tenant { tenant_id: "other-tenant" }),
    ];

    let batch_out = check_permissions_batch(
        &asgs, &roles, "u", queries, 100,
    ).await.unwrap();

    // Compare against per-call results.
    for (i, (slug, scope)) in queries.iter().enumerate() {
        let single = check_permission(
            &asgs, &roles, "u", slug, *scope, 100,
        ).await.unwrap();
        assert_eq!(batch_out[i], single,
            "batch result at index {i} must match per-query check");
    }

    // Spot-check: index 0 is allowed (TENANT_READ at t-acme),
    // index 2 is denied (no GROUP_DELETE in role), index 3 is
    // denied (different tenant scope).
    assert!(batch_out[0].is_allowed());
    assert!(batch_out[1].is_allowed());
    assert!(!batch_out[2].is_allowed());
    assert!(!batch_out[3].is_allowed());
}

#[tokio::test]
async fn batch_no_assignments_denies_every_query_with_NoAssignments() {
    use super::service::check_permissions_batch;

    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();
    // No assignments for user "u".

    let queries: &[(&str, ScopeRef<'_>)] = &[
        (PermissionCatalog::TENANT_READ,    ScopeRef::Tenant { tenant_id: "t" }),
        (PermissionCatalog::GROUP_CREATE,   ScopeRef::Tenant { tenant_id: "t" }),
        (PermissionCatalog::ROLE_ASSIGN,    ScopeRef::Tenant { tenant_id: "t" }),
    ];
    let out = check_permissions_batch(&asgs, &roles, "u", queries, 100)
        .await.unwrap();

    assert_eq!(out.len(), 3);
    for o in &out {
        assert_eq!(*o, CheckOutcome::Denied(DenyReason::NoAssignments));
    }
}

#[tokio::test]
async fn batch_with_dangling_role_id_denies_gracefully() {
    // A role assignment points at a role row that no longer
    // exists. check_permission handles this by skipping; batch
    // should preserve the same behaviour rather than panicking
    // or treating the dangling assignment as a match.
    use super::service::check_permissions_batch;

    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();
    asgs.create(&assignment("a", "u", "ghost-role",
        Scope::Tenant { tenant_id: "t".into() })).await.unwrap();

    let queries: &[(&str, ScopeRef<'_>)] = &[
        (PermissionCatalog::TENANT_READ, ScopeRef::Tenant { tenant_id: "t" }),
    ];
    let out = check_permissions_batch(&asgs, &roles, "u", queries, 100)
        .await.unwrap();
    assert_eq!(out[0], CheckOutcome::Denied(DenyReason::PermissionMissing));
}

#[tokio::test]
async fn batch_respects_expiration_per_query() {
    use super::service::check_permissions_batch;

    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();
    roles.create(&role("r-admin", None, "admin", &[
        PermissionCatalog::TENANT_READ,
    ])).await.unwrap();
    let mut a = assignment("a", "u", "r-admin",
        Scope::Tenant { tenant_id: "t".into() });
    a.expires_at = Some(50);  // expired by now=100
    asgs.create(&a).await.unwrap();

    let queries: &[(&str, ScopeRef<'_>)] = &[
        (PermissionCatalog::TENANT_READ, ScopeRef::Tenant { tenant_id: "t" }),
    ];
    let out = check_permissions_batch(&asgs, &roles, "u", queries, 100)
        .await.unwrap();
    // Expired → Denied(Expired), same as single check.
    assert_eq!(out[0], CheckOutcome::Denied(DenyReason::Expired));
}
