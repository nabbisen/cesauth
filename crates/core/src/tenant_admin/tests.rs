//! Tenant-scoped admin auth-gate tests.
//!
//! Covers the three invariants `resolve_tenant_admin` enforces
//! plus the failure-mapping detail (status code, message). Stubs
//! are local to this file to avoid a circular dependency on
//! `cesauth-adapter-test`.

use super::*;
use crate::admin::types::{AdminPrincipal, Role as AdminRole};
use crate::ports::{PortError, PortResult};
use crate::tenancy::ports::TenantRepository;
use crate::tenancy::types::{Tenant, TenantStatus};
use crate::types::{User, UserStatus};
use crate::tenancy::AccountType;
use std::cell::RefCell;

// ---------------------------------------------------------------------
// Stubs.
// ---------------------------------------------------------------------

#[derive(Debug, Default)]
struct StubTenants { rows: RefCell<Vec<Tenant>>, fail: RefCell<bool> }

impl TenantRepository for StubTenants {
    async fn create(&self, t: &Tenant) -> PortResult<()> {
        self.rows.borrow_mut().push(t.clone());
        Ok(())
    }
    async fn get(&self, id: &str) -> PortResult<Option<Tenant>> {
        if *self.fail.borrow() { return Err(PortError::Unavailable); }
        Ok(self.rows.borrow().iter().find(|t| t.id == id).cloned())
    }
    async fn find_by_slug(&self, slug: &str) -> PortResult<Option<Tenant>> {
        if *self.fail.borrow() { return Err(PortError::Unavailable); }
        Ok(self.rows.borrow().iter().find(|t| t.slug == slug).cloned())
    }
    async fn list_active(&self) -> PortResult<Vec<Tenant>> {
        Ok(self.rows.borrow().clone())
    }
    async fn set_status(&self, _: &str, _: TenantStatus, _: i64) -> PortResult<()> { Ok(()) }
    async fn update_display_name(&self, _: &str, _: &str, _: i64) -> PortResult<()> { Ok(()) }
}

use crate::ports::repo::UserRepository;

#[derive(Debug, Default)]
struct StubUsers { rows: RefCell<Vec<User>>, fail: RefCell<bool> }

impl UserRepository for StubUsers {
    async fn find_by_id(&self, id: &str) -> PortResult<Option<User>> {
        if *self.fail.borrow() { return Err(PortError::Unavailable); }
        Ok(self.rows.borrow().iter().find(|u| u.id == id).cloned())
    }
    async fn find_by_email(&self, _: &str) -> PortResult<Option<User>> { Ok(None) }
    async fn create(&self, u: &User) -> PortResult<()> {
        self.rows.borrow_mut().push(u.clone());
        Ok(())
    }
    async fn update(&self, _: &User) -> PortResult<()> { Ok(()) }
    async fn list_by_tenant(&self, tid: &str) -> PortResult<Vec<User>> {
        Ok(self.rows.borrow().iter().filter(|u| u.tenant_id == tid).cloned().collect())
    }
    async fn list_anonymous_expired(&self, _: i64) -> PortResult<Vec<User>> {
        Ok(Vec::new())
    }
    async fn delete_by_id(&self, id: &str) -> PortResult<()> {
        self.rows.borrow_mut().retain(|u| u.id != id);
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------

fn tenant(id: &str, slug: &str) -> Tenant {
    Tenant {
        id:           id.into(),
        slug:         slug.into(),
        display_name: slug.into(),
        status:       TenantStatus::Active,
        created_at:   0,
        updated_at:   0,
    }
}

fn user(id: &str, tenant_id: &str) -> User {
    User {
        id:             id.into(),
        tenant_id:      tenant_id.into(),
        email:          None,
        email_verified: false,
        display_name:   None,
        account_type:   AccountType::HumanUser,
        status:         UserStatus::Active,
        created_at:     0,
        updated_at:     0,
    }
}

fn user_bound_principal(user_id: &str) -> AdminPrincipal {
    AdminPrincipal {
        id:      "tk-1".into(),
        name:    Some("alice".into()),
        role:    AdminRole::Operations,
        user_id: Some(user_id.into()),
    }
}

fn system_admin_principal() -> AdminPrincipal {
    AdminPrincipal {
        id:      "tk-sys".into(),
        name:    Some("ops".into()),
        role:    AdminRole::Super,
        user_id: None,
    }
}

// ---------------------------------------------------------------------
// Happy path.
// ---------------------------------------------------------------------

#[tokio::test]
async fn resolves_when_principal_user_belongs_to_slug_tenant() {
    let tenants = StubTenants::default();
    let users   = StubUsers::default();
    tenants.rows.borrow_mut().push(tenant("t-acme", "acme"));
    users.rows.borrow_mut().push(user("u-alice", "t-acme"));

    let p = user_bound_principal("u-alice");
    let ctx = resolve_tenant_admin(p.clone(), "acme", &tenants, &users)
        .await.expect("happy path should resolve");

    assert_eq!(ctx.principal.id, p.id);
    assert_eq!(ctx.tenant.id, "t-acme");
    assert_eq!(ctx.tenant.slug, "acme");
    assert_eq!(ctx.user.id, "u-alice");
    assert_eq!(ctx.user.tenant_id, "t-acme");
}

// ---------------------------------------------------------------------
// Three invariants — one test each, matching the docstring.
// ---------------------------------------------------------------------

#[tokio::test]
async fn refuses_system_admin_token_per_adr_003() {
    // ADR-003: a system-admin token presented at the
    // tenant-scoped surface is refused. The operator should be
    // using /admin/tenancy/... instead. This is the structural
    // separation that makes "switch mode" leakage impossible.
    let tenants = StubTenants::default();
    let users   = StubUsers::default();
    tenants.rows.borrow_mut().push(tenant("t-acme", "acme"));

    let p = system_admin_principal();
    let err = resolve_tenant_admin(p, "acme", &tenants, &users)
        .await.expect_err("system-admin must be refused at tenant-scoped surface");

    assert_eq!(err, TenantAdminFailure::NotUserBound);
    assert_eq!(err.status_code(), 403);
}

#[tokio::test]
async fn fails_unknown_tenant_when_slug_does_not_resolve() {
    let tenants = StubTenants::default();
    let users   = StubUsers::default();
    users.rows.borrow_mut().push(user("u-alice", "t-acme"));

    let p = user_bound_principal("u-alice");
    let err = resolve_tenant_admin(p, "unknown-slug", &tenants, &users)
        .await.expect_err("missing tenant must fail");

    assert_eq!(err, TenantAdminFailure::UnknownTenant);
    assert_eq!(err.status_code(), 404);
}

#[tokio::test]
async fn fails_wrong_tenant_when_user_belongs_elsewhere() {
    // The cross-tenant access attempt. Alice is in tenant
    // "acme", but tries to visit /admin/t/beta/. Must fail with
    // the dedicated WrongTenant signal so the worker layer can
    // audit it as a boundary violation.
    let tenants = StubTenants::default();
    let users   = StubUsers::default();
    tenants.rows.borrow_mut().push(tenant("t-acme", "acme"));
    tenants.rows.borrow_mut().push(tenant("t-beta", "beta"));
    users.rows.borrow_mut().push(user("u-alice", "t-acme"));

    let p = user_bound_principal("u-alice");
    let err = resolve_tenant_admin(p, "beta", &tenants, &users)
        .await.expect_err("cross-tenant access must fail");

    assert_eq!(err, TenantAdminFailure::WrongTenant);
    assert_eq!(err.status_code(), 403);
}

// ---------------------------------------------------------------------
// Other failures.
// ---------------------------------------------------------------------

#[tokio::test]
async fn fails_unknown_user_when_principal_user_id_is_stale() {
    let tenants = StubTenants::default();
    let users   = StubUsers::default();  // no users
    tenants.rows.borrow_mut().push(tenant("t-acme", "acme"));

    let p = user_bound_principal("u-deleted");
    let err = resolve_tenant_admin(p, "acme", &tenants, &users)
        .await.expect_err("stale user_id must fail");

    assert_eq!(err, TenantAdminFailure::UnknownUser);
    assert_eq!(err.status_code(), 401);
}

#[tokio::test]
async fn fails_unavailable_when_tenant_repo_breaks() {
    let tenants = StubTenants::default();
    let users   = StubUsers::default();
    *tenants.fail.borrow_mut() = true;

    let p = user_bound_principal("u-alice");
    let err = resolve_tenant_admin(p, "acme", &tenants, &users)
        .await.expect_err("storage failure must surface");

    assert_eq!(err, TenantAdminFailure::Unavailable);
    assert_eq!(err.status_code(), 503);
}

#[tokio::test]
async fn fails_unavailable_when_user_repo_breaks() {
    // Tenant lookup succeeds, user lookup breaks. Make sure we
    // distinguish "user repo broke" from "user not found".
    let tenants = StubTenants::default();
    let users   = StubUsers::default();
    tenants.rows.borrow_mut().push(tenant("t-acme", "acme"));
    *users.fail.borrow_mut() = true;

    let p = user_bound_principal("u-alice");
    let err = resolve_tenant_admin(p, "acme", &tenants, &users)
        .await.expect_err("user repo failure must surface");

    assert_eq!(err, TenantAdminFailure::Unavailable);
}

// ---------------------------------------------------------------------
// Failure presentation.
// ---------------------------------------------------------------------

#[test]
fn failure_messages_are_distinct_and_human_safe() {
    use TenantAdminFailure::*;
    let msgs = [NotUserBound, UnknownTenant, UnknownUser, WrongTenant, Unavailable]
        .iter()
        .map(|f| f.message())
        .collect::<Vec<_>>();

    // Distinct.
    let mut sorted = msgs.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), msgs.len(),
        "failure messages must be distinct so logs can disambiguate");

    // None leak the slug or user_id back (we never echo input).
    for m in &msgs {
        assert!(!m.contains("acme"));
        assert!(!m.contains("u-alice"));
    }
}

#[test]
fn failure_status_codes_match_semantics() {
    use TenantAdminFailure::*;
    // NotUserBound = 403 (forbidden — request well-formed but disallowed)
    assert_eq!(NotUserBound.status_code(), 403);
    // UnknownTenant = 404 (the resource does not exist for anyone)
    assert_eq!(UnknownTenant.status_code(), 404);
    // UnknownUser = 401 (the principal's auth state is broken)
    assert_eq!(UnknownUser.status_code(), 401);
    // WrongTenant = 403 (forbidden — explicitly cross-tenant)
    assert_eq!(WrongTenant.status_code(), 403);
    // Unavailable = 503 (storage layer)
    assert_eq!(Unavailable.status_code(), 503);
}
