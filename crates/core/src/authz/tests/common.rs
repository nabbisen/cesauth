//! Shared stubs and helpers for authz test submodules.
//!
//! Split out from the monolithic tests.rs in v0.78.0.

//! Authorization domain tests.
//!
//! These cover the scope-covering lattice, the permission catalog,
//! and the check-permission state machine against a tiny in-module
//! stub repository. Keeping the stub local avoids a circular
//! dependency between `cesauth-core` and `cesauth-adapter-test`
//! (the latter depends on the former).

pub(super) use super::super::ports::{RoleAssignmentRepository, RoleRepository};
pub(super) use super::super::service::{check_permission, CheckOutcome, DenyReason};
pub(super) use super::super::types::*;
pub(super) use crate::ports::{PortError, PortResult};
pub(super) use std::cell::RefCell;

// ---------------------------------------------------------------------
// Tiny in-module stubs. Sync (no async internals); the trait fns are
// async but we just wrap synchronous data.
// ---------------------------------------------------------------------

#[derive(Debug, Default)]
pub(super) struct StubRoles { rows: RefCell<Vec<Role>> }
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
pub(super) struct StubAssignments { rows: RefCell<Vec<RoleAssignment>> }
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

pub(super) fn role(id: &str, tenant: Option<&str>, slug: &str, perms: &[&str]) -> Role {
    Role {
        id: id.into(), tenant_id: tenant.map(str::to_owned),
        slug: slug.into(), display_name: slug.into(),
        permissions: perms.iter().map(|p| Permission::new(*p)).collect(),
        created_at: 0, updated_at: 0,
    }
}

pub(super) fn assignment(id: &str, user: &str, role_id: &str, scope: Scope) -> RoleAssignment {
    RoleAssignment {
        id: id.into(), user_id: user.into(), role_id: role_id.into(),
        scope, granted_by: "test".into(), granted_at: 0, expires_at: None,
    }
}

// ---------------------------------------------------------------------
