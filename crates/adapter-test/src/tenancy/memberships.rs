//! In-memory unified membership store.
//!
//! Three vectors, one mutex. The `MembershipRepository` trait is one
//! port covering all three relations; collapsing them into a single
//! adapter keeps tests cheap (one struct to construct) and matches the
//! port shape.

use std::sync::Mutex;

use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::tenancy::ports::MembershipRepository;
use cesauth_core::tenancy::types::{
    GroupMembership, OrganizationMembership, TenantMembership,
};

#[derive(Debug, Default)]
pub struct InMemoryMembershipRepository {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    tenants: Vec<TenantMembership>,
    orgs:    Vec<OrganizationMembership>,
    groups:  Vec<GroupMembership>,
}

impl MembershipRepository for InMemoryMembershipRepository {
    // --- tenant ---
    async fn add_tenant_membership(&self, m: &TenantMembership) -> PortResult<()> {
        let mut s = self.state.lock().unwrap();
        if s.tenants.iter().any(|r| r.tenant_id == m.tenant_id && r.user_id == m.user_id) {
            return Err(PortError::Conflict);
        }
        s.tenants.push(m.clone());
        Ok(())
    }
    async fn remove_tenant_membership(&self, t: &str, u: &str) -> PortResult<()> {
        self.state.lock().unwrap().tenants.retain(|r| !(r.tenant_id == t && r.user_id == u));
        Ok(())
    }
    async fn list_tenant_members(&self, t: &str) -> PortResult<Vec<TenantMembership>> {
        Ok(self.state.lock().unwrap().tenants.iter()
           .filter(|r| r.tenant_id == t).cloned().collect())
    }
    async fn list_tenants_for_user(&self, u: &str) -> PortResult<Vec<TenantMembership>> {
        Ok(self.state.lock().unwrap().tenants.iter()
           .filter(|r| r.user_id == u).cloned().collect())
    }

    // --- organization ---
    async fn add_organization_membership(&self, m: &OrganizationMembership) -> PortResult<()> {
        let mut s = self.state.lock().unwrap();
        if s.orgs.iter().any(|r| r.organization_id == m.organization_id && r.user_id == m.user_id) {
            return Err(PortError::Conflict);
        }
        s.orgs.push(m.clone());
        Ok(())
    }
    async fn remove_organization_membership(&self, o: &str, u: &str) -> PortResult<()> {
        self.state.lock().unwrap().orgs.retain(|r| !(r.organization_id == o && r.user_id == u));
        Ok(())
    }
    async fn list_organization_members(&self, o: &str) -> PortResult<Vec<OrganizationMembership>> {
        Ok(self.state.lock().unwrap().orgs.iter()
           .filter(|r| r.organization_id == o).cloned().collect())
    }
    async fn list_organizations_for_user(&self, u: &str) -> PortResult<Vec<OrganizationMembership>> {
        Ok(self.state.lock().unwrap().orgs.iter()
           .filter(|r| r.user_id == u).cloned().collect())
    }

    // --- group ---
    async fn add_group_membership(&self, m: &GroupMembership) -> PortResult<()> {
        let mut s = self.state.lock().unwrap();
        if s.groups.iter().any(|r| r.group_id == m.group_id && r.user_id == m.user_id) {
            return Err(PortError::Conflict);
        }
        s.groups.push(m.clone());
        Ok(())
    }
    async fn remove_group_membership(&self, g: &str, u: &str) -> PortResult<()> {
        self.state.lock().unwrap().groups.retain(|r| !(r.group_id == g && r.user_id == u));
        Ok(())
    }
    async fn list_group_members(&self, g: &str) -> PortResult<Vec<GroupMembership>> {
        Ok(self.state.lock().unwrap().groups.iter()
           .filter(|r| r.group_id == g).cloned().collect())
    }
    async fn list_groups_for_user(&self, u: &str) -> PortResult<Vec<GroupMembership>> {
        Ok(self.state.lock().unwrap().groups.iter()
           .filter(|r| r.user_id == u).cloned().collect())
    }
}
