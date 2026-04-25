use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::authz::ports::RoleRepository;
use cesauth_core::authz::types::Role;
use cesauth_core::ports::{PortError, PortResult};

#[derive(Debug, Default)]
pub struct InMemoryRoleRepository {
    rows: Mutex<HashMap<String, Role>>,
}

impl RoleRepository for InMemoryRoleRepository {
    async fn create(&self, r: &Role) -> PortResult<()> {
        let mut g = self.rows.lock().unwrap();
        // Slug uniqueness: per-tenant for tenant roles, global for system roles.
        let dup = g.values().any(|x| x.slug == r.slug && x.tenant_id == r.tenant_id);
        if dup { return Err(PortError::Conflict); }
        g.insert(r.id.clone(), r.clone());
        Ok(())
    }
    async fn get(&self, id: &str) -> PortResult<Option<Role>> {
        Ok(self.rows.lock().unwrap().get(id).cloned())
    }
    async fn find_by_slug(&self, tenant: Option<&str>, slug: &str) -> PortResult<Option<Role>> {
        Ok(self.rows.lock().unwrap().values()
           .find(|r| r.slug == slug && r.tenant_id.as_deref() == tenant)
           .cloned())
    }
    async fn list_visible_to_tenant(&self, tenant: &str) -> PortResult<Vec<Role>> {
        Ok(self.rows.lock().unwrap().values()
           .filter(|r| r.tenant_id.is_none() || r.tenant_id.as_deref() == Some(tenant))
           .cloned().collect())
    }
    async fn list_system_roles(&self) -> PortResult<Vec<Role>> {
        Ok(self.rows.lock().unwrap().values()
           .filter(|r| r.tenant_id.is_none()).cloned().collect())
    }
}
