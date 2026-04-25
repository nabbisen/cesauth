use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::tenancy::ports::GroupRepository;
use cesauth_core::tenancy::types::{Group, GroupParent, GroupStatus};

#[derive(Debug, Default)]
pub struct InMemoryGroupRepository {
    rows: Mutex<HashMap<String, Group>>,
}

impl GroupRepository for InMemoryGroupRepository {
    async fn create(&self, g: &Group) -> PortResult<()> {
        let mut rows = self.rows.lock().unwrap();
        let dup = rows.values().any(|r|
            r.slug == g.slug && match (&r.parent, &g.parent) {
                (GroupParent::Tenant, GroupParent::Tenant) => r.tenant_id == g.tenant_id,
                (GroupParent::Organization { organization_id: a },
                 GroupParent::Organization { organization_id: b }) => a == b,
                _ => false,
            });
        if dup { return Err(PortError::Conflict); }
        rows.insert(g.id.clone(), g.clone());
        Ok(())
    }
    async fn get(&self, id: &str) -> PortResult<Option<Group>> {
        Ok(self.rows.lock().unwrap().get(id).cloned())
    }
    async fn list_tenant_scoped(&self, tenant: &str) -> PortResult<Vec<Group>> {
        Ok(self.rows.lock().unwrap().values()
           .filter(|r| r.tenant_id == tenant
                   && matches!(r.parent, GroupParent::Tenant)
                   && !matches!(r.status, GroupStatus::Deleted))
           .cloned().collect())
    }
    async fn list_for_organization(&self, org_id: &str) -> PortResult<Vec<Group>> {
        Ok(self.rows.lock().unwrap().values()
           .filter(|r| matches!(&r.parent, GroupParent::Organization { organization_id }
                                if organization_id == org_id)
                   && !matches!(r.status, GroupStatus::Deleted))
           .cloned().collect())
    }
    async fn delete(&self, id: &str, now: i64) -> PortResult<()> {
        let mut g = self.rows.lock().unwrap();
        match g.get_mut(id) {
            Some(r) => { r.status = GroupStatus::Deleted; r.updated_at = now; Ok(()) }
            None    => Err(PortError::NotFound),
        }
    }
}
