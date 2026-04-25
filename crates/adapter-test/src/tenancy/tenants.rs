use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::tenancy::ports::TenantRepository;
use cesauth_core::tenancy::types::{Tenant, TenantStatus};

#[derive(Debug, Default)]
pub struct InMemoryTenantRepository {
    rows: Mutex<HashMap<String, Tenant>>,
}

impl TenantRepository for InMemoryTenantRepository {
    async fn create(&self, t: &Tenant) -> PortResult<()> {
        let mut g = self.rows.lock().unwrap();
        if g.values().any(|r| r.slug == t.slug) {
            return Err(PortError::Conflict);
        }
        g.insert(t.id.clone(), t.clone());
        Ok(())
    }
    async fn get(&self, id: &str) -> PortResult<Option<Tenant>> {
        Ok(self.rows.lock().unwrap().get(id).cloned())
    }
    async fn find_by_slug(&self, slug: &str) -> PortResult<Option<Tenant>> {
        Ok(self.rows.lock().unwrap().values().find(|r| r.slug == slug).cloned())
    }
    async fn list_active(&self) -> PortResult<Vec<Tenant>> {
        Ok(self.rows.lock().unwrap().values()
           .filter(|r| !matches!(r.status, TenantStatus::Deleted))
           .cloned().collect())
    }
    async fn set_status(&self, id: &str, s: TenantStatus, now: i64) -> PortResult<()> {
        let mut g = self.rows.lock().unwrap();
        match g.get_mut(id) {
            Some(t) => { t.status = s; t.updated_at = now; Ok(()) }
            None    => Err(PortError::NotFound),
        }
    }
    async fn update_display_name(&self, id: &str, name: &str, now: i64) -> PortResult<()> {
        let mut g = self.rows.lock().unwrap();
        match g.get_mut(id) {
            Some(t) => { t.display_name = name.to_owned(); t.updated_at = now; Ok(()) }
            None    => Err(PortError::NotFound),
        }
    }
}
