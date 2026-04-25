use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::tenancy::ports::OrganizationRepository;
use cesauth_core::tenancy::types::{Organization, OrganizationStatus};

#[derive(Debug, Default)]
pub struct InMemoryOrganizationRepository {
    rows: Mutex<HashMap<String, Organization>>,
}

impl OrganizationRepository for InMemoryOrganizationRepository {
    async fn create(&self, o: &Organization) -> PortResult<()> {
        let mut g = self.rows.lock().unwrap();
        if g.values().any(|r| r.tenant_id == o.tenant_id && r.slug == o.slug) {
            return Err(PortError::Conflict);
        }
        g.insert(o.id.clone(), o.clone());
        Ok(())
    }
    async fn get(&self, id: &str) -> PortResult<Option<Organization>> {
        Ok(self.rows.lock().unwrap().get(id).cloned())
    }
    async fn find_by_slug(&self, tenant: &str, slug: &str) -> PortResult<Option<Organization>> {
        Ok(self.rows.lock().unwrap().values()
           .find(|r| r.tenant_id == tenant && r.slug == slug).cloned())
    }
    async fn list_for_tenant(&self, tenant: &str) -> PortResult<Vec<Organization>> {
        Ok(self.rows.lock().unwrap().values()
           .filter(|r| r.tenant_id == tenant && !matches!(r.status, OrganizationStatus::Deleted))
           .cloned().collect())
    }
    async fn set_status(&self, id: &str, s: OrganizationStatus, now: i64) -> PortResult<()> {
        let mut g = self.rows.lock().unwrap();
        match g.get_mut(id) {
            Some(o) => { o.status = s; o.updated_at = now; Ok(()) }
            None    => Err(PortError::NotFound),
        }
    }
    async fn update_display_name(&self, id: &str, name: &str, now: i64) -> PortResult<()> {
        let mut g = self.rows.lock().unwrap();
        match g.get_mut(id) {
            Some(o) => { o.display_name = name.to_owned(); o.updated_at = now; Ok(()) }
            None    => Err(PortError::NotFound),
        }
    }
}
