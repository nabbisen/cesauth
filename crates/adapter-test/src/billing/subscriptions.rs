use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::billing::ports::SubscriptionRepository;
use cesauth_core::billing::types::{Subscription, SubscriptionStatus};
use cesauth_core::ports::{PortError, PortResult};

#[derive(Debug, Default)]
pub struct InMemorySubscriptionRepository {
    rows: Mutex<HashMap<String, Subscription>>,
}

impl SubscriptionRepository for InMemorySubscriptionRepository {
    async fn create(&self, s: &Subscription) -> PortResult<()> {
        let mut g = self.rows.lock().unwrap();
        if g.values().any(|r| r.tenant_id == s.tenant_id) {
            return Err(PortError::Conflict);
        }
        g.insert(s.id.clone(), s.clone());
        Ok(())
    }
    async fn current_for_tenant(&self, tenant: &str) -> PortResult<Option<Subscription>> {
        Ok(self.rows.lock().unwrap().values()
           .find(|s| s.tenant_id == tenant).cloned())
    }
    async fn set_plan(&self, id: &str, plan: &str, now: i64) -> PortResult<()> {
        let mut g = self.rows.lock().unwrap();
        match g.get_mut(id) {
            Some(s) => { s.plan_id = plan.to_owned(); s.updated_at = now; Ok(()) }
            None    => Err(PortError::NotFound),
        }
    }
    async fn set_status(&self, id: &str, status: SubscriptionStatus, now: i64) -> PortResult<()> {
        let mut g = self.rows.lock().unwrap();
        match g.get_mut(id) {
            Some(s) => {
                s.status = status; s.status_changed_at = now; s.updated_at = now; Ok(())
            }
            None    => Err(PortError::NotFound),
        }
    }
}
