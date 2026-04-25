use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::billing::ports::PlanRepository;
use cesauth_core::billing::types::Plan;
use cesauth_core::ports::PortResult;

#[derive(Debug, Default)]
pub struct InMemoryPlanRepository {
    rows: Mutex<HashMap<String, Plan>>,
}

impl InMemoryPlanRepository {
    /// Test helper: insert a plan. Tests construct their plans
    /// directly rather than through any creation API (there isn't
    /// one — plans are catalog data, seeded by the migration).
    pub fn insert(&self, p: Plan) {
        self.rows.lock().unwrap().insert(p.id.clone(), p);
    }
}

impl PlanRepository for InMemoryPlanRepository {
    async fn get(&self, id: &str) -> PortResult<Option<Plan>> {
        Ok(self.rows.lock().unwrap().get(id).cloned())
    }
    async fn find_by_slug(&self, slug: &str) -> PortResult<Option<Plan>> {
        Ok(self.rows.lock().unwrap().values().find(|p| p.slug == slug).cloned())
    }
    async fn list_active(&self) -> PortResult<Vec<Plan>> {
        Ok(self.rows.lock().unwrap().values().filter(|p| p.active).cloned().collect())
    }
}
