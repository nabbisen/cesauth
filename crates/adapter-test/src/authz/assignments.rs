use std::sync::Mutex;

use cesauth_core::authz::ports::RoleAssignmentRepository;
use cesauth_core::authz::types::{RoleAssignment, Scope};
use cesauth_core::ports::PortResult;

#[derive(Debug, Default)]
pub struct InMemoryRoleAssignmentRepository {
    rows: Mutex<Vec<RoleAssignment>>,
}

impl RoleAssignmentRepository for InMemoryRoleAssignmentRepository {
    async fn create(&self, a: &RoleAssignment) -> PortResult<()> {
        self.rows.lock().unwrap().push(a.clone());
        Ok(())
    }
    async fn delete(&self, id: &str) -> PortResult<()> {
        self.rows.lock().unwrap().retain(|r| r.id != id);
        Ok(())
    }
    async fn list_for_user(&self, user_id: &str) -> PortResult<Vec<RoleAssignment>> {
        Ok(self.rows.lock().unwrap().iter()
           .filter(|r| r.user_id == user_id).cloned().collect())
    }
    async fn list_in_scope(&self, scope: &Scope) -> PortResult<Vec<RoleAssignment>> {
        Ok(self.rows.lock().unwrap().iter()
           .filter(|r| &r.scope == scope).cloned().collect())
    }
    async fn purge_expired(&self, now: i64) -> PortResult<u64> {
        let mut g = self.rows.lock().unwrap();
        let before = g.len();
        g.retain(|a| match a.expires_at {
            Some(t) => t > now,
            None    => true,
        });
        Ok((before - g.len()) as u64)
    }
}
