//! In-memory `GrantRepository`.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::repo::{Grant, GrantRepository};
use cesauth_core::ports::{PortError, PortResult};


#[derive(Debug, Default)]
pub struct InMemoryGrantRepository {
    inner: Mutex<HashMap<String, Grant>>,
}

impl GrantRepository for InMemoryGrantRepository {
    async fn create(&self, grant: &Grant) -> PortResult<()> {
        let mut m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        if m.contains_key(&grant.id) {
            return Err(PortError::Conflict);
        }
        m.insert(grant.id.clone(), grant.clone());
        Ok(())
    }

    async fn list_active_for_user(&self, user_id: &str) -> PortResult<Vec<Grant>> {
        let m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.values()
            .filter(|g| g.user_id == user_id && g.revoked_at.is_none())
            .cloned()
            .collect())
    }

    async fn mark_revoked(&self, grant_id: &str, now_unix: i64) -> PortResult<()> {
        let mut m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        let g = m.get_mut(grant_id).ok_or(PortError::NotFound)?;
        g.revoked_at.get_or_insert(now_unix);
        Ok(())
    }
}
