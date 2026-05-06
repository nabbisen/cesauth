//! In-memory `UserRepository`.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::repo::UserRepository;
use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::tenancy::AccountType;
use cesauth_core::types::{UnixSeconds, User};


#[derive(Debug, Default)]
pub struct InMemoryUserRepository {
    by_id: Mutex<HashMap<String, User>>,
}

impl UserRepository for InMemoryUserRepository {
    async fn find_by_id(&self, id: &str) -> PortResult<Option<User>> {
        let m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.get(id).cloned())
    }

    async fn find_by_email(&self, email: &str) -> PortResult<Option<User>> {
        let needle = email.to_ascii_lowercase();
        let m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.values()
            .find(|u| u.email.as_deref().is_some_and(|e| e.to_ascii_lowercase() == needle))
            .cloned())
    }

    async fn create(&self, user: &User) -> PortResult<()> {
        let mut m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        if m.contains_key(&user.id) {
            return Err(PortError::Conflict);
        }
        if let Some(ref email) = user.email {
            let lowered = email.to_ascii_lowercase();
            if m.values()
                .any(|u| u.email.as_deref().is_some_and(|e| e.to_ascii_lowercase() == lowered))
            {
                return Err(PortError::Conflict);
            }
        }
        m.insert(user.id.clone(), user.clone());
        Ok(())
    }

    async fn update(&self, user: &User) -> PortResult<()> {
        let mut m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        if !m.contains_key(&user.id) {
            return Err(PortError::NotFound);
        }
        m.insert(user.id.clone(), user.clone());
        Ok(())
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> PortResult<Vec<User>> {
        let m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        let mut out: Vec<User> = m.values()
            .filter(|u| u.tenant_id == tenant_id
                     && !matches!(u.status, cesauth_core::types::UserStatus::Deleted))
            .cloned()
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    async fn list_anonymous_expired(
        &self,
        cutoff_unix: UnixSeconds,
    ) -> PortResult<Vec<User>> {
        // Mirror the SQL: account_type='anonymous' AND email IS NULL
        // AND created_at < cutoff. The email-IS-NULL clause is what
        // skips promoted rows; ADR-004 §Q3.
        let m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        let mut out: Vec<User> = m.values()
            .filter(|u| u.account_type == AccountType::Anonymous
                     && u.email.is_none()
                     && u.created_at < cutoff_unix)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    async fn delete_by_id(&self, id: &str) -> PortResult<()> {
        let mut m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        m.remove(id);
        // Idempotent: missing row is not an error. The sweep may
        // race with itself or with a concurrent admin delete.
        Ok(())
    }
}
