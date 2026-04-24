//! In-memory `SigningKeyRepository`.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::repo::{PublicSigningKey, SigningKeyRepository};
use cesauth_core::ports::{PortError, PortResult};


#[derive(Debug, Default)]
pub struct InMemorySigningKeyRepository {
    inner: Mutex<HashMap<String, PublicSigningKey>>,
}

impl SigningKeyRepository for InMemorySigningKeyRepository {
    async fn list_active(&self) -> PortResult<Vec<PublicSigningKey>> {
        let m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.values().cloned().collect())
    }

    async fn register(&self, key: &PublicSigningKey) -> PortResult<()> {
        let mut m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        if m.contains_key(&key.kid) {
            return Err(PortError::Conflict);
        }
        m.insert(key.kid.clone(), key.clone());
        Ok(())
    }

    async fn retire(&self, kid: &str, retired_at: i64) -> PortResult<()> {
        let mut m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        let k = m.get_mut(kid).ok_or(PortError::NotFound)?;
        k.retired_at.get_or_insert(retired_at);
        Ok(())
    }
}
