//! In-memory `AuthenticatorRepository`.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::repo::AuthenticatorRepository;
use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::webauthn::StoredAuthenticator;


#[derive(Debug, Default)]
pub struct InMemoryAuthenticatorRepository {
    by_cred: Mutex<HashMap<String, StoredAuthenticator>>,
}

impl AuthenticatorRepository for InMemoryAuthenticatorRepository {
    async fn find_by_credential_id(
        &self,
        credential_id: &str,
    ) -> PortResult<Option<StoredAuthenticator>> {
        let m = self.by_cred.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.get(credential_id).cloned())
    }

    async fn list_by_user(&self, user_id: &str) -> PortResult<Vec<StoredAuthenticator>> {
        let m = self.by_cred.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.values().filter(|a| a.user_id == user_id).cloned().collect())
    }

    async fn create(&self, authn: &StoredAuthenticator) -> PortResult<()> {
        let mut m = self.by_cred.lock().map_err(|_| PortError::Unavailable)?;
        if m.contains_key(&authn.credential_id) {
            return Err(PortError::Conflict);
        }
        m.insert(authn.credential_id.clone(), authn.clone());
        Ok(())
    }

    async fn touch(
        &self,
        credential_id:  &str,
        new_sign_count: u32,
        last_used_at:   i64,
    ) -> PortResult<()> {
        let mut m = self.by_cred.lock().map_err(|_| PortError::Unavailable)?;
        let a = m.get_mut(credential_id).ok_or(PortError::NotFound)?;
        // Cloning detection: counter must be monotonically increasing.
        if new_sign_count != 0 && new_sign_count <= a.sign_count {
            return Err(PortError::PreconditionFailed("sign_count not monotonic"));
        }
        a.sign_count    = new_sign_count;
        a.last_used_at  = Some(last_used_at);
        Ok(())
    }

    async fn delete(&self, credential_id: &str) -> PortResult<()> {
        let mut m = self.by_cred.lock().map_err(|_| PortError::Unavailable)?;
        m.remove(credential_id).ok_or(PortError::NotFound)?;
        Ok(())
    }
}
