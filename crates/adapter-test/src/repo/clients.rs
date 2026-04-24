//! In-memory `ClientRepository`.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::repo::ClientRepository;
use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::types::OidcClient;


#[derive(Debug, Default)]
pub struct InMemoryClientRepository {
    inner: Mutex<HashMap<String, (OidcClient, Option<String>)>>,
}

impl ClientRepository for InMemoryClientRepository {
    async fn find(&self, client_id: &str) -> PortResult<Option<OidcClient>> {
        let m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.get(client_id).map(|(c, _)| c.clone()))
    }

    async fn client_secret_hash(&self, client_id: &str) -> PortResult<Option<String>> {
        let m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.get(client_id).and_then(|(_, h)| h.clone()))
    }

    async fn create(&self, client: &OidcClient, secret_hash: Option<&str>) -> PortResult<()> {
        let mut m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        if m.contains_key(&client.id) {
            return Err(PortError::Conflict);
        }
        m.insert(client.id.clone(), (client.clone(), secret_hash.map(str::to_owned)));
        Ok(())
    }
}
