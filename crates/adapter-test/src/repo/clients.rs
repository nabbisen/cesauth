//! In-memory `ClientRepository`.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::repo::{ClientAuthView, ClientRepository};
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

    async fn find_auth_view(&self, client_id: &str) -> PortResult<Option<ClientAuthView>> {
        let m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.get(client_id).map(|(client, secret_hash)| ClientAuthView {
            client_id:          client.id.clone(),
            client_type:        client.client_type,
            client_secret_hash: secret_hash.clone(),
            audience:           client.audience.clone(),
            token_auth_method:  client.token_auth_method,
        }))
    }

    async fn create(&self, client: &OidcClient, secret_hash: Option<&str>) -> PortResult<()> {
        let mut m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        if m.contains_key(&client.id) {
            return Err(PortError::Conflict);
        }
        m.insert(client.id.clone(), (client.clone(), secret_hash.map(str::to_owned)));
        Ok(())
    }

    async fn list(&self) -> PortResult<Vec<OidcClient>> {
        let m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        let mut clients: Vec<OidcClient> = m.values().map(|(c, _)| c.clone()).collect();
        clients.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(clients)
    }

    async fn update(&self, client: &OidcClient) -> PortResult<()> {
        let mut m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        let Some((existing, _)) = m.get_mut(&client.id) else {
            return Err(PortError::NotFound);
        };
        // Mirror the adapter's column list (RFC 141 C1-141 item 3):
        // client_type is not updatable here (see the trait doc);
        // token_auth_method is.
        existing.name              = client.name.clone();
        existing.redirect_uris     = client.redirect_uris.clone();
        existing.allowed_scopes    = client.allowed_scopes.clone();
        existing.token_auth_method = client.token_auth_method;
        existing.require_pkce      = client.require_pkce;
        existing.audience          = client.audience.clone();
        Ok(())
    }

    async fn set_secret_hash(&self, client_id: &str, secret_hash: Option<&str>) -> PortResult<()> {
        let mut m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        let Some(entry) = m.get_mut(client_id) else {
            return Err(PortError::NotFound);
        };
        entry.1 = secret_hash.map(str::to_owned);
        Ok(())
    }

    async fn delete(&self, client_id: &str) -> PortResult<()> {
        let mut m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        if m.remove(client_id).is_none() {
            return Err(PortError::NotFound);
        }
        Ok(())
    }
}
