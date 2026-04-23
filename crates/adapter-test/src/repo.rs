//! In-memory repository implementations.
//!
//! Not a lot to say: these are HashMaps behind Mutexes. The behaviours
//! worth checking (case-insensitive email lookup, conflict on create)
//! are encoded in tests against this module, which means: if the
//! Cloudflare D1 adapter later diverges on semantics, we know the
//! divergence by replacing this with the D1 adapter in those same
//! tests and watching them fail.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::repo::{
    AuthenticatorRepository, ClientRepository, Grant, GrantRepository, PublicSigningKey,
    SigningKeyRepository, UserRepository,
};
use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::types::{OidcClient, User};
use cesauth_core::webauthn::StoredAuthenticator;

// -------------------------------------------------------------------------
// UserRepository
// -------------------------------------------------------------------------

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
}

// -------------------------------------------------------------------------
// ClientRepository
// -------------------------------------------------------------------------

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

// -------------------------------------------------------------------------
// AuthenticatorRepository
// -------------------------------------------------------------------------

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

// -------------------------------------------------------------------------
// GrantRepository
// -------------------------------------------------------------------------

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

// -------------------------------------------------------------------------
// SigningKeyRepository
// -------------------------------------------------------------------------

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

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::types::UserStatus;

    fn u(id: &str, email: Option<&str>) -> User {
        User {
            id: id.into(),
            email: email.map(str::to_owned),
            email_verified: false,
            display_name: None,
            status: UserStatus::Active,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[tokio::test]
    async fn email_lookup_is_case_insensitive() {
        let repo = InMemoryUserRepository::default();
        repo.create(&u("1", Some("A@Example.com"))).await.unwrap();
        assert!(repo.find_by_email("a@example.com").await.unwrap().is_some());
        assert!(repo.find_by_email("A@EXAMPLE.COM").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn email_unique_across_case() {
        let repo = InMemoryUserRepository::default();
        repo.create(&u("1", Some("a@example.com"))).await.unwrap();
        assert!(matches!(
            repo.create(&u("2", Some("A@Example.COM"))).await,
            Err(PortError::Conflict)
        ));
    }
}
