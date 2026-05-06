//! In-memory `TotpAuthenticatorRepository` for tests.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::totp::storage::{TotpAuthenticator, TotpAuthenticatorRepository};


#[derive(Debug, Default)]
pub struct InMemoryTotpAuthenticatorRepository {
    by_id: Mutex<HashMap<String, TotpAuthenticator>>,
}

impl TotpAuthenticatorRepository for InMemoryTotpAuthenticatorRepository {
    async fn create(&self, row: &TotpAuthenticator) -> PortResult<()> {
        let mut m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        if m.contains_key(&row.id) {
            return Err(PortError::Conflict);
        }
        m.insert(row.id.clone(), row.clone());
        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> PortResult<Option<TotpAuthenticator>> {
        let m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.get(id).cloned())
    }

    async fn find_active_for_user(&self, user_id: &str)
        -> PortResult<Option<TotpAuthenticator>>
    {
        let m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        // "Most recently confirmed" — pick the row with the
        // largest `confirmed_at`. Ties are broken arbitrarily;
        // the find_active_returns_most_recent test pins this
        // semantic for the multi-authenticator case.
        let active = m.values()
            .filter(|r| r.user_id == user_id)
            .filter(|r| r.confirmed_at.is_some())
            .max_by_key(|r| r.confirmed_at.unwrap_or(0))
            .cloned();
        Ok(active)
    }

    async fn confirm(&self, id: &str, last_used_step: u64, now: i64)
        -> PortResult<()>
    {
        let mut m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        let row = m.get_mut(id).ok_or(PortError::NotFound)?;
        if row.confirmed_at.is_some() {
            // Idempotency: a second confirm is a no-op-as-error.
            // The HTTP layer maps NotFound to a 400 with a clear
            // message — confirming twice means the client is
            // confused, not that the server lost state.
            return Err(PortError::NotFound);
        }
        row.confirmed_at   = Some(now);
        row.last_used_step = last_used_step;
        row.last_used_at   = Some(now);
        Ok(())
    }

    async fn update_last_used_step(&self, id: &str, last_used_step: u64, now: i64)
        -> PortResult<()>
    {
        let mut m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        let row = m.get_mut(id).ok_or(PortError::NotFound)?;
        row.last_used_step = last_used_step;
        row.last_used_at   = Some(now);
        Ok(())
    }

    async fn delete(&self, id: &str) -> PortResult<()> {
        let mut m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        m.remove(id).ok_or(PortError::NotFound)?;
        Ok(())
    }

    async fn delete_all_for_user(&self, user_id: &str) -> PortResult<()> {
        // No-op-on-empty mirrors the recovery-codes adapter and
        // the trait contract. The disable-TOTP flow is best-effort
        // idempotent (see disable.rs module doc) so a second call
        // is harmless.
        let mut m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        m.retain(|_, r| r.user_id != user_id);
        Ok(())
    }

    async fn list_unconfirmed_older_than(&self, cutoff_unix: i64)
        -> PortResult<Vec<String>>
    {
        let m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.values()
            .filter(|r| r.confirmed_at.is_none())
            .filter(|r| r.created_at < cutoff_unix)
            .map(|r| r.id.clone())
            .collect())
    }
}
