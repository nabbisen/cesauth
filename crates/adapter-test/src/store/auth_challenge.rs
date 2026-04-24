//! In-memory `AuthChallengeStore`.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::store::{AuthChallengeStore, Challenge};
use cesauth_core::ports::{PortError, PortResult};


#[derive(Debug, Default)]
pub struct InMemoryAuthChallengeStore {
    map: Mutex<HashMap<String, Challenge>>,
}

impl AuthChallengeStore for InMemoryAuthChallengeStore {
    async fn put(&self, handle: &str, challenge: &Challenge) -> PortResult<()> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        if m.contains_key(handle) {
            return Err(PortError::Conflict);
        }
        m.insert(handle.to_owned(), challenge.clone());
        Ok(())
    }

    async fn peek(&self, handle: &str) -> PortResult<Option<Challenge>> {
        let m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.get(handle).cloned())
    }

    async fn take(&self, handle: &str) -> PortResult<Option<Challenge>> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.remove(handle))
    }

    async fn bump_magic_link_attempts(&self, handle: &str) -> PortResult<u32> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        let entry = m.get_mut(handle).ok_or(PortError::NotFound)?;
        match entry {
            Challenge::MagicLink { attempts, .. } => {
                *attempts = attempts.saturating_add(1);
                Ok(*attempts)
            }
            _ => Err(PortError::PreconditionFailed("not a magic link challenge")),
        }
    }
}
