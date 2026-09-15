//! In-memory `AuthChallengeStore`.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::store::{AuthChallengeStore, Challenge};
use cesauth_core::ports::{PortError, PortResult};


#[derive(Debug, Default)]
pub struct InMemoryAuthChallengeStore {
    map: Mutex<HashMap<cesauth_core::types::ChallengeHandle, Challenge>>,
}

impl AuthChallengeStore for InMemoryAuthChallengeStore {
    async fn put(&self, handle: &cesauth_core::types::ChallengeHandle, challenge: &Challenge) -> PortResult<()> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        if m.contains_key(handle) {
            return Err(PortError::Conflict);
        }
        m.insert(handle.clone(), challenge.clone());
        Ok(())
    }

    // RFC 140: expired iff `now_unix >= expires_at()` (the port's contract).
    async fn peek(&self, handle: &cesauth_core::types::ChallengeHandle, now_unix: i64) -> PortResult<Option<Challenge>> {
        let m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.get(handle).filter(|c| now_unix < c.expires_at()).cloned())
    }

    async fn take(&self, handle: &cesauth_core::types::ChallengeHandle, now_unix: i64) -> PortResult<Option<Challenge>> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        // Removed whether live or expired; only a live entry is returned.
        Ok(m.remove(handle).filter(|c| now_unix < c.expires_at()))
    }

    async fn bump_magic_link_attempts(&self, handle: &cesauth_core::types::ChallengeHandle, now_unix: i64) -> PortResult<u32> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        let entry = m.get_mut(handle)
            .filter(|c| now_unix < c.expires_at())
            .ok_or(PortError::NotFound)?;
        match entry {
            Challenge::MagicLink { attempts, .. } => {
                *attempts = attempts.saturating_add(1);
                Ok(*attempts)
            }
            _ => Err(PortError::PreconditionFailed("not a magic link challenge")),
        }
    }
}
