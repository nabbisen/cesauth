//! In-memory `ActiveSessionStore`.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::store::{ActiveSessionStore, SessionState, SessionStatus};
use cesauth_core::ports::{PortError, PortResult};


#[derive(Debug, Default)]
pub struct InMemoryActiveSessionStore {
    map: Mutex<HashMap<String, SessionState>>,
}

impl ActiveSessionStore for InMemoryActiveSessionStore {
    async fn start(&self, state: &SessionState) -> PortResult<()> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        if m.contains_key(&state.session_id) {
            return Err(PortError::Conflict);
        }
        m.insert(state.session_id.clone(), state.clone());
        Ok(())
    }

    async fn touch(&self, session_id: &str, now_unix: i64) -> PortResult<SessionStatus> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        match m.get_mut(session_id) {
            None => Ok(SessionStatus::NotStarted),
            Some(s) if s.revoked_at.is_some() => Ok(SessionStatus::Revoked(s.clone())),
            Some(s) => {
                s.last_seen_at = now_unix;
                Ok(SessionStatus::Active(s.clone()))
            }
        }
    }

    async fn status(&self, session_id: &str) -> PortResult<SessionStatus> {
        let m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        Ok(match m.get(session_id) {
            None => SessionStatus::NotStarted,
            Some(s) if s.revoked_at.is_some() => SessionStatus::Revoked(s.clone()),
            Some(s) => SessionStatus::Active(s.clone()),
        })
    }

    async fn revoke(&self, session_id: &str, now_unix: i64) -> PortResult<SessionStatus> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        match m.get_mut(session_id) {
            None => Ok(SessionStatus::NotStarted),
            Some(s) => {
                if s.revoked_at.is_none() {
                    s.revoked_at = Some(now_unix);
                }
                Ok(SessionStatus::Revoked(s.clone()))
            }
        }
    }
}
