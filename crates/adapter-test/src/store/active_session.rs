//! In-memory `ActiveSessionStore`.
//!
//! v0.35.0 extends the store with idle-timeout checks (consulted
//! inside `touch` so the check is atomic with the touch update)
//! and a per-user listing capability (`list_for_user`). The
//! map is keyed on session_id; `list_for_user` does an O(n)
//! scan, which is fine for tests — the production CF adapter
//! uses a dedicated index DO instead.

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

    async fn touch(
        &self,
        session_id:        &str,
        now_unix:          i64,
        idle_timeout_secs: i64,
        absolute_ttl_secs: i64,
    ) -> PortResult<SessionStatus> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        let Some(s) = m.get_mut(session_id) else {
            return Ok(SessionStatus::NotStarted);
        };
        if s.revoked_at.is_some() {
            return Ok(SessionStatus::Revoked(s.clone()));
        }

        // Absolute lifetime check first — a session past its
        // hard cap is gone regardless of activity. Order
        // matters: a session may be both idle AND past its
        // absolute lifetime; we report the absolute case for
        // forensic clarity (it's the deeper-cause).
        if absolute_ttl_secs > 0 && s.created_at + absolute_ttl_secs <= now_unix {
            s.revoked_at = Some(now_unix);
            return Ok(SessionStatus::AbsoluteExpired(s.clone()));
        }

        // Idle check: if `idle_timeout_secs > 0` AND
        // `last_seen_at + idle_timeout_secs <= now`, expire.
        // Setting idle_timeout_secs to 0 disables this gate.
        if idle_timeout_secs > 0 && s.last_seen_at + idle_timeout_secs <= now_unix {
            s.revoked_at = Some(now_unix);
            return Ok(SessionStatus::IdleExpired(s.clone()));
        }

        // Otherwise the session is active. Bump last_seen_at.
        s.last_seen_at = now_unix;
        Ok(SessionStatus::Active(s.clone()))
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

    async fn list_for_user(
        &self,
        user_id:         &str,
        include_revoked: bool,
        limit:           u32,
    ) -> PortResult<Vec<SessionState>> {
        let m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        let mut out: Vec<SessionState> = m.values()
            .filter(|s| s.user_id == user_id)
            .filter(|s| include_revoked || s.revoked_at.is_none())
            .cloned()
            .collect();
        // Newest-first by created_at.
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        out.truncate(limit as usize);
        Ok(out)
    }
}