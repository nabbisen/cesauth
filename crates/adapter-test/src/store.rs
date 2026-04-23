//! In-memory implementations of the DO-shaped store ports.
//!
//! Each impl uses a single `Mutex<HashMap>` keyed by the handle. Since
//! all of `async fn` here is synchronous under the hood, the mutex is a
//! faithful stand-in for per-key DO serialization: two concurrent
//! callers will be ordered, the first wins state transitions, the
//! second sees the post-first state.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::store::{
    ActiveSessionStore, AuthChallengeStore, Challenge, FamilyInit, FamilyState,
    RateLimitDecision, RateLimitStore, RefreshTokenFamilyStore, RotateOutcome, SessionState,
    SessionStatus,
};
use cesauth_core::ports::{PortError, PortResult};

// -------------------------------------------------------------------------
// AuthChallengeStore
// -------------------------------------------------------------------------

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

// -------------------------------------------------------------------------
// RefreshTokenFamilyStore
// -------------------------------------------------------------------------

const RETIRED_RING_SIZE: usize = 16;

#[derive(Debug, Default)]
pub struct InMemoryRefreshTokenFamilyStore {
    map: Mutex<HashMap<String, FamilyState>>,
}

impl RefreshTokenFamilyStore for InMemoryRefreshTokenFamilyStore {
    async fn init(&self, init: &FamilyInit) -> PortResult<()> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        if m.contains_key(&init.family_id) {
            return Err(PortError::Conflict);
        }
        m.insert(
            init.family_id.clone(),
            FamilyState {
                family_id:       init.family_id.clone(),
                user_id:         init.user_id.clone(),
                client_id:       init.client_id.clone(),
                scopes:          init.scopes.clone(),
                current_jti:     init.first_jti.clone(),
                retired_jtis:    Vec::new(),
                created_at:      init.now_unix,
                last_rotated_at: init.now_unix,
                revoked_at:      None,
            },
        );
        Ok(())
    }

    async fn rotate(
        &self,
        family_id:     &str,
        presented_jti: &str,
        new_jti:       &str,
        now_unix:      i64,
    ) -> PortResult<RotateOutcome> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        let fam = m.get_mut(family_id).ok_or(PortError::NotFound)?;

        if fam.revoked_at.is_some() {
            return Ok(RotateOutcome::AlreadyRevoked);
        }

        if presented_jti == fam.current_jti {
            // Rotation.
            let old = std::mem::replace(&mut fam.current_jti, new_jti.to_owned());
            fam.retired_jtis.push(old);
            if fam.retired_jtis.len() > RETIRED_RING_SIZE {
                fam.retired_jtis.remove(0);
            }
            fam.last_rotated_at = now_unix;
            Ok(RotateOutcome::Rotated { new_current_jti: new_jti.to_owned() })
        } else {
            // Reuse or unknown. Either way, burn the family.
            fam.revoked_at = Some(now_unix);
            Ok(RotateOutcome::ReusedAndRevoked)
        }
    }

    async fn revoke(&self, family_id: &str, now_unix: i64) -> PortResult<()> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        let fam = m.get_mut(family_id).ok_or(PortError::NotFound)?;
        if fam.revoked_at.is_none() {
            fam.revoked_at = Some(now_unix);
        }
        Ok(())
    }

    async fn peek(&self, family_id: &str) -> PortResult<Option<FamilyState>> {
        let m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.get(family_id).cloned())
    }
}

// -------------------------------------------------------------------------
// ActiveSessionStore
// -------------------------------------------------------------------------

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

// -------------------------------------------------------------------------
// RateLimitStore
// -------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Window {
    start: i64,
    count: u32,
}

#[derive(Debug, Default)]
pub struct InMemoryRateLimitStore {
    map: Mutex<HashMap<String, Window>>,
}

impl RateLimitStore for InMemoryRateLimitStore {
    async fn hit(
        &self,
        bucket_key:     &str,
        now_unix:       i64,
        window_secs:    i64,
        limit:          u32,
        escalate_after: u32,
    ) -> PortResult<RateLimitDecision> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        let w = m
            .entry(bucket_key.to_owned())
            .or_insert(Window { start: now_unix, count: 0 });
        if now_unix.saturating_sub(w.start) >= window_secs {
            *w = Window { start: now_unix, count: 0 };
        }
        w.count = w.count.saturating_add(1);
        Ok(RateLimitDecision {
            allowed:   w.count <= limit,
            count:     w.count,
            limit,
            resets_in: window_secs.saturating_sub(now_unix.saturating_sub(w.start)),
            escalate:  w.count > escalate_after,
        })
    }

    async fn reset(&self, bucket_key: &str) -> PortResult<()> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        m.remove(bucket_key);
        Ok(())
    }
}

// -------------------------------------------------------------------------
// Tests - exercise the domain rules through these adapters.
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::ports::store::{AuthChallengeStore, Challenge};
    use cesauth_core::types::Scopes;

    fn sample_auth_code() -> Challenge {
        Challenge::AuthCode {
            client_id:             "c".into(),
            redirect_uri:          "https://app/cb".into(),
            user_id:               "u".into(),
            scopes:                Scopes(vec!["openid".into()]),
            nonce:                 None,
            code_challenge:        "x".into(),
            code_challenge_method: "S256".into(),
            issued_at:             0,
            expires_at:             60,
        }
    }

    #[tokio::test]
    async fn auth_code_single_consumption() {
        let store = InMemoryAuthChallengeStore::default();
        store.put("h", &sample_auth_code()).await.unwrap();
        // First take wins.
        assert!(store.take("h").await.unwrap().is_some());
        // Second take sees empty. This is the single-consumption invariant.
        assert!(store.take("h").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn auth_code_put_no_overwrite() {
        let store = InMemoryAuthChallengeStore::default();
        store.put("h", &sample_auth_code()).await.unwrap();
        assert!(matches!(
            store.put("h", &sample_auth_code()).await,
            Err(PortError::Conflict)
        ));
    }

    #[tokio::test]
    async fn refresh_reuse_burns_family() {
        let store = InMemoryRefreshTokenFamilyStore::default();
        let init = FamilyInit {
            family_id: "f".into(),
            user_id:   "u".into(),
            client_id: "c".into(),
            scopes:    vec!["openid".into()],
            first_jti: "j1".into(),
            now_unix:  0,
        };
        store.init(&init).await.unwrap();

        // Rotate once legitimately.
        let out = store.rotate("f", "j1", "j2", 10).await.unwrap();
        assert!(matches!(out, RotateOutcome::Rotated { .. }));

        // Present the old jti - reuse detection must fire.
        let out = store.rotate("f", "j1", "j3", 20).await.unwrap();
        assert!(matches!(out, RotateOutcome::ReusedAndRevoked));

        // Even the legitimate new jti no longer rotates - family is dead.
        let out = store.rotate("f", "j2", "j4", 30).await.unwrap();
        assert!(matches!(out, RotateOutcome::AlreadyRevoked));
    }

    #[tokio::test]
    async fn rate_limit_window_rolls() {
        let store = InMemoryRateLimitStore::default();
        for i in 0..5 {
            let d = store.hit("k", i, 10, 3, 2).await.unwrap();
            // After 3 hits we're past limit; after 2 we escalate.
            if i < 3 { assert!(d.allowed); } else { assert!(!d.allowed); }
            if i >= 2 { assert!(d.escalate); }
        }
        // Beyond window: fresh counter.
        let d = store.hit("k", 100, 10, 3, 2).await.unwrap();
        assert_eq!(d.count, 1);
        assert!(d.allowed);
        assert!(!d.escalate);
    }
}
