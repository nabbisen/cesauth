//! In-memory `AnonymousSessionRepository` for tests.
//!
//! HashMap behind a Mutex, same pattern as the other repository
//! adapters. The behaviours covered: insertion conflict on
//! duplicate hash, hot-path lookup by hash, mass revocation by
//! user_id, expired-row cleanup.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::anonymous::{AnonymousSession, AnonymousSessionRepository};
use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::types::UnixSeconds;

#[derive(Debug, Default)]
pub struct InMemoryAnonymousSessionRepository {
    /// Indexed by token_hash for hot-path lookup.
    inner: Mutex<HashMap<String, AnonymousSession>>,
}

impl AnonymousSessionRepository for InMemoryAnonymousSessionRepository {
    async fn create(
        &self,
        token_hash: &str,
        user_id:    &str,
        tenant_id:  &str,
        now_unix:   UnixSeconds,
        ttl_secs:   i64,
    ) -> PortResult<AnonymousSession> {
        let mut m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        if m.contains_key(token_hash) {
            return Err(PortError::Conflict);
        }
        let row = AnonymousSession {
            token_hash: token_hash.to_owned(),
            user_id:    user_id.to_owned(),
            tenant_id:  tenant_id.to_owned(),
            created_at: now_unix,
            expires_at: now_unix + ttl_secs,
        };
        m.insert(token_hash.to_owned(), row.clone());
        Ok(row)
    }

    async fn find_by_hash(&self, token_hash: &str)
        -> PortResult<Option<AnonymousSession>>
    {
        let m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.get(token_hash).cloned())
    }

    async fn revoke_for_user(&self, user_id: &str) -> PortResult<usize> {
        let mut m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        let before = m.len();
        m.retain(|_, row| row.user_id != user_id);
        Ok(before - m.len())
    }

    async fn delete_expired(&self, now_unix: UnixSeconds) -> PortResult<usize> {
        let mut m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        let before = m.len();
        m.retain(|_, row| !row.is_expired(now_unix));
        Ok(before - m.len())
    }
}

// =====================================================================
// Tests
// =====================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::anonymous::ANONYMOUS_TOKEN_TTL_SECONDS;

    #[tokio::test]
    async fn create_and_lookup_round_trip() {
        let repo = InMemoryAnonymousSessionRepository::default();
        let row = repo.create(
            "hash-abc", "u-1", "tenant-default",
            1_000, ANONYMOUS_TOKEN_TTL_SECONDS,
        ).await.unwrap();
        assert_eq!(row.user_id, "u-1");
        assert_eq!(row.expires_at, 1_000 + ANONYMOUS_TOKEN_TTL_SECONDS);

        let found = repo.find_by_hash("hash-abc").await.unwrap();
        assert_eq!(found, Some(row));
    }

    #[tokio::test]
    async fn create_returns_conflict_on_duplicate_hash() {
        // The PK is the hash. Astronomically unlikely collisions
        // still need a sane error path.
        let repo = InMemoryAnonymousSessionRepository::default();
        repo.create("h", "u-1", "tenant-default", 0, 60).await.unwrap();
        let err = repo.create("h", "u-2", "tenant-default", 0, 60).await
            .expect_err("duplicate hash must fail");
        assert!(matches!(err, PortError::Conflict));
    }

    #[tokio::test]
    async fn find_by_hash_returns_none_for_unknown() {
        let repo = InMemoryAnonymousSessionRepository::default();
        assert_eq!(repo.find_by_hash("nope").await.unwrap(), None);
    }

    #[tokio::test]
    async fn revoke_for_user_drops_only_that_users_sessions() {
        // The promotion path uses this: at promotion, every
        // anonymous bearer for the user is invalidated. Other
        // users' sessions must survive.
        let repo = InMemoryAnonymousSessionRepository::default();
        repo.create("h-alice-1", "u-alice", "t", 0, 60).await.unwrap();
        repo.create("h-alice-2", "u-alice", "t", 0, 60).await.unwrap();
        repo.create("h-bob",     "u-bob",   "t", 0, 60).await.unwrap();

        let removed = repo.revoke_for_user("u-alice").await.unwrap();
        assert_eq!(removed, 2);

        assert_eq!(repo.find_by_hash("h-alice-1").await.unwrap(), None);
        assert_eq!(repo.find_by_hash("h-alice-2").await.unwrap(), None);
        // Bob's session is untouched.
        assert!(repo.find_by_hash("h-bob").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn revoke_for_user_is_idempotent() {
        // Calling revoke when no sessions exist returns Ok(0),
        // not an error. The promotion path may have already
        // lost the bearer; the second call should be a no-op.
        let repo = InMemoryAnonymousSessionRepository::default();
        let removed = repo.revoke_for_user("u-ghost").await.unwrap();
        assert_eq!(removed, 0);
    }

    #[tokio::test]
    async fn delete_expired_uses_expires_at_threshold() {
        let repo = InMemoryAnonymousSessionRepository::default();
        // Three rows with different expires_at.
        repo.create("h-1", "u-1", "t", 0,   100).await.unwrap();  // expires at 100
        repo.create("h-2", "u-2", "t", 50,  100).await.unwrap();  // expires at 150
        repo.create("h-3", "u-3", "t", 200, 100).await.unwrap();  // expires at 300

        // At now=120: rows 1 (expired) and not 2 or 3.
        let removed = repo.delete_expired(120).await.unwrap();
        assert_eq!(removed, 1);
        assert_eq!(repo.find_by_hash("h-1").await.unwrap(), None);
        assert!(repo.find_by_hash("h-2").await.unwrap().is_some());
        assert!(repo.find_by_hash("h-3").await.unwrap().is_some());

        // At now=200: row 2 is now also expired.
        let removed = repo.delete_expired(200).await.unwrap();
        assert_eq!(removed, 1);

        // Row 3 still alive.
        assert!(repo.find_by_hash("h-3").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn is_expired_treats_boundary_as_expired() {
        // ADR-004 Q2: tokens expire AT or after expires_at. The
        // exact boundary case (now == expires_at) is "expired".
        let row = AnonymousSession {
            token_hash: "h".into(), user_id: "u".into(),
            tenant_id: "t".into(), created_at: 0, expires_at: 100,
        };
        assert!(!row.is_expired(99));
        assert!( row.is_expired(100), "boundary is inclusive of expired");
        assert!( row.is_expired(101));
    }
}
