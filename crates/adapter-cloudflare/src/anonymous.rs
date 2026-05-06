//! `AnonymousSessionRepository` D1 adapter (v0.16.0, ADR-004).
//!
//! Backs the `anonymous_sessions` table introduced in
//! migration `0006_anonymous.sql`. Same shape as the
//! `CloudflareAdminTokenRepository`: thin wrapper around prepared
//! D1 statements, error mapping through `PortError::*`.

use cesauth_core::anonymous::{AnonymousSession, AnonymousSessionRepository};
use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::types::UnixSeconds;
use serde::Deserialize;
use worker::Env;

use crate::ports::repo::{d1_int, db, run_err};

pub struct CloudflareAnonymousSessionRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareAnonymousSessionRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareAnonymousSessionRepository")
            .finish_non_exhaustive()
    }
}

impl<'a> CloudflareAnonymousSessionRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct SessionRow {
    token_hash: String,
    user_id:    String,
    tenant_id:  String,
    created_at: i64,
    expires_at: i64,
}

impl From<SessionRow> for AnonymousSession {
    fn from(r: SessionRow) -> Self {
        AnonymousSession {
            token_hash: r.token_hash,
            user_id:    r.user_id,
            tenant_id:  r.tenant_id,
            created_at: r.created_at,
            expires_at: r.expires_at,
        }
    }
}

impl AnonymousSessionRepository for CloudflareAnonymousSessionRepository<'_> {
    async fn create(
        &self,
        token_hash: &str,
        user_id:    &str,
        tenant_id:  &str,
        now_unix:   UnixSeconds,
        ttl_secs:   i64,
    ) -> PortResult<AnonymousSession> {
        let db = db(self.env)?;
        let expires = now_unix + ttl_secs;

        // The PK is `token_hash`. A duplicate hash means the caller
        // tried to insert the same plaintext twice — astronomically
        // unlikely but the DB is the layer that enforces. Treat it
        // as Conflict so the caller can pick a fresh handle.
        let stmt = db.prepare(
            "INSERT INTO anonymous_sessions \
              (token_hash, user_id, tenant_id, created_at, expires_at) \
              VALUES (?, ?, ?, ?, ?)"
        ).bind(&[
            token_hash.into(),
            user_id.into(),
            tenant_id.into(),
            d1_int(now_unix),
            d1_int(expires),
        ]).map_err(|e| run_err("anon_session_bind", e))?;

        match stmt.run().await {
            Ok(_)  => Ok(AnonymousSession {
                token_hash: token_hash.to_owned(),
                user_id:    user_id.to_owned(),
                tenant_id:  tenant_id.to_owned(),
                created_at: now_unix,
                expires_at: expires,
            }),
            Err(e) => {
                // SQLite reports UNIQUE-violations as "constraint
                // failed". The exact message format is brittle so
                // we match coarsely and fall back to Unavailable
                // for everything else.
                let msg = format!("{e:?}");
                if msg.contains("UNIQUE") || msg.contains("PRIMARY KEY") {
                    Err(PortError::Conflict)
                } else if msg.contains("FOREIGN KEY") {
                    // user_id or tenant_id doesn't exist — caller
                    // asked us to mint a session for a row that
                    // isn't there yet.
                    Err(PortError::NotFound)
                } else {
                    Err(run_err("anon_session_create", e))
                }
            }
        }
    }

    async fn find_by_hash(&self, token_hash: &str)
        -> PortResult<Option<AnonymousSession>>
    {
        let db = db(self.env)?;
        let row: Option<SessionRow> = db.prepare(
            "SELECT token_hash, user_id, tenant_id, created_at, expires_at \
             FROM anonymous_sessions WHERE token_hash = ?"
        ).bind(&[token_hash.into()])
            .map_err(|e| run_err("anon_session_find_bind", e))?
            .first(None).await
            .map_err(|_| PortError::Unavailable)?;
        Ok(row.map(AnonymousSession::from))
    }

    async fn revoke_for_user(&self, user_id: &str) -> PortResult<usize> {
        let db = db(self.env)?;
        let res = db.prepare(
            "DELETE FROM anonymous_sessions WHERE user_id = ?"
        ).bind(&[user_id.into()])
            .map_err(|e| run_err("anon_session_revoke_bind", e))?
            .run().await
            .map_err(|e| run_err("anon_session_revoke", e))?;
        let meta = res.meta().map_err(|_| PortError::Unavailable)?;
        Ok(meta.and_then(|m| m.changes).unwrap_or(0) as usize)
    }

    async fn delete_expired(&self, now_unix: UnixSeconds) -> PortResult<usize> {
        let db = db(self.env)?;
        let res = db.prepare(
            "DELETE FROM anonymous_sessions WHERE expires_at <= ?"
        ).bind(&[d1_int(now_unix)])
            .map_err(|e| run_err("anon_session_sweep_bind", e))?
            .run().await
            .map_err(|e| run_err("anon_session_sweep", e))?;
        let meta = res.meta().map_err(|_| PortError::Unavailable)?;
        Ok(meta.and_then(|m| m.changes).unwrap_or(0) as usize)
    }
}
