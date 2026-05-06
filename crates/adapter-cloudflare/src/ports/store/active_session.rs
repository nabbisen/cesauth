//! `ActiveSessionStore` adapter — Cloudflare DO + D1 index hybrid.
//!
//! v0.35.0 splits the adapter's responsibility:
//!
//! - The per-session `ActiveSession` DO remains the source of
//!   truth for individual session state. Hot operations (touch
//!   on every authenticated request, revoke, status) round-trip
//!   the DO and nothing else.
//!
//! - A D1 `user_sessions` table provides the per-user index
//!   that the DO layout structurally can't (DOs are
//!   single-keyed; cross-DO iteration isn't a thing). At
//!   `start` time the adapter writes BOTH the DO state AND the
//!   D1 index row; at `revoke` time it updates the DO AND
//!   mirrors `revoked_at` to the index. `list_for_user` reads
//!   the index without consulting the DO at all.
//!
//! The two stores are eventually consistent for the index
//! columns. The "newer" of (DO, D1) is always the DO since
//! the DO is the authoritative store for live operations and
//! the D1 update happens immediately after each successful DO
//! write.
//!
//! ADR-012 §"Sessions track" documents the design tradeoffs.

use cesauth_core::ports::store::{
    ActiveSessionStore, AuthMethod, SessionState, SessionStatus,
};
use cesauth_core::ports::{PortError, PortResult};
use serde::{Deserialize, Serialize};
use worker::{Env, Stub};

use super::super::repo::{d1_int, db, run_err};
use super::rpc_call;


#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum SessionCmd<'a> {
    Start  { state: &'a SessionState },
    /// **v0.35.0** — Touch carries the timeout config so the DO
    /// can do the idle/absolute checks atomically with the touch
    /// update.
    Touch  { now_unix: i64, idle_timeout_secs: i64, absolute_ttl_secs: i64 },
    Status,
    Revoke { now_unix: i64 },
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum SessionReply {
    Ok,
    Conflict,
    NotStarted,
    Active          { state: SessionState },
    Revoked         { state: SessionState },
    IdleExpired     { state: SessionState },
    AbsoluteExpired { state: SessionState },
}

pub struct CloudflareActiveSessionStore<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareActiveSessionStore<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareActiveSessionStore").finish_non_exhaustive()
    }
}

impl<'a> CloudflareActiveSessionStore<'a> {
    pub fn new(env: &'a Env) -> Self {
        Self { env }
    }

    fn stub(&self, session_id: &str) -> PortResult<Stub> {
        self.env
            .durable_object("ACTIVE_SESSION")
            .map_err(|_| PortError::Unavailable)?
            .id_from_name(session_id)
            .map_err(|_| PortError::Unavailable)?
            .get_stub()
            .map_err(|_| PortError::Unavailable)
    }

    /// Mirror the DO state's revoked_at into the D1 index.
    /// Best-effort: a D1 hiccup must not unwind a successful
    /// DO revoke.
    async fn mirror_revoked(&self, session_id: &str, revoked_at: i64) -> PortResult<()> {
        let db = db(self.env)?;
        let stmt = db.prepare(
            "UPDATE user_sessions SET revoked_at = ?1 WHERE session_id = ?2 AND revoked_at IS NULL",
        )
        .bind(&[d1_int(revoked_at), session_id.into()])
        .map_err(|e| run_err("user_sessions.mirror_revoked bind", e))?;
        stmt.run().await
            .map_err(|e| run_err("user_sessions.mirror_revoked run", e))?;
        Ok(())
    }
}

impl ActiveSessionStore for CloudflareActiveSessionStore<'_> {
    async fn start(&self, state: &SessionState) -> PortResult<()> {
        // 1. Authoritative DO write first.
        let stub  = self.stub(&state.session_id)?;
        let reply: SessionReply = rpc_call(&stub, &SessionCmd::Start { state }).await?;
        match reply {
            SessionReply::Ok       => {}
            SessionReply::Conflict => return Err(PortError::Conflict),
            _                      => return Err(PortError::Unavailable),
        }

        // 2. Index row in D1.
        let db = db(self.env)?;
        let stmt = db.prepare(
            "INSERT OR IGNORE INTO user_sessions \
             (session_id, user_id, created_at, revoked_at, auth_method, client_id) \
             VALUES (?1, ?2, ?3, NULL, ?4, ?5)",
        )
        .bind(&[
            state.session_id.as_str().into(),
            state.user_id.as_str().into(),
            d1_int(state.created_at),
            auth_method_to_str(state.auth_method).into(),
            state.client_id.as_str().into(),
        ])
        .map_err(|e| run_err("user_sessions.start bind", e))?;
        stmt.run().await
            .map_err(|e| run_err("user_sessions.start run", e))?;
        Ok(())
    }

    async fn touch(
        &self,
        session_id:        &str,
        now_unix:          i64,
        idle_timeout_secs: i64,
        absolute_ttl_secs: i64,
    ) -> PortResult<SessionStatus> {
        let stub  = self.stub(session_id)?;
        let reply: SessionReply = rpc_call(
            &stub,
            &SessionCmd::Touch { now_unix, idle_timeout_secs, absolute_ttl_secs },
        ).await?;

        // If the DO returned Idle/AbsoluteExpired, mirror the
        // revoke into the index. Best-effort.
        match &reply {
            SessionReply::IdleExpired     { state } |
            SessionReply::AbsoluteExpired { state } => {
                if let Some(rev) = state.revoked_at {
                    let _ = self.mirror_revoked(session_id, rev).await;
                }
            }
            _ => {}
        }
        Ok(from_reply(reply))
    }

    async fn status(&self, session_id: &str) -> PortResult<SessionStatus> {
        let stub  = self.stub(session_id)?;
        let reply: SessionReply = rpc_call(&stub, &SessionCmd::Status).await?;
        Ok(from_reply(reply))
    }

    async fn revoke(&self, session_id: &str, now_unix: i64) -> PortResult<SessionStatus> {
        let stub  = self.stub(session_id)?;
        let reply: SessionReply = rpc_call(&stub, &SessionCmd::Revoke { now_unix }).await?;
        if matches!(reply, SessionReply::Revoked { .. }) {
            let _ = self.mirror_revoked(session_id, now_unix).await;
        }
        Ok(from_reply(reply))
    }

    async fn list_for_user(
        &self,
        user_id:         &str,
        include_revoked: bool,
        limit:           u32,
    ) -> PortResult<Vec<SessionState>> {
        let db = db(self.env)?;
        let limit_val = limit.min(500) as i64;

        let sql = if include_revoked {
            "SELECT session_id, user_id, created_at, revoked_at, auth_method, client_id \
             FROM user_sessions WHERE user_id = ?1 \
             ORDER BY created_at DESC LIMIT ?2"
        } else {
            "SELECT session_id, user_id, created_at, revoked_at, auth_method, client_id \
             FROM user_sessions WHERE user_id = ?1 AND revoked_at IS NULL \
             ORDER BY created_at DESC LIMIT ?2"
        };

        let stmt = db.prepare(sql)
            .bind(&[user_id.into(), d1_int(limit_val)])
            .map_err(|e| run_err("user_sessions.list bind", e))?;
        let result = stmt.all().await.map_err(|_| PortError::Unavailable)?;
        let rows = result.results::<DbRow>().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().filter_map(DbRow::into_state).collect())
    }
}

fn from_reply(r: SessionReply) -> SessionStatus {
    match r {
        SessionReply::Active          { state } => SessionStatus::Active(state),
        SessionReply::Revoked         { state } => SessionStatus::Revoked(state),
        SessionReply::IdleExpired     { state } => SessionStatus::IdleExpired(state),
        SessionReply::AbsoluteExpired { state } => SessionStatus::AbsoluteExpired(state),
        _                                       => SessionStatus::NotStarted,
    }
}

fn auth_method_to_str(m: AuthMethod) -> &'static str {
    match m {
        AuthMethod::Passkey   => "passkey",
        AuthMethod::MagicLink => "magic_link",
        AuthMethod::Admin     => "admin",
    }
}

fn auth_method_from_str(s: &str) -> Option<AuthMethod> {
    match s {
        "passkey"    => Some(AuthMethod::Passkey),
        "magic_link" => Some(AuthMethod::MagicLink),
        "admin"      => Some(AuthMethod::Admin),
        _            => None,
    }
}

#[derive(Deserialize)]
struct DbRow {
    session_id:  String,
    user_id:     String,
    created_at:  i64,
    revoked_at:  Option<i64>,
    auth_method: String,
    client_id:   String,
}

impl DbRow {
    /// Project the index row into a `SessionState`. Returns
    /// `None` if the `auth_method` column doesn't decode (which
    /// would indicate a DDL drift bug; v0.35.0 doesn't add new
    /// auth methods).
    ///
    /// `last_seen_at` and `scopes` are not mirrored into the
    /// index — they're hot-path mutable in the DO and the
    /// user-facing list page doesn't render them. Set
    /// `last_seen_at = created_at` as a sentinel so callers that
    /// look at it see "well-defined but stale".
    fn into_state(self) -> Option<SessionState> {
        Some(SessionState {
            session_id:   self.session_id,
            user_id:      self.user_id,
            client_id:    self.client_id,
            scopes:       Vec::new(),
            auth_method:  auth_method_from_str(&self.auth_method)?,
            created_at:   self.created_at,
            last_seen_at: self.created_at,
            revoked_at:   self.revoked_at,
        })
    }
}
