//! `ActiveSessionStore` DO adapter.

use cesauth_core::ports::store::{ActiveSessionStore, SessionState, SessionStatus};
use cesauth_core::ports::{PortError, PortResult};
use serde::{Deserialize, Serialize};
use worker::{Env, Stub};

use super::rpc_call;


#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum SessionCmd<'a> {
    Start  { state: &'a SessionState },
    Touch  { now_unix: i64 },
    Status,
    Revoke { now_unix: i64 },
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum SessionReply {
    Ok,
    Conflict,
    NotStarted,
    Active  { state: SessionState },
    Revoked { state: SessionState },
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
}

impl ActiveSessionStore for CloudflareActiveSessionStore<'_> {
    async fn start(&self, state: &SessionState) -> PortResult<()> {
        let stub  = self.stub(&state.session_id)?;
        let reply: SessionReply = rpc_call(&stub, &SessionCmd::Start { state }).await?;
        match reply {
            SessionReply::Ok       => Ok(()),
            SessionReply::Conflict => Err(PortError::Conflict),
            _                      => Err(PortError::Unavailable),
        }
    }

    async fn touch(&self, session_id: &str, now_unix: i64) -> PortResult<SessionStatus> {
        let stub  = self.stub(session_id)?;
        let reply: SessionReply = rpc_call(&stub, &SessionCmd::Touch { now_unix }).await?;
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
        Ok(from_reply(reply))
    }
}

fn from_reply(r: SessionReply) -> SessionStatus {
    match r {
        SessionReply::Active  { state } => SessionStatus::Active(state),
        SessionReply::Revoked { state } => SessionStatus::Revoked(state),
        _                               => SessionStatus::NotStarted,
    }
}
