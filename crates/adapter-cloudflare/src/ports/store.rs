//! DO-backed implementations of the core store ports.
//!
//! Each adapter here talks to one DO class via the `Env` binding.
//! The pattern is always:
//!
//! 1. Look up the DO namespace (`env.durable_object("...")`).
//! 2. Derive the DO id from a domain key (auth handle, family id,
//!    session id, bucket key). We use `id_from_name(...)` so the same
//!    key consistently addresses the same DO instance.
//! 3. Build a stub, call `.fetch_with_request(...)` with a POSTed JSON
//!    command, decode the reply.
//!
//! The fetch URL we send is a dummy - DOs don't route by URL, only by
//! id. We use `https://do/` purely because `Request::new_with_init`
//! requires some URL string.

use cesauth_core::ports::store::{
    ActiveSessionStore, AuthChallengeStore, Challenge, FamilyInit, FamilyState,
    RateLimitDecision, RateLimitStore, RefreshTokenFamilyStore, RotateOutcome, SessionState,
    SessionStatus,
};
use cesauth_core::ports::{PortError, PortResult};
use serde::{Deserialize, Serialize};
use worker::{Env, Method, Request, RequestInit, Stub};

/// Build a Request carrying a JSON command body. Used by every
/// adapter below.
fn rpc_request<C: Serialize>(cmd: &C) -> Result<Request, PortError> {
    let body = serde_json::to_string(cmd).map_err(|_| PortError::Serialization)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_body(Some(body.into()));
    Request::new_with_init("https://do/", &init).map_err(|_| PortError::Unavailable)
}

async fn rpc_call<C, R>(stub: &Stub, cmd: &C) -> PortResult<R>
where
    C: Serialize,
    R: for<'de> Deserialize<'de>,
{
    let req  = rpc_request(cmd)?;
    let mut resp = stub.fetch_with_request(req).await.map_err(|_| PortError::Unavailable)?;
    resp.json::<R>().await.map_err(|_| PortError::Serialization)
}

// -------------------------------------------------------------------------
// AuthChallengeStore
// -------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum ChallengeCmd<'a> {
    Put { challenge: &'a Challenge },
    Peek,
    Take,
    Bump,
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ChallengeReply {
    Ok,
    Conflict,
    Value    { challenge: Option<Challenge> },
    Attempts { count: u32 },
    NotFound,
    PreconditionFailed,
}

pub struct CloudflareAuthChallengeStore<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareAuthChallengeStore<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareAuthChallengeStore").finish_non_exhaustive()
    }
}

impl<'a> CloudflareAuthChallengeStore<'a> {
    pub fn new(env: &'a Env) -> Self {
        Self { env }
    }

    fn stub(&self, handle: &str) -> PortResult<Stub> {
        self.env
            .durable_object("AUTH_CHALLENGE")
            .map_err(|_| PortError::Unavailable)?
            .id_from_name(handle)
            .map_err(|_| PortError::Unavailable)?
            .get_stub()
            .map_err(|_| PortError::Unavailable)
    }
}

impl AuthChallengeStore for CloudflareAuthChallengeStore<'_> {
    async fn put(&self, handle: &str, challenge: &Challenge) -> PortResult<()> {
        let stub  = self.stub(handle)?;
        let reply: ChallengeReply = rpc_call(&stub, &ChallengeCmd::Put { challenge }).await?;
        match reply {
            ChallengeReply::Ok       => Ok(()),
            ChallengeReply::Conflict => Err(PortError::Conflict),
            _                        => Err(PortError::Unavailable),
        }
    }

    async fn peek(&self, handle: &str) -> PortResult<Option<Challenge>> {
        let stub  = self.stub(handle)?;
        let reply: ChallengeReply = rpc_call(&stub, &ChallengeCmd::Peek).await?;
        match reply {
            ChallengeReply::Value { challenge } => Ok(challenge),
            _                                    => Err(PortError::Unavailable),
        }
    }

    async fn take(&self, handle: &str) -> PortResult<Option<Challenge>> {
        let stub  = self.stub(handle)?;
        let reply: ChallengeReply = rpc_call(&stub, &ChallengeCmd::Take).await?;
        match reply {
            ChallengeReply::Value { challenge } => Ok(challenge),
            _                                    => Err(PortError::Unavailable),
        }
    }

    async fn bump_magic_link_attempts(&self, handle: &str) -> PortResult<u32> {
        let stub  = self.stub(handle)?;
        let reply: ChallengeReply = rpc_call(&stub, &ChallengeCmd::Bump).await?;
        match reply {
            ChallengeReply::Attempts { count }      => Ok(count),
            ChallengeReply::NotFound                => Err(PortError::NotFound),
            ChallengeReply::PreconditionFailed      => Err(PortError::PreconditionFailed(
                "not a magic link challenge",
            )),
            _ => Err(PortError::Unavailable),
        }
    }
}

// -------------------------------------------------------------------------
// RefreshTokenFamilyStore
// -------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum FamilyCmd<'a> {
    Init   { init:          &'a FamilyInit },
    Rotate { presented_jti: &'a str, new_jti: &'a str, now_unix: i64 },
    Peek,
    Revoke { now_unix:      i64 },
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum FamilyReply {
    Ok,
    Rotated { new_current_jti: String },
    AlreadyRevoked,
    ReusedAndRevoked,
    NotInitialized,
    Conflict,
    State { state: FamilyState },
}

pub struct CloudflareRefreshTokenFamilyStore<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareRefreshTokenFamilyStore<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareRefreshTokenFamilyStore").finish_non_exhaustive()
    }
}

impl<'a> CloudflareRefreshTokenFamilyStore<'a> {
    pub fn new(env: &'a Env) -> Self {
        Self { env }
    }

    fn stub(&self, family_id: &str) -> PortResult<Stub> {
        self.env
            .durable_object("REFRESH_TOKEN_FAMILY")
            .map_err(|_| PortError::Unavailable)?
            .id_from_name(family_id)
            .map_err(|_| PortError::Unavailable)?
            .get_stub()
            .map_err(|_| PortError::Unavailable)
    }
}

impl RefreshTokenFamilyStore for CloudflareRefreshTokenFamilyStore<'_> {
    async fn init(&self, init: &FamilyInit) -> PortResult<()> {
        let stub  = self.stub(&init.family_id)?;
        let reply: FamilyReply = rpc_call(&stub, &FamilyCmd::Init { init }).await?;
        match reply {
            FamilyReply::Ok       => Ok(()),
            FamilyReply::Conflict => Err(PortError::Conflict),
            _                     => Err(PortError::Unavailable),
        }
    }

    async fn rotate(
        &self,
        family_id:     &str,
        presented_jti: &str,
        new_jti:       &str,
        now_unix:      i64,
    ) -> PortResult<RotateOutcome> {
        let stub  = self.stub(family_id)?;
        let reply: FamilyReply = rpc_call(
            &stub,
            &FamilyCmd::Rotate { presented_jti, new_jti, now_unix },
        ).await?;
        match reply {
            FamilyReply::Rotated { new_current_jti } =>
                Ok(RotateOutcome::Rotated { new_current_jti }),
            FamilyReply::AlreadyRevoked              => Ok(RotateOutcome::AlreadyRevoked),
            FamilyReply::ReusedAndRevoked            => Ok(RotateOutcome::ReusedAndRevoked),
            FamilyReply::NotInitialized              => Err(PortError::NotFound),
            _                                        => Err(PortError::Unavailable),
        }
    }

    async fn revoke(&self, family_id: &str, now_unix: i64) -> PortResult<()> {
        let stub  = self.stub(family_id)?;
        let reply: FamilyReply = rpc_call(&stub, &FamilyCmd::Revoke { now_unix }).await?;
        match reply {
            FamilyReply::AlreadyRevoked => Ok(()),
            FamilyReply::NotInitialized => Err(PortError::NotFound),
            _                           => Err(PortError::Unavailable),
        }
    }

    async fn peek(&self, family_id: &str) -> PortResult<Option<FamilyState>> {
        let stub  = self.stub(family_id)?;
        let reply: FamilyReply = rpc_call(&stub, &FamilyCmd::Peek).await?;
        match reply {
            FamilyReply::State { state } => Ok(Some(state)),
            FamilyReply::NotInitialized  => Ok(None),
            _                            => Err(PortError::Unavailable),
        }
    }
}

// -------------------------------------------------------------------------
// ActiveSessionStore
// -------------------------------------------------------------------------

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

// -------------------------------------------------------------------------
// RateLimitStore
// -------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum RateCmd {
    Hit {
        now_unix:       i64,
        window_secs:    i64,
        limit:          u32,
        escalate_after: u32,
    },
    Reset,
}

#[derive(Deserialize)]
struct RateReply {
    allowed:   bool,
    count:     u32,
    limit:     u32,
    resets_in: i64,
    escalate:  bool,
}

pub struct CloudflareRateLimitStore<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareRateLimitStore<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareRateLimitStore").finish_non_exhaustive()
    }
}

impl<'a> CloudflareRateLimitStore<'a> {
    pub fn new(env: &'a Env) -> Self {
        Self { env }
    }

    fn stub(&self, bucket: &str) -> PortResult<Stub> {
        self.env
            .durable_object("RATE_LIMIT")
            .map_err(|_| PortError::Unavailable)?
            .id_from_name(bucket)
            .map_err(|_| PortError::Unavailable)?
            .get_stub()
            .map_err(|_| PortError::Unavailable)
    }
}

impl RateLimitStore for CloudflareRateLimitStore<'_> {
    async fn hit(
        &self,
        bucket_key:     &str,
        now_unix:       i64,
        window_secs:    i64,
        limit:          u32,
        escalate_after: u32,
    ) -> PortResult<RateLimitDecision> {
        let stub  = self.stub(bucket_key)?;
        let reply: RateReply = rpc_call(
            &stub,
            &RateCmd::Hit { now_unix, window_secs, limit, escalate_after },
        ).await?;
        Ok(RateLimitDecision {
            allowed:   reply.allowed,
            count:     reply.count,
            limit:     reply.limit,
            resets_in: reply.resets_in,
            escalate:  reply.escalate,
        })
    }

    async fn reset(&self, bucket_key: &str) -> PortResult<()> {
        let stub = self.stub(bucket_key)?;
        let req  = rpc_request(&RateCmd::Reset)?;
        stub.fetch_with_request(req).await.map_err(|_| PortError::Unavailable)?;
        Ok(())
    }
}
