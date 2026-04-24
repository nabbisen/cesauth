//! `AuthChallengeStore` DO adapter.

use cesauth_core::ports::store::{AuthChallengeStore, Challenge};
use cesauth_core::ports::{PortError, PortResult};
use serde::{Deserialize, Serialize};
use worker::{Env, Stub};

use super::rpc_call;


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
