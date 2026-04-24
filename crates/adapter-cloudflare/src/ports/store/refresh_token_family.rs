//! `RefreshTokenFamilyStore` DO adapter.

use cesauth_core::ports::store::{
    FamilyInit, FamilyState, RefreshTokenFamilyStore, RotateOutcome,
};
use cesauth_core::ports::{PortError, PortResult};
use serde::{Deserialize, Serialize};
use worker::{Env, Stub};

use super::rpc_call;


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
