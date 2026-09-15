//! `RefreshTokenFamilyStore` DO adapter.

use cesauth_core::ports::store::{
    FamilyInit, FamilyState, LifetimeExpiry, RefreshLifetime, RefreshTokenFamilyStore, RotateOutcome,
};
use cesauth_core::ports::{PortError, PortResult};
use serde::{Deserialize, Serialize};
use worker::{Env, Stub};

use super::rpc_call;


#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum FamilyCmd<'a> {
    Init   { init:          &'a FamilyInit },
    // RFC 139: must match `Command::Rotate` in `refresh_token_family.rs` (the DO).
    Rotate { presented_jti: &'a cesauth_core::types::Jti, new_jti: &'a cesauth_core::types::Jti, now_unix: i64, absolute_secs: i64, idle_secs: i64 },
    Peek,
    Revoke { now_unix:      i64 },
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum FamilyReply {
    Ok,
    Rotated { new_current_jti: cesauth_core::types::Jti },
    AlreadyRevoked,
    /// **v0.34.0**: carries forensic data so the worker can emit a
    /// distinct audit event (`refresh_token_reuse_detected`) and so
    /// `peek` results post-revocation surface the cause.
    ReusedAndRevoked { reused_jti: cesauth_core::types::Jti, was_retired: bool },
    /// RFC 139: past the absolute cap or idle window; the DO revoked it.
    Expired { kind: LifetimeExpiry },
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
        let stub  = self.stub(init.family_id.as_str())?;
        let reply: FamilyReply = rpc_call(&stub, &FamilyCmd::Init { init }).await?;
        match reply {
            FamilyReply::Ok       => Ok(()),
            FamilyReply::Conflict => Err(PortError::Conflict),
            _                     => Err(PortError::Unavailable),
        }
    }

    async fn rotate(
        &self,
        family_id:     &cesauth_core::types::FamilyId,
        presented_jti: &cesauth_core::types::Jti,
        new_jti:       &cesauth_core::types::Jti,
        now_unix:      i64,
        lifetime:      &RefreshLifetime,
    ) -> PortResult<RotateOutcome> {
        let stub  = self.stub(family_id.as_str())?;
        let reply: FamilyReply = rpc_call(
            &stub,
            &FamilyCmd::Rotate {
                presented_jti,
                new_jti,
                now_unix,
                absolute_secs: lifetime.absolute_secs(),
                idle_secs:     lifetime.idle_secs(),
            },
        ).await?;
        match reply {
            FamilyReply::Rotated { new_current_jti } =>
                Ok(RotateOutcome::Rotated { new_current_jti }),
            FamilyReply::AlreadyRevoked              => Ok(RotateOutcome::AlreadyRevoked),
            FamilyReply::ReusedAndRevoked { reused_jti, was_retired } =>
                Ok(RotateOutcome::ReusedAndRevoked { reused_jti, was_retired }),
            FamilyReply::Expired { kind }            => Ok(RotateOutcome::Expired(kind)),
            FamilyReply::NotInitialized              => Err(PortError::NotFound),
            _                                        => Err(PortError::Unavailable),
        }
    }

    async fn revoke(&self, family_id: &cesauth_core::types::FamilyId, now_unix: i64) -> PortResult<()> {
        let stub  = self.stub(family_id.as_str())?;
        let reply: FamilyReply = rpc_call(&stub, &FamilyCmd::Revoke { now_unix }).await?;
        match reply {
            FamilyReply::AlreadyRevoked => Ok(()),
            FamilyReply::NotInitialized => Err(PortError::NotFound),
            _                           => Err(PortError::Unavailable),
        }
    }

    async fn peek(&self, family_id: &cesauth_core::types::FamilyId) -> PortResult<Option<FamilyState>> {
        let stub  = self.stub(family_id.as_str())?;
        let reply: FamilyReply = rpc_call(&stub, &FamilyCmd::Peek).await?;
        match reply {
            FamilyReply::State { state } => Ok(Some(state)),
            FamilyReply::NotInitialized  => Ok(None),
            _                            => Err(PortError::Unavailable),
        }
    }
}
