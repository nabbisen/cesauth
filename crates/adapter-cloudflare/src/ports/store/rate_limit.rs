//! `RateLimitStore` DO adapter.

use cesauth_core::ports::store::{RateLimitDecision, RateLimitStore};
use cesauth_core::ports::{PortError, PortResult};
use serde::{Deserialize, Serialize};
use worker::{Env, Stub};

use super::{rpc_call, rpc_request};


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
