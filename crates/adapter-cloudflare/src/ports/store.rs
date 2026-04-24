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
//!
//! One submodule per store trait. The parent file keeps only the RPC
//! helpers that every adapter uses, plus the module declarations and
//! re-exports.

use cesauth_core::ports::{PortError, PortResult};
use serde::{Deserialize, Serialize};
use worker::{Method, Request, RequestInit, Stub};

mod active_session;
mod auth_challenge;
mod rate_limit;
mod refresh_token_family;

pub use active_session::CloudflareActiveSessionStore;
pub use auth_challenge::CloudflareAuthChallengeStore;
pub use rate_limit::CloudflareRateLimitStore;
pub use refresh_token_family::CloudflareRefreshTokenFamilyStore;

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
