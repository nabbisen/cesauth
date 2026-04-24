//! `GET /.well-known/openid-configuration`.

use cesauth_core::oidc::discovery::DiscoveryDocument;
use worker::{Request, Response, Result, RouteContext};

use crate::config::Config;


pub async fn discovery<D>(_req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let cfg = Config::from_env(&ctx.env)?;
    let doc = DiscoveryDocument::new(&cfg.issuer);
    let mut resp = Response::from_json(&doc)?;
    // Discovery is safe to cache at the edge; match KV's default TTL.
    let _ = resp.headers_mut().set("cache-control", "public, max-age=300");
    Ok(resp)
}
