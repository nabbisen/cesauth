//! `GET /jwks.json`.

use cesauth_cf::ports::repo::CloudflareSigningKeyRepository;
use cesauth_core::jwt::{Jwk, JwksDocument};
use cesauth_core::ports::repo::SigningKeyRepository;
use worker::{Request, Response, Result, RouteContext};


pub async fn jwks<D>(_req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let repo   = CloudflareSigningKeyRepository::new(&ctx.env);
    let active = repo.list_active().await
        .map_err(|_| worker::Error::RustError("signing key lookup failed".into()))?;

    let keys: Vec<Jwk> = active
        .into_iter()
        .map(|k| Jwk::ed25519(k.kid, k.public_key_b64))
        .collect();

    let mut resp = Response::from_json(&JwksDocument { keys })?;
    let _ = resp.headers_mut().set("cache-control", "public, max-age=300");
    Ok(resp)
}
