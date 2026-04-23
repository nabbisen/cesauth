//! KV-backed cache.
//!
//! Strict rule (per spec §3.3, repeated here because the temptation
//! is real): callers MUST NOT use this for auth truth. Discovery doc
//! and JWKS are the only intended consumers, and both tolerate stale
//! reads up to the configured TTL.

use cesauth_core::ports::cache::CacheStore;
use cesauth_core::ports::{PortError, PortResult};
use worker::Env;

pub struct CloudflareCache<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareCache<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareCache").finish_non_exhaustive()
    }
}

impl<'a> CloudflareCache<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

impl CacheStore for CloudflareCache<'_> {
    async fn get(&self, key: &str) -> PortResult<Option<Vec<u8>>> {
        let ns = self.env.kv("CACHE").map_err(|_| PortError::Unavailable)?;
        match ns.get(key).bytes().await {
            Ok(v) => Ok(v),
            Err(_) => Err(PortError::Unavailable),
        }
    }

    async fn put(&self, key: &str, value: &[u8], ttl_secs: u32) -> PortResult<()> {
        let ns = self.env.kv("CACHE").map_err(|_| PortError::Unavailable)?;
        ns.put_bytes(key, value)
            .map_err(|_| PortError::Unavailable)?
            .expiration_ttl(ttl_secs.into())
            .execute()
            .await
            .map_err(|_| PortError::Unavailable)?;
        Ok(())
    }
}
