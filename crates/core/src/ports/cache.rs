//! Best-effort cache.
//!
//! Maps to Cloudflare KV in the production adapter. Because KV is
//! eventually consistent and replicated, **no caller may use this
//! trait as a source of authentication truth**. The only permitted
//! uses are:
//!
//! * Discovery document (`/.well-known/openid-configuration`)
//! * JWKS (`/jwks.json`)
//! * Public metadata that's safe to serve slightly stale
//!
//! Spec §3.3 is explicit about this. The trait does not carry any
//! "freshness" guarantees; callers must be okay with stale reads.

use super::PortResult;

pub trait CacheStore {
    /// Return the cached value or `None` if missing / expired.
    async fn get(&self, key: &str) -> PortResult<Option<Vec<u8>>>;

    /// Store with an expiry. `ttl_secs` is advisory: backends may round
    /// up to whatever the minimum resolution is.
    async fn put(&self, key: &str, value: &[u8], ttl_secs: u32) -> PortResult<()>;
}
