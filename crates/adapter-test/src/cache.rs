//! In-memory cache. TTL is advisory - the test-time "now" is whatever
//! the test wants it to be; there's no wall clock involved.
//!
//! We choose to *not* model expiry at all here: tests that care about
//! TTL should drive it through explicit clears. Modeling expiry would
//! force an artificial "now" parameter on `get`, which KV does not
//! have, and which would propagate up into test-only code paths in
//! the callers.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::cache::CacheStore;
use cesauth_core::ports::{PortError, PortResult};

#[derive(Debug, Default)]
pub struct InMemoryCache {
    map: Mutex<HashMap<String, Vec<u8>>>,
}

impl CacheStore for InMemoryCache {
    async fn get(&self, key: &str) -> PortResult<Option<Vec<u8>>> {
        let m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.get(key).cloned())
    }

    async fn put(&self, key: &str, value: &[u8], _ttl_secs: u32) -> PortResult<()> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        m.insert(key.to_owned(), value.to_owned());
        Ok(())
    }
}
