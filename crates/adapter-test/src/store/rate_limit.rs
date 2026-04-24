//! In-memory `RateLimitStore`.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::store::{RateLimitDecision, RateLimitStore};
use cesauth_core::ports::{PortError, PortResult};


#[derive(Debug, Clone)]
struct Window {
    start: i64,
    count: u32,
}

#[derive(Debug, Default)]
pub struct InMemoryRateLimitStore {
    map: Mutex<HashMap<String, Window>>,
}

impl RateLimitStore for InMemoryRateLimitStore {
    async fn hit(
        &self,
        bucket_key:     &str,
        now_unix:       i64,
        window_secs:    i64,
        limit:          u32,
        escalate_after: u32,
    ) -> PortResult<RateLimitDecision> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        let w = m
            .entry(bucket_key.to_owned())
            .or_insert(Window { start: now_unix, count: 0 });
        if now_unix.saturating_sub(w.start) >= window_secs {
            *w = Window { start: now_unix, count: 0 };
        }
        w.count = w.count.saturating_add(1);
        Ok(RateLimitDecision {
            allowed:   w.count <= limit,
            count:     w.count,
            limit,
            resets_in: window_secs.saturating_sub(now_unix.saturating_sub(w.start)),
            escalate:  w.count > escalate_after,
        })
    }

    async fn reset(&self, bucket_key: &str) -> PortResult<()> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        m.remove(bucket_key);
        Ok(())
    }
}
