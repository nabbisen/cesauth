//! `RateLimit` DO.
//!
//! Fixed-window counter. Unlike the other DOs in this crate, the
//! state (`WindowState`) is purely internal to the DO - it's never
//! surfaced across the port boundary. The port only sees a
//! `RateLimitDecision` (from `cesauth_core::ports::store`), so the
//! domain crate doesn't need to know what the window shape is.
//!
//! See `ports::store::CloudflareRateLimitStore` for the adapter side.

use serde::{Deserialize, Serialize};
#[allow(clippy::wildcard_imports)]
use worker::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WindowState {
    window_start: i64,
    count:        u32,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Command {
    Hit {
        now_unix:       i64,
        window_secs:    i64,
        limit:          u32,
        escalate_after: u32,
    },
    Reset,
}

#[derive(Debug, Serialize)]
struct HitReply {
    allowed:   bool,
    count:     u32,
    limit:     u32,
    resets_in: i64,
    escalate:  bool,
}

const KEY: &str = "window";

#[durable_object]
pub struct RateLimit {
    state: State,
    _env:  Env,
}

impl DurableObject for RateLimit {
    fn new(state: State, env: Env) -> Self {
        Self { state, _env: env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let cmd: Command = match req.json().await {
            Ok(v)  => v,
            Err(_) => return Response::error("bad command", 400),
        };

        let storage = self.state.storage();

        match cmd {
            Command::Hit { now_unix, window_secs, limit, escalate_after } => {
                // worker 0.8: `storage.get` returns `Result<Option<T>>`.
                // Treat missing key and I/O error the same way here -
                // start a fresh window.
                let mut w = storage
                    .get::<WindowState>(KEY)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or(WindowState { window_start: now_unix, count: 0 });

                if now_unix.saturating_sub(w.window_start) >= window_secs {
                    w = WindowState { window_start: now_unix, count: 0 };
                }
                w.count = w.count.saturating_add(1);
                storage.put(KEY, &w).await?;

                Response::from_json(&HitReply {
                    allowed:   w.count <= limit,
                    count:     w.count,
                    limit,
                    resets_in: window_secs.saturating_sub(now_unix.saturating_sub(w.window_start)),
                    escalate:  w.count > escalate_after,
                })
            }

            Command::Reset => {
                let _ = storage.delete(KEY).await;
                Response::ok("reset")
            }
        }
    }
}
