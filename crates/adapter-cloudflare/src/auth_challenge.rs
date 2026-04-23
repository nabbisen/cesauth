//! `AuthChallenge` DO.
//!
//! Owns short-lived, single-consumption data:
//!
//! * Authorization codes (redeemable at /token)
//! * WebAuthn ceremony nonces
//! * Magic Link OTP hashes
//!
//! The domain type (`Challenge`) is defined in `cesauth_core::ports::store`
//! so that the in-memory adapter, the Cloudflare adapter, and the
//! service layer all agree on the shape. This file is just the RPC
//! shell + storage plumbing.
//!
//! ## Contract
//!
//! * `Put` refuses to overwrite. A second put on the same handle
//!   returns conflict. This preserves the invariant that each handle
//!   maps to at most one challenge for its lifetime.
//! * `Take` is atomic: delete happens before the value is returned.
//! * Expiry is handled via DO alarms: a challenge schedules self-GC
//!   at its `expires_at` time.

use cesauth_core::ports::store::Challenge;
use serde::{Deserialize, Serialize};
#[allow(clippy::wildcard_imports)]
use worker::*;

/// Wire protocol for this DO, consumed by `CloudflareAuthChallengeStore`
/// in `ports::store`. Tagged enum keeps the RPC surface compile-checked
/// at both ends.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Command {
    Put  { challenge: Challenge },
    Peek,
    Take,
    Bump,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Outcome {
    Ok,
    Conflict,
    Value    { challenge: Option<Challenge> },
    Attempts { count: u32 },
    NotFound,
    PreconditionFailed,
}

const KEY: &str = "challenge";

#[durable_object]
pub struct AuthChallenge {
    state: State,
    _env:  Env,
}

impl DurableObject for AuthChallenge {
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
            Command::Put { challenge } => {
                // worker 0.8: `storage.get` returns `Result<Option<T>>`.
                // Missing key is `Ok(None)`, not an `Err`.
                if storage.get::<Challenge>(KEY).await?.is_some() {
                    return Response::from_json(&Outcome::Conflict);
                }

                let expires_at = challenge.expires_at();
                storage.put(KEY, &challenge).await?;

                // Self-GC. Alarm fires once at stored time; if `Take`
                // happens first, the alarm is a no-op (delete on a
                // missing key is safe).
                let alarm_ms = expires_at.saturating_mul(1000);
                storage.set_alarm(alarm_ms).await?;

                Response::from_json(&Outcome::Ok)
            }

            Command::Peek => {
                let v = storage.get::<Challenge>(KEY).await.ok().flatten();
                Response::from_json(&Outcome::Value { challenge: v })
            }

            Command::Take => {
                let v = storage.get::<Challenge>(KEY).await.ok().flatten();
                if v.is_some() {
                    // Delete first so a late concurrent `Take` cannot
                    // see a value we already returned.
                    storage.delete(KEY).await?;
                }
                Response::from_json(&Outcome::Value { challenge: v })
            }

            Command::Bump => {
                let Some(mut c) = storage.get::<Challenge>(KEY).await? else {
                    return Response::from_json(&Outcome::NotFound);
                };
                if let Challenge::MagicLink { ref mut attempts, .. } = c {
                    *attempts = attempts.saturating_add(1);
                    let n = *attempts;
                    storage.put(KEY, &c).await?;
                    Response::from_json(&Outcome::Attempts { count: n })
                } else {
                    Response::from_json(&Outcome::PreconditionFailed)
                }
            }
        }
    }

    async fn alarm(&self) -> Result<Response> {
        let _ = self.state.storage().delete(KEY).await;
        Response::ok("expired")
    }
}
