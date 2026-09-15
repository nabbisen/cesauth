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
//! * **Expiry is enforced at read (RFC 140).** `Peek`, `Take` and `Bump`
//!   carry the caller's `now_unix`; an entry is expired iff
//!   `now_unix >= expires_at`. An expired `Peek` returns `None` without
//!   deleting, an expired `Take` deletes and returns `None`, and an
//!   expired `Bump` is `NotFound`. The DO reads no clock.
//! * The alarm set at `Put` is **cleanup only**. It propagates a failed
//!   delete, so the runtime sees the failure; correctness never depends
//!   on it having run.

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
    // RFC 140: must match `ChallengeCmd` in `ports/store/auth_challenge.rs`.
    // A field on one side only compiles and fails at runtime ("bad command").
    Peek { now_unix: i64 },
    Take { now_unix: i64 },
    Bump { now_unix: i64 },
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

            Command::Peek { now_unix } => {
                let v = storage.get::<Challenge>(KEY).await.ok().flatten()
                    .filter(|c| now_unix < c.expires_at());
                Response::from_json(&Outcome::Value { challenge: v })
            }

            Command::Take { now_unix } => {
                let v = storage.get::<Challenge>(KEY).await.ok().flatten();
                if v.is_some() {
                    // Delete first so a late concurrent `Take` cannot
                    // see a value we already returned. An expired entry
                    // is deleted too, and never returned (RFC 140).
                    storage.delete(KEY).await?;
                }
                let v = v.filter(|c| now_unix < c.expires_at());
                Response::from_json(&Outcome::Value { challenge: v })
            }

            Command::Bump { now_unix } => {
                let Some(mut c) = storage.get::<Challenge>(KEY).await?
                    .filter(|c| now_unix < c.expires_at())
                else {
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
        // RFC 140: propagate a failed delete so the runtime sees it.
        // Discarding it reported success and left the entry forever.
        self.state.storage().delete(KEY).await?;
        Response::ok("expired")
    }
}
