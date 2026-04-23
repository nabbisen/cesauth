//! `ActiveSession` DO.
//!
//! Authoritative view of a live session so revocation is immediate.
//! `SessionState` and `AuthMethod` live in `cesauth_core::ports::store`.

use cesauth_core::ports::store::SessionState;
use serde::{Deserialize, Serialize};
#[allow(clippy::wildcard_imports)]
use worker::*;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Command {
    Start  { state: SessionState },
    Touch  { now_unix: i64 },
    Status,
    Revoke { now_unix: i64 },
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Outcome {
    Ok,
    Conflict,
    NotStarted,
    Active  { state: SessionState },
    Revoked { state: SessionState },
}

const KEY: &str = "session";

#[durable_object]
pub struct ActiveSession {
    state: State,
    _env:  Env,
}

impl DurableObject for ActiveSession {
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
            Command::Start { state: s } => {
                // Note: in worker 0.8 `storage.get::<T>` returns
                // `Result<Option<T>>`. Missing key is `Ok(None)`, not
                // an `Err`. Any `Err` is an actual I/O failure.
                match storage.get::<SessionState>(KEY).await? {
                    Some(_) => return Response::from_json(&Outcome::Conflict),
                    None    => {
                        storage.put(KEY, &s).await?;
                        Response::from_json(&Outcome::Ok)
                    }
                }
            }

            Command::Touch { now_unix } => {
                let Some(mut s) = storage.get::<SessionState>(KEY).await? else {
                    return Response::from_json(&Outcome::NotStarted);
                };
                if s.revoked_at.is_some() {
                    return Response::from_json(&Outcome::Revoked { state: s });
                }
                s.last_seen_at = now_unix;
                storage.put(KEY, &s).await?;
                Response::from_json(&Outcome::Active { state: s })
            }

            Command::Status => {
                let Some(s) = storage.get::<SessionState>(KEY).await? else {
                    return Response::from_json(&Outcome::NotStarted);
                };
                if s.revoked_at.is_some() {
                    Response::from_json(&Outcome::Revoked { state: s })
                } else {
                    Response::from_json(&Outcome::Active { state: s })
                }
            }

            Command::Revoke { now_unix } => {
                let Some(mut s) = storage.get::<SessionState>(KEY).await? else {
                    return Response::from_json(&Outcome::NotStarted);
                };
                if s.revoked_at.is_none() {
                    s.revoked_at = Some(now_unix);
                    storage.put(KEY, &s).await?;
                }
                Response::from_json(&Outcome::Revoked { state: s })
            }
        }
    }
}
