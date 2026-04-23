//! `RefreshTokenFamily` DO.
//!
//! Serialized state machine for family-based refresh token rotation.
//! The domain types (`FamilyState`, `FamilyInit`, `RotateOutcome`)
//! live in `cesauth_core::ports::store`; this file is the RPC shell.
//!
//! Key invariant: reuse of a rotated-out refresh token atomically
//! revokes the whole family. This is enforced below and also covered
//! by the in-memory adapter's tests - whichever you break first, CI
//! fails.

use cesauth_core::ports::store::{FamilyInit, FamilyState};
use serde::{Deserialize, Serialize};
#[allow(clippy::wildcard_imports)]
use worker::*;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Command {
    Init   { init:           FamilyInit },
    Rotate { presented_jti:  String, new_jti: String, now_unix: i64 },
    Peek,
    Revoke { now_unix:       i64 },
}

/// Serializable mirror of `cesauth_core::ports::store::RotateOutcome`.
/// We keep it local so the DO's wire format is not structurally tied
/// to the core enum's `serde` layout - if core ever adds a variant
/// for a new rotation outcome, we can update this mapping explicitly.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Outcome {
    Ok,
    Rotated { new_current_jti: String },
    AlreadyRevoked,
    ReusedAndRevoked,
    NotInitialized,
    Conflict,
    State { state: FamilyState },
}

const KEY: &str = "family";
const RETIRED_RING_SIZE: usize = 16;

#[durable_object]
pub struct RefreshTokenFamily {
    state: State,
    _env:  Env,
}

impl DurableObject for RefreshTokenFamily {
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
            Command::Init { init } => {
                // worker 0.8: `storage.get` returns `Result<Option<T>>`.
                // A present key means the family was already initialised;
                // reusing a family id would let the caller hijack an
                // existing grant, so refuse.
                if storage.get::<FamilyState>(KEY).await?.is_some() {
                    return Response::from_json(&Outcome::Conflict);
                }
                let fam = FamilyState {
                    family_id:       init.family_id,
                    user_id:         init.user_id,
                    client_id:       init.client_id,
                    scopes:          init.scopes,
                    current_jti:     init.first_jti,
                    retired_jtis:    Vec::new(),
                    created_at:      init.now_unix,
                    last_rotated_at: init.now_unix,
                    revoked_at:      None,
                };
                storage.put(KEY, &fam).await?;
                Response::from_json(&Outcome::Ok)
            }

            Command::Rotate { presented_jti, new_jti, now_unix } => {
                let Some(mut fam) = storage.get::<FamilyState>(KEY).await? else {
                    return Response::from_json(&Outcome::NotInitialized);
                };

                if fam.revoked_at.is_some() {
                    return Response::from_json(&Outcome::AlreadyRevoked);
                }

                if presented_jti == fam.current_jti {
                    let old = std::mem::replace(&mut fam.current_jti, new_jti.clone());
                    fam.retired_jtis.push(old);
                    if fam.retired_jtis.len() > RETIRED_RING_SIZE {
                        fam.retired_jtis.remove(0);
                    }
                    fam.last_rotated_at = now_unix;
                    storage.put(KEY, &fam).await?;
                    Response::from_json(&Outcome::Rotated { new_current_jti: new_jti })
                } else {
                    // Either a retired jti or something wholly unknown.
                    // In both cases, revoke the family immediately
                    // (RFC 9700 §4.14.2 reuse detection).
                    fam.revoked_at = Some(now_unix);
                    storage.put(KEY, &fam).await?;
                    Response::from_json(&Outcome::ReusedAndRevoked)
                }
            }

            Command::Peek => match storage.get::<FamilyState>(KEY).await? {
                Some(fam) => Response::from_json(&Outcome::State { state: fam }),
                None      => Response::from_json(&Outcome::NotInitialized),
            },

            Command::Revoke { now_unix } => {
                let Some(mut fam) = storage.get::<FamilyState>(KEY).await? else {
                    return Response::from_json(&Outcome::NotInitialized);
                };
                if fam.revoked_at.is_none() {
                    fam.revoked_at = Some(now_unix);
                    storage.put(KEY, &fam).await?;
                }
                Response::from_json(&Outcome::AlreadyRevoked)
            }
        }
    }
}
