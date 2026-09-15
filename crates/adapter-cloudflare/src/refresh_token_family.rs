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
//!
//! **RFC 139:** `Rotate` also enforces the lifetime policy it is sent —
//! revoked, then absolute cap, then idle window, then the jti — using
//! core's `FamilyState::lifetime`, and an expiry revokes and records
//! `expired` in the same `put`.

use cesauth_core::ports::store::{FamilyInit, FamilyState, Lifetime, LifetimeExpiry, RefreshLifetime};
use serde::{Deserialize, Serialize};
#[allow(clippy::wildcard_imports)]
use worker::*;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Command {
    Init   { init:           FamilyInit },
    // RFC 139: the policy travels with the command. Must match
    // `FamilyCmd::Rotate` in `ports/store/refresh_token_family.rs`; a field on
    // one side only compiles and fails at runtime ("bad command").
    Rotate { presented_jti:  String, new_jti: String, now_unix: i64, absolute_secs: i64, idle_secs: i64 },
    Peek,
    Revoke { now_unix:       i64 },
}

/// Serializable mirror of `cesauth_core::ports::store::RotateOutcome`.
/// We keep it local so the DO's wire format is not structurally tied
/// to the core enum's `serde` layout - if core ever adds a variant
/// for a new rotation outcome, we can update this mapping explicitly.
///
/// **v0.34.0**: `ReusedAndRevoked` now carries `reused_jti` and
/// `was_retired` for forensic audit. The wire format is forward-
/// compatible with v0.33.0 readers — they'd see the new fields and
/// (depending on the deserializer) ignore them; in practice all
/// readers in this repo bump together.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Outcome {
    Ok,
    Rotated { new_current_jti: String },
    AlreadyRevoked,
    ReusedAndRevoked { reused_jti: String, was_retired: bool },
    /// RFC 139: past the absolute cap or idle window; revoked in this write.
    Expired { kind: LifetimeExpiry },
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
                    reused_jti:        None,
                    reused_at:         None,
                    reuse_was_retired: None,
                    expired:           None,
                    auth_time:         init.auth_time,
                };
                storage.put(KEY, &fam).await?;
                Response::from_json(&Outcome::Ok)
            }

            Command::Rotate { presented_jti, new_jti, now_unix, absolute_secs, idle_secs } => {
                // Rebuilt through the validator: a policy that would disable
                // the absolute cap is refused, never applied (RFC 139 §7.2).
                let Ok(lifetime) = RefreshLifetime::new(absolute_secs, idle_secs) else {
                    return Response::error("invalid refresh lifetime policy", 400);
                };
                let Some(mut fam) = storage.get::<FamilyState>(KEY).await? else {
                    return Response::from_json(&Outcome::NotInitialized);
                };

                if fam.revoked_at.is_some() {
                    return Response::from_json(&Outcome::AlreadyRevoked);
                }

                // RFC 139 §10.2: lifetime before the jti. An expired family
                // presented with a retired jti is expired, not reuse-detected.
                if let Lifetime::Expired(kind) = fam.lifetime(now_unix, &lifetime) {
                    fam.revoked_at = Some(now_unix);
                    fam.expired    = Some(kind);
                    storage.put(KEY, &fam).await?;
                    return Response::from_json(&Outcome::Expired { kind });
                }

                if presented_jti.as_str() == fam.current_jti.as_str() {
                    let old = std::mem::replace(&mut fam.current_jti, cesauth_core::types::Jti::from_storage(new_jti.clone()));
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
                    //
                    // v0.34.0: capture forensic fields so audit
                    // surfaces the cause. `was_retired` distinguishes
                    // the recognized-retired-jti case from the
                    // unknown-jti case (= forged or shotgun attack).
                    let was_retired = fam.retired_jtis.iter().any(|j| j.as_str() == presented_jti.as_str());

                    fam.revoked_at        = Some(now_unix);
                    fam.reused_jti        = Some(cesauth_core::types::Jti::from_storage(presented_jti.clone()));
                    fam.reused_at         = Some(now_unix);
                    fam.reuse_was_retired = Some(was_retired);
                    storage.put(KEY, &fam).await?;

                    Response::from_json(&Outcome::ReusedAndRevoked {
                        reused_jti: presented_jti,
                        was_retired,
                    })
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
