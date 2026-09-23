//! **RFC 118** — the refresh-token family lifecycle, as an executable
//! reference model. **This module is the normative description** of what a
//! [`RefreshTokenFamilyStore`](super::RefreshTokenFamilyStore) must do; the
//! stores are held to it by generated sequences (`cesauth-adapter-test`,
//! `store/refresh_family_proptests.rs`) and it is small enough to review line by
//! line.
//!
//! Written from RFC 9700 §4.14.2, the port's documented contract
//! (`RotateOutcome`, `FamilyState`, `rotate`), RFC 139 §10.2's check order and
//! RFC 118 §5 as corrected by §16 — not from a store's source. std-only: no
//! async, no ports, no clock (each operation is handed its `now`).
//!
//! # The invariants
//!
//! 1. **Single live jti.** `rotate` accepts exactly one jti: the one most
//!    recently issued (`current_jti`). Nothing else is ever accepted.
//! 2. **Rotation kills the predecessor.** After a successful rotation, presenting
//!    the jti it replaced yields `ReusedAndRevoked` and the family is revoked.
//! 3. **Revocation is absorbing.** After any revocation (explicit, reuse or
//!    expiry) every later `rotate` is `AlreadyRevoked`, and nothing about the
//!    family changes again — in particular the reuse forensics are never
//!    overwritten (the first reuse is the interesting one).
//! 4. **Rotation bookkeeping** (RFC 118 §16.1: there is no version counter).
//!    `last_rotated_at` is the `now` of the most recent successful rotation, and
//!    each successful rotation appends exactly one jti to the retired ring.
//! 5. **Forensic fidelity** (§16.2). The ring holds the last
//!    [`RETIRED_RING_CAP`] rotated-out jtis. `was_retired` is `true` iff the
//!    presented jti is in it; an older jti, or one never issued, is `false`.
//!    **Both revoke the family**, so this labels the event and does not weaken
//!    the response.
//! 6. **Expiry** (§16.3, RFC 139). Checked in this order: revoked → absolute →
//!    idle → jti. An expired family presented with a retired jti is `Expired`,
//!    not reuse, and its reuse forensics stay `None`. The policy is an input to
//!    each rotation, never model state, so lowering it shortens a live family.
//! 7. **Init uniqueness.** `init` on an existing id is `Conflict` and never
//!    resets anything.
//!
//! **A family that does not exist** is not a [`FamilyModel`] (the model
//! represents one that does, and the generated sequences always initialise
//! first). The rule for it is [`apply_to_absent`]: `rotate` and `revoke` are
//! `NotFound` (the port states this, RFC 118 C1). It is pinned by an example
//! test and a store contract test, not by the generator.
//!
//! **Out of scope, deliberately.** Concurrent interleaving: the model is a
//! sequence, which is all a single-threaded Durable Object exposes.
//!
//! The deadline arithmetic is **not** here. The model calls
//! [`FamilyState::lifetime`], the one function the store, the oracle and
//! introspection all call (RFC 139 §9.2); a second copy would be a place they
//! could disagree.

use crate::ports::store::{FamilyInit, FamilyState, Lifetime, RefreshLifetime};
use crate::types::Jti;

/// How many rotated-out jtis a family remembers (RFC 118 §16.2). The model owns
/// this figure so a change to a store's constant is caught, not agreed with.
pub const RETIRED_RING_CAP: usize = 16;

/// One operation on a family that exists.
#[derive(Debug, Clone)]
pub enum Op {
    /// `init` on the id this model already represents.
    Init(FamilyInit),
    /// `lifetime` is the policy **at this call**, not model state (§16.3).
    Rotate { presented: Jti, new: Jti, lifetime: RefreshLifetime },
    /// An explicit revocation.
    Revoke,
}

/// What an operation returned, mirroring `RotateOutcome` plus `init`/`revoke`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelOutcome {
    Conflict,
    Revoked,
    Rotated { new_current_jti: Jti },
    AlreadyRevoked,
    ReusedAndRevoked { reused_jti: Jti, was_retired: bool },
    Expired(crate::ports::store::LifetimeExpiry),
    /// The family does not exist. Only [`apply_to_absent`] returns it.
    NotFound,
}

/// What `op` returns on an id that was never initialised: `NotFound` for
/// `rotate` and `revoke`. `Init` is not an outcome here: it creates the family
/// (`FamilyModel::new`), so it returns `None`.
pub fn apply_to_absent(op: &Op) -> Option<ModelOutcome> {
    match op {
        Op::Init(_)                        => None,
        Op::Rotate { .. } | Op::Revoke     => Some(ModelOutcome::NotFound),
    }
}

/// The lifecycle of one family. Its state is a [`FamilyState`], so it can be
/// compared field for field with what a store's `peek` returns.
#[derive(Debug, Clone)]
pub struct FamilyModel {
    state: FamilyState,
}

impl FamilyModel {
    /// The family as `init` creates it: current jti is the first, the ring is
    /// empty, nothing is revoked, and no forensics or expiry are recorded.
    pub fn new(init: &FamilyInit) -> Self {
        Self { state: fresh(init) }
    }

    /// What `peek` must show.
    pub fn state(&self) -> &FamilyState { &self.state }

    pub fn apply(&mut self, op: &Op, now: i64) -> ModelOutcome {
        match op {
            // Invariant 7: refused, and nothing is reset.
            Op::Init(_) => ModelOutcome::Conflict,

            // Absorbing (invariant 3): a second revocation changes nothing, so
            // the first `revoked_at` stands. Explicit revocation records neither
            // reuse forensics nor an expiry.
            Op::Revoke => {
                if self.state.revoked_at.is_none() {
                    self.state.revoked_at = Some(now);
                }
                ModelOutcome::Revoked
            }

            Op::Rotate { presented, new, lifetime } => self.rotate(presented, new, now, lifetime),
        }
    }

    fn rotate(&mut self, presented: &Jti, new: &Jti, now: i64, lifetime: &RefreshLifetime) -> ModelOutcome {
        let s = &mut self.state;

        // 1. Already revoked: absorbing, and nothing changes.
        if s.revoked_at.is_some() {
            return ModelOutcome::AlreadyRevoked;
        }

        // 2-3. Past the absolute cap, then the idle window (RFC 139 §10.2). The
        // family is revoked and the deadline recorded, and it is not rotated.
        if let Lifetime::Expired(kind) = s.lifetime(now, lifetime) {
            s.revoked_at = Some(now);
            s.expired    = Some(kind);
            return ModelOutcome::Expired(kind);
        }

        // 4. The presented jti is the current one: rotate (invariants 1, 2, 4).
        if *presented == s.current_jti {
            let old = std::mem::replace(&mut s.current_jti, new.clone());
            s.retired_jtis.push(old);
            if s.retired_jtis.len() > RETIRED_RING_CAP {
                s.retired_jtis.remove(0);
            }
            s.last_rotated_at = now;
            return ModelOutcome::Rotated { new_current_jti: new.clone() };
        }

        // Anything else is reuse (RFC 9700 §4.14.2): revoke, and record whether
        // the jti was one this family remembers (invariant 5).
        let was_retired = s.retired_jtis.contains(presented);
        s.revoked_at        = Some(now);
        s.reused_jti        = Some(presented.clone());
        s.reused_at         = Some(now);
        s.reuse_was_retired = Some(was_retired);
        ModelOutcome::ReusedAndRevoked { reused_jti: presented.clone(), was_retired }
    }
}

fn fresh(init: &FamilyInit) -> FamilyState {
    FamilyState {
        family_id:         init.family_id.clone(),
        user_id:           init.user_id.clone(),
        client_id:         init.client_id.clone(),
        scopes:            init.scopes.clone(),
        current_jti:       init.first_jti.clone(),
        retired_jtis:      Vec::new(),
        created_at:        init.now_unix,
        last_rotated_at:   init.now_unix,
        revoked_at:        None,
        reused_jti:        None,
        reused_at:         None,
        reuse_was_retired: None,
        expired:           None,
        auth_time:         init.auth_time,
    }
}

#[cfg(test)]
mod tests;
