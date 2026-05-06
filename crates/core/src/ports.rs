//! Persistence ports.
//!
//! The narrow set of traits adapters must implement. Per the project
//! architecture addendum:
//!
//! * No generic storage framework. Each trait encodes a *specific*
//!   operation shape, not a "thing that stores things".
//! * The operations we bless are: **read**, **write**, and the
//!   domain-meaningful state transitions **transact / lock / serialize /
//!   revoke / consume / rotate**. Anything beyond that is out of scope.
//! * The trait boundary between D1-shape (CRUD) and DO-shape
//!   (serialized state machine) is kept visible in the module split -
//!   we deliberately do *not* paper over it, because the consistency
//!   guarantees differ and forcing one abstraction would leak the
//!   weaker guarantee to callers that want the stronger one.
//!
//! Submodules:
//!
//! * [`repo`]  - D1-shaped CRUD for long-lived relational data.
//! * [`store`] - DO-shaped, per-key serialized state machines.
//! * [`audit`] - R2-shaped append-only sink.
//! * [`cache`] - KV-shaped best-effort cache.
//!
//! `async fn in trait` is used throughout. These traits are consumed
//! with static dispatch (generics) by the service layer and route
//! handlers; they are not intended to be dyn-compatible. The lint is
//! silenced module-wide below.

#![allow(async_fn_in_trait)]

pub mod audit;
pub mod audit_chain;
pub mod cache;
pub mod repo;
pub mod session_index;
pub mod store;

use thiserror::Error;

/// The single error type surfaced by every port.
///
/// Adapters map their own backend errors down to this small set. The
/// variants are chosen so that callers can branch on *domain-relevant*
/// outcomes (Conflict vs PreconditionFailed) without leaking the
/// underlying storage technology.
#[derive(Debug, Error)]
pub enum PortError {
    /// The record does not exist.
    #[error("not found")]
    NotFound,

    /// The caller tried to create a record that already exists, or put
    /// a challenge into a slot that was already occupied. In
    /// single-consumption contexts (auth codes, refresh families), a
    /// Conflict on put means "pick a new handle", not "retry".
    #[error("already exists")]
    Conflict,

    /// The store recognized the key but the requested transition is
    /// not permitted from the current state. Used for things like
    /// rotating a refresh token that has already been retired - the
    /// domain meaning is different from "not found" and different from
    /// "conflict".
    #[error("precondition failed: {0}")]
    PreconditionFailed(&'static str),

    /// The backend is unreachable or returned an unrecoverable error.
    /// Distinct from `Conflict` / `NotFound` because retries may help.
    #[error("storage unavailable")]
    Unavailable,

    /// Payload could not be serialized into or deserialized out of the
    /// underlying store.
    #[error("serialization")]
    Serialization,
}

pub type PortResult<T> = Result<T, PortError>;

impl From<serde_json::Error> for PortError {
    fn from(_: serde_json::Error) -> Self {
        PortError::Serialization
    }
}
