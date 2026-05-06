//! Audit log domain logic.
//!
//! This module holds the audit log primitives that don't depend on
//! storage or runtime: the hash chain calculation, the chain input
//! layout, the genesis sentinel values. Storage is over in
//! `crate::ports::audit` (the trait) and the adapters; the worker
//! layer wires storage to the HTTP entry points.
//!
//! The chain mechanism is documented in ADR-010 and in the operator
//! chapter `docs/src/expert/audit-log-hash-chain.md`. This module is
//! the canonical implementation of the byte layout that the chain
//! depends on. Changing anything in [`chain::compute_chain_hash`] is
//! a chain version bump.

pub mod chain;
pub mod retention;
pub mod verifier;
