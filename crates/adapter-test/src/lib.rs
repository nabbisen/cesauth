//! # cesauth-adapter-test
//!
//! In-memory port implementations for host-side tests.
//!
//! Per the architecture addendum (§4): cesauth pins its domain
//! specification *first* by exercising the `core` service layer
//! through these adapters, and only then wires `adapter-cloudflare` to
//! the real Workers environment. A test that fails here means the
//! domain is wrong; a test that passes here but fails in `wrangler
//! dev` means the adapter is wrong.
//!
//! These implementations are **not** production-grade:
//!
//! * They use `std::sync::Mutex` (blocking) rather than async mutexes.
//!   Fine for tests, wrong for real load.
//! * They never expire entries on a wall clock; the test supplies
//!   `now_unix` explicitly.
//! * They do no durability - process restart loses everything.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms)]
#![allow(async_fn_in_trait)]

pub mod admin;
pub mod anonymous;
pub mod audit;
pub mod authz;
pub mod billing;
pub mod cache;
pub mod repo;
pub mod store;
pub mod tenancy;
