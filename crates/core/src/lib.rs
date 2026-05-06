//! # cesauth-core
//!
//! The domain layer of cesauth. This crate has **no** dependency on
//! `worker`, Cloudflare-specific crates, or any runtime service. It exists
//! so the protocol logic (OIDC, WebAuthn, JWT, Magic Link) can be
//! unit-tested on the host and reasoned about in isolation from the
//! Workers execution environment.
//!
//! Boundaries:
//!
//! * Pure functions and value types live here.
//! * Anything that touches D1, KV, R2, a Durable Object, or an HTTP
//!   response **does not** live here - it belongs to `cesauth-worker`
//!   or `cesauth-do`.
//! * Traits that describe *what* a storage-facing caller must provide
//!   (for example, "give me the authenticator with this credential_id")
//!   live here, and are implemented in the worker crate.
//!
//! See `docs/architecture.md` for the full diagram.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms)]
// Matches adapter-test: many ports are `async fn` in a trait, which
// lacks `Send` bounds on the returned future. We're fine with that
// here because the worker runtime is single-threaded per request.
#![allow(async_fn_in_trait)]

pub mod admin;
pub mod anonymous;
pub mod authz;
pub mod billing;
pub mod error;
pub mod jwt;
pub mod magic_link;
pub mod migrate;
pub mod oidc;
pub mod ports;
pub mod service;
pub mod session;
pub mod tenancy;
pub mod tenant_admin;
pub mod turnstile;
pub mod types;
pub mod webauthn;

pub use error::{CoreError, CoreResult};
