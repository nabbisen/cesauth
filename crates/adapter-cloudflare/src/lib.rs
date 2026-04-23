// `#[durable_object]`-tagged structs hold `worker::State` and
// `worker::Env`, neither of which implements `Debug`. Suppress the
// default `missing_debug_implementations` warning crate-wide.
#![allow(missing_debug_implementations)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

//! # cesauth-adapter-cloudflare
//!
//! The Cloudflare side of the port/adapter boundary. Two kinds of code
//! live here:
//!
//! 1. **Durable Object classes** (`auth_challenge`,
//!    `refresh_token_family`, `active_session`, `rate_limit`) - the
//!    actual `#[durable_object]` definitions that the Workers runtime
//!    loads. Their *domain state types* are owned by `cesauth-core`
//!    (see `cesauth_core::ports::store`); this crate supplies only
//!    the storage backing and the per-request RPC shell.
//!
//! 2. **Port adapters** (`ports::*`) - trait implementations that
//!    bridge `cesauth-core`'s ports to the Cloudflare runtime. The DO
//!    store adapters talk to (1) via its HTTP RPC; the D1 repo
//!    adapters talk directly to the D1 binding; the KV cache and R2
//!    audit adapters do likewise.
//!
//! ## DO export path
//!
//! `#[durable_object]` emits `#[wasm_bindgen]` exports, which the
//! Workers runtime binds by class name (see `wrangler.toml`). Because
//! those exports are emitted when the cdylib links this rlib, the
//! re-export from the `worker` crate (`pub use cesauth_cf::*;`) is
//! what actually surfaces them in the final WASM binary. Do not
//! collapse that indirection without verifying DO classes still load.

pub mod active_session;
pub mod auth_challenge;
pub mod ports;
pub mod rate_limit;
pub mod refresh_token_family;

pub use active_session::ActiveSession;
pub use auth_challenge::AuthChallenge;
pub use rate_limit::RateLimit;
pub use refresh_token_family::RefreshTokenFamily;
