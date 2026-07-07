//! Deployment-target entrypoints.
//!
//! Each file in this directory is one deployment target.
//! Currently only Cloudflare Workers is supported.
//!
//! The `#[event(fetch)]` and `#[event(scheduled)]` handlers live in
//! `lib.rs` for now because the `worker::event` macro generates WASM
//! exports that must be visible at the cdylib root.  A follow-up
//! refactor will move them here once a `#[path]`-based re-export
//! pattern that satisfies `worker-build` is verified on the wasm32
//! target (env-blocked: requires `wrangler dev` to confirm).
//!
//! What this module already owns:
//! - The Durable Object class re-exports (see `cloudflare.rs`).
//!
//! Future:
//! - `pub mod axum;` — self-hosted deployment target.
pub mod cloudflare;
