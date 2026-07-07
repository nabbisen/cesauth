//! Cloudflare Workers entrypoint bindings.
//!
//! This file owns the Cloudflare-specific glue that would not exist in
//! a self-hosted (Axum) deployment:
//!
//! - **Durable Object re-exports**: `#[durable_object]` generates WASM
//!   exports under the *cdylib* crate.  The DO implementations live in
//!   `cesauth-adapter-cloudflare`; we re-export them here so the
//!   macro-generated WASM export symbols land in `cesauth-backend`'s
//!   compiled module.  Remove any of these only after updating
//!   `wrangler.toml` and verifying the DO classes still load in
//!   `wrangler dev`.
//!
//! - **`#[event(fetch)]` / `#[event(scheduled)]`**: the Workers fetch
//!   and cron handlers.  Currently these live in `lib.rs` because the
//!   `worker::event` proc-macro generates `extern "C"` exports that
//!   must be at the cdylib root.  They will be moved here once the
//!   re-export pattern is verified against the wasm32 target.

// Re-export the four DO classes so the macro-generated WASM exports
// land in the cesauth-backend cdylib.
pub use cesauth_cf::{ActiveSession, AuthChallenge, RateLimit, RefreshTokenFamily};
