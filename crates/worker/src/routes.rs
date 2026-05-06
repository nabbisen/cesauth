//! HTTP route handlers, one submodule per broad endpoint family.
//!
//! The handlers here are thin: they validate input, call into
//! `cesauth-core` for protocol logic, call into Durable Objects via
//! their `fetch` RPC, write audit events, and emit a response. Anything
//! with domain meaning belongs in `cesauth-core`; anything with
//! transactional meaning belongs in a DO.

pub mod admin;
pub mod api_v1;
pub mod dev;
pub mod magic_link;
pub mod me;
pub mod oidc;
pub mod session;
pub mod ui;
pub mod webauthn;
