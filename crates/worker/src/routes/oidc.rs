//! `/authorize`, `/token`, `/revoke`, `/.well-known/openid-configuration`, `/jwks.json`.
//!
//! One submodule per endpoint. Every handler here is a thin glue
//! layer: parse -> call into `cesauth_core::service` -> shape the HTTP
//! response. If a handler starts growing business logic, that logic
//! should be pushed into `core`.

mod authorize;
mod discovery;
mod introspect;
mod jwks;
mod revoke;
mod token;

pub use authorize::authorize;
pub use discovery::discovery;
pub use introspect::handler as introspect;
pub use jwks::jwks;
pub use revoke::revoke;
pub use token::token;
