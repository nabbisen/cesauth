//! In-memory repository implementations.
//!
//! Not a lot to say: these are HashMaps behind Mutexes. The behaviours
//! worth checking (case-insensitive email lookup, conflict on create)
//! are encoded in tests against this module, which means: if the
//! Cloudflare D1 adapter later diverges on semantics, we know the
//! divergence by replacing this with the D1 adapter in those same
//! tests and watching them fail.
//!
//! One submodule per port trait - symmetric to
//! `cesauth_cf::ports::repo`.

mod authenticators;
mod clients;
mod grants;
mod signing_keys;
mod users;

pub use authenticators::InMemoryAuthenticatorRepository;
pub use clients::InMemoryClientRepository;
pub use grants::InMemoryGrantRepository;
pub use signing_keys::InMemorySigningKeyRepository;
pub use users::InMemoryUserRepository;

#[cfg(test)]
mod tests;
