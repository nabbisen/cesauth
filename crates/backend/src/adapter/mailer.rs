//! Worker-layer mailer factory.
//!
//! Re-exports `cesauth_cf::mailer::from_env` so route handlers can write
//! `use crate::adapter::mailer::from_env` without importing the CF crate
//! directly.
//!
//! Having this thin wrapper keeps the import surface clean and makes it
//! easy to swap the factory in integration tests.

pub use cesauth_cf::mailer::from_env;
