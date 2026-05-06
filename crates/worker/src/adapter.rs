//! Worker-layer adapter wrappers.
//!
//! This module re-exports factory functions from `cesauth-adapter-cloudflare`
//! so that route handlers import from `crate::adapter` without needing to
//! know the underlying CF adapter crate.

pub mod mailer;
