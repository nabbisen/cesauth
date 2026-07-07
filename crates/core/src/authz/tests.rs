//! Authorization domain tests.
//!
//! **v0.78.0 modularization.** The single-file version of this module
//! exceeded 606 lines. Tests are now split into themed submodules:
//!
//! - [`common`]                   — stubs (in-module repository) + helpers
//! - [`catalog_and_assignments`]  — catalog shape, no-assignments edge case
//! - [`scope_and_expiration`]     — system role, scope mismatch, permission missing, expiration
//! - [`happy_and_dangling`]       — happy path + dangling role tolerance
//! - [`batch_permissions`]        — v0.15.0 check_permissions_batch
//! - [`rfc_052_hardening`]        — RFC 052 authorization hardening

mod common;
mod catalog_and_assignments;
mod scope_and_expiration;
mod happy_and_dangling;
mod batch_permissions;
mod rfc_052_hardening;
