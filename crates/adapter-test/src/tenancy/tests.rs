//! Integration tests for the v0.5.0 tenancy-service extension.
//!
//! These exercise the core service layer through the in-memory
//! adapters. They are intentionally located in `adapter-test` rather
//! than `cesauth-core::tenancy::tests` because they need actual port
//! impls.
//!
//! **v0.78.0 modularization.** The single-file version of this module
//! exceeded 664 lines. Tests are now split into themed submodules:
//!
//! - [`common`]               — shared fixtures
//! - [`end_to_end`]            — tenant → org → group → user (§16.1/16.2)
//! - [`permission_lattice`]    — §16.3 permission checks at full lattice
//! - [`billing`]               — billing round-trip + history append
//! - [`membership_negative`]   — membership negative paths
//! - [`rfc_056_soft_delete`]   — RFC 056 soft delete tests
//! - [`rfc_058_onboarding`]    — RFC 058 onboarding E2E (SaaS guide §16.2/§16.6)

mod common;
mod end_to_end;
mod permission_lattice;
mod billing;
mod membership_negative;
mod rfc_056_soft_delete;
mod rfc_058_onboarding;
