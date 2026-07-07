//! Cross-module sanity-check tests for the tenant-admin surface.
//!
//! Per-template tests live next to each template. These tests assert
//! invariants across the module: that every page goes through
//! `tenant_admin_frame` and includes the tenant identity, that nav
//! links are slug-relative, and that drill-in tabs don't bleed into
//! the nav.
//!
//! **v0.77.0 modularization.** The single-file version of this module
//! exceeded 895 lines. Tests are now split into per-feature submodules
//! under `tenant_admin/tests/`, each scoped to one release or theme:
//!
//! - [`common`]            — shared fixtures (`principal`, `sample_tenant`, etc.)
//! - [`frame_invariants`]  — every page goes through `tenant_admin_frame`
//! - [`page_level`]        — overview, organizations, users
//! - [`mutation_forms`]    — v0.14.0 create/edit forms
//! - [`affordance_gating`] — v0.15.0 role-based affordance gating
//! - [`membership_forms`]  — v0.15.0 membership add/remove forms
//! - [`design_tokens`]     — RFC 105 design-token unification

mod common;
mod frame_invariants;
mod page_level;
mod mutation_forms;
mod affordance_gating;
mod membership_forms;
mod design_tokens;
