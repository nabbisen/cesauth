//! Unit tests for the parent `crates/ui/src/templates/` module.
//!
//! **v0.75.0 modularization.** The single-file version of this module
//! exceeded 2,000 lines (4x the dev-guideline 500-ELOC "strongly
//! recommended split" threshold). Tests are now split into per-feature
//! submodules under `templates/tests/`, each scoped to one release or
//! RFC milestone:
//!
//! - [`common`]              — shared `strip_inline_style` helper.
//! - [`early_pages`]         — login, error, magic_link sent page,
//!                             initial TOTP flow (v0.28.0–v0.30.0).
//! - [`v0_31_design`]        — design tokens, flash_block,
//!                             totp_enroll error slot, security_center
//!                             base (v0.31.0 P0-A through P0-D).
//! - [`v0_35_sessions`]      — sessions_page rendering + EN locale.
//! - [`v0_45_bulk_revoke`]   — sessions bulk-revoke (ADR-012 §Q4).
//! - [`i18n`]                — cross-template i18n tests (v0.39.0 +
//!                             v0.47.0 EN extensions).
//! - [`rfc_006_and_later`]   — RFC 006 nonce + RFC 027 flash a11y
//!                             + html-lang + recovery confirm
//!                             + skip-link + magic-link availability.
//!
//! Adding a new test: place it next to the milestone that introduced
//! the feature. If a new feature/milestone arrives, create a new
//! submodule rather than padding an existing one (keep each module
//! under 500 ELOC per the guideline).

mod common;
mod early_pages;
mod v0_31_design;
mod v0_35_sessions;
mod v0_45_bulk_revoke;
mod i18n;
mod rfc_006_and_later;
