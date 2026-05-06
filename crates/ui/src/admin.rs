//! Admin-console HTML templates.
//!
//! Every page on the v0.3 Cost & Data Safety Admin Console is a pure
//! function here. Pages are server-rendered plain HTML with no
//! JavaScript; the strict CSP applied by the worker layer blocks any
//! script-src outright.
//!
//! Shared chrome — the `<header>`/`<nav>`/`<footer>` — is in
//! [`frame::admin_frame`]; every page delegates to it after rendering
//! its body fragment.
//!
//! Intentionally not using a templating engine. These pages are short;
//! `format!` with an `escape()` pass on every untrusted string is
//! obvious at a glance and has zero dependency weight.
//!
//! Accessibility targets (spec §9):
//!   * Every table uses `<th scope=...>` headers.
//!   * Alerts use `role="status"` so screen-readers announce them on
//!     page load without being intrusive (vs `role="alert"` which
//!     interrupts).
//!   * Danger-class controls have both visual (red border + "This will
//!     …" phrasing) and programmatic (aria-label) cues.

pub mod alerts;
pub mod audit;
pub mod audit_chain;
pub mod config;
pub mod config_edit;
pub mod cost;
pub mod frame;
pub mod overview;
pub mod safety;
pub mod tokens;

pub use alerts::alerts_page;
pub use audit::audit_page;
pub use audit_chain::audit_chain_status_page;
pub use config::config_page;
pub use config_edit::{confirm_page as config_confirm_page, edit_form as config_edit_form};
pub use cost::cost_page;
pub use overview::overview_page;
pub use safety::safety_page;
pub use tokens::{created_page as token_created_page, list_page as tokens_list_page, new_form as token_new_form};

#[cfg(test)]
mod tests;
