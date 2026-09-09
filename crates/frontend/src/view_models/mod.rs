//! View models and form contracts (RFC 029, imported RFC 131 R2a).
//!
//! Every screen component accepts exactly one typed view-model struct as its
//! primary prop. Form components carry a [`FormContract`] that specifies
//! the HTTP action, method, CSRF token, Turnstile token, field list,
//! redirect target, and audit event name — all resolved by the server before
//! rendering.
//!
//! The workbench adapter (`cesauth-mockup-workbench/src/adapters/`) supplies
//! mock values for each contract. The production backend supplies real values
//! built from session and domain state.

pub mod auth;
pub mod me;
pub mod operator;
pub mod roles;
pub mod shared;
pub mod tenant;
