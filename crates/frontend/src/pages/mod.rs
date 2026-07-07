//! Route-level Leptos page components.
//!
//! Each module maps to one URL path.  Modules are added here as
//! screens are migrated from the old string-template layer per the
//! Phase C migration schedule in the master plan.
//!
//! Phase C schedule (from RFC 115):
//!   v0.79.2 — security_center  ← current
//!   v0.79.3 — sessions
//!   v0.79.4 — totp
//!   v0.79.5 — login + magic_link
//!   v0.79.6 — tenant admin console
//!   v0.79.7 — system operator console
//!   v0.80.0 — remove all old string templates
pub mod security_center;
pub mod sessions;
pub mod totp;
