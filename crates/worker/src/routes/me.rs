//! `/me/*` — user self-service routes.
//!
//! All routes here are cookie-authenticated via
//! `__Host-cesauth_session`. The `auth::resolve_or_redirect`
//! helper centralizes that gate.
//!
//! v0.28.0 introduced this module with the `auth` helper +
//! TOTP presentation-layer support (templates, QR generator).
//! v0.29.0 adds the actual TOTP HTTP routes (`/me/security/totp/*`)
//! plus the verify-gate insertion in `post_auth::complete_auth`.
//! Future releases will add `/me/security` (session-listing,
//! "new device" notifications), `/me/email` (email-change flow),
//! etc.

pub mod auth;
pub mod security;
pub mod totp;
