//! `/me/*` — user self-service routes.
//!
//! All routes here are cookie-authenticated via
//! `__Host-cesauth_session`. The `auth::resolve_or_redirect`
//! helper centralizes that gate.
//!
//! v0.28.0 introduces this module with the `auth` helper +
//! TOTP presentation-layer support (templates in `cesauth-ui`,
//! QR generator in `cesauth_core::totp::qr`). The actual TOTP
//! HTTP routes (`/me/security/totp/*`) land in v0.29.0 along
//! with the `complete_auth` verify-gate insertion. Future
//! releases will add `/me/security` (session-listing, "new
//! device" notifications), `/me/email` (email-change flow), etc.

pub mod auth;
