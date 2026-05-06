//! TOTP self-service routes under `/me/security/totp/*`.
//!
//! Wired in v0.29.0 (Security track Phase 6 of 11). The
//! cryptographic library is in `cesauth_core::totp` (v0.26.0);
//! storage adapters in `cesauth_core::totp::storage` and
//! `cesauth-adapter-cloudflare` (v0.27.0); UI templates in
//! `cesauth_ui::templates::totp_*` (v0.28.0); QR code generator
//! in `cesauth_core::totp::qr` (v0.28.0). This module is the
//! HTTP-facing layer that ties them all together.
//!
//! Routes:
//!
//! - `GET  /me/security/totp/enroll` — show the QR code and
//!   manual-entry secret. Mints a fresh secret, parks an
//!   unconfirmed `totp_authenticators` row, renders the
//!   confirmation form.
//! - `POST /me/security/totp/enroll/confirm` — verify the
//!   first code. On success, flips `confirmed_at`, mints 10
//!   recovery codes, displays them once, ends the flow.
//! - `GET  /me/security/totp/verify` — TOTP prompt page after
//!   the post-MagicLink gate parked a `Challenge::PendingTotp`.
//! - `POST /me/security/totp/verify` — verify the code, on
//!   success consume the PendingTotp + resume the original
//!   `complete_auth` continuation (start session, mint AuthCode
//!   if AR was parked, redirect).
//! - `POST /me/security/totp/recover` — single-use recovery
//!   code redemption, alternative to the verify path.
//!
//! Disable flow (`POST /me/security/totp/disable`) is
//! deferred to v0.30.0 alongside the cron sweep, redaction
//! profile, and operator chapter — see ROADMAP.

pub mod enroll;
pub mod recover;
pub mod verify;
