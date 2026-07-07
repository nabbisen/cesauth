//! Tests for `cesauth_core::totp`. Extracted to keep the parent
//! file focused on production code.
//!
//! The RFC 6238 test vectors at the top of the file pin the
//! HMAC-SHA1 implementation against the canonical reference.
//! Without them, a regression in time-step math could land silently
//! and break every existing authenticator.
//!
//! **v0.78.0 modularization.** Split into themed submodules:
//!
//! - [`rfc6238_vectors`]   — RFC 6238 Appendix B canonical test vectors
//! - [`step_for_unix`]     — time-step computation
//! - [`secret_round_trip`] — secret serialization round-trip + validation
//! - [`format_parse_code`] — format_code / parse_code helpers
//! - [`verify_replay`]     — verify_with_replay_protection
//! - [`otpauth_uri`]       — otpauth:// URI formatting
//! - [`recovery_codes`]    — recovery-code generation + verification
//! - [`encryption`]        — secret encryption / decryption

mod rfc6238_vectors;
mod step_for_unix;
mod secret_round_trip;
mod format_parse_code;
mod verify_replay;
mod otpauth_uri;
mod recovery_codes;
mod encryption;
