//! WebAuthn / Passkey ceremonies.
//!
//! We intentionally stay on the `webauthn-rs-core` + `webauthn-rs-proto`
//! subcrates rather than the full `webauthn-rs`. The full crate pulls in
//! `tokio` and `openssl`, neither of which builds for
//! `wasm32-unknown-unknown`. The `-core` and `-proto` crates carry just
//! the protocol types and the cryptographic verification, which is all
//! we need: cesauth holds its own state in D1 + Durable Objects and does
//! not want the session manager the parent crate bundles.
//!
//! The module is split into:
//!
//! * [`registration`] - new-credential ceremony (spec §11.4).
//! * [`authentication`] - assertion ceremony for login (spec §4.1).
//!
//! Both produce typed in-memory state that the worker layer hands to the
//! `AuthChallenge` Durable Object. The DO, not us, guarantees that a
//! challenge is consumed at most once.

pub mod authentication;
pub mod cose;
pub mod registration;

use serde::{Deserialize, Serialize};

use crate::types::{Id, UnixSeconds};

/// The subset of an authenticator we persist in D1. See the schema for
/// the authoritative column list; anything that isn't stable across
/// assertions (for example the current challenge) must *not* live here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAuthenticator {
    pub id:              Id,
    pub user_id:         Id,
    /// base64url-no-pad of the raw credential ID as the browser sends it.
    pub credential_id:   String,
    /// Raw COSE public key bytes. Left opaque here - verification
    /// happens via `webauthn-rs-core` which parses COSE itself.
    pub public_key:      Vec<u8>,
    pub sign_count:      u32,
    pub transports:      Option<Vec<String>>,
    pub aaguid:          Option<String>,
    pub backup_eligible: bool,
    pub backup_state:    bool,
    pub name:            Option<String>,
    pub created_at:      UnixSeconds,
    pub last_used_at:    Option<UnixSeconds>,
}

/// Relying Party identity. This is passed to every ceremony function so
/// that the origin / rpId checks are not accidentally pulled from
/// globals.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    pub id:     String,   // e.g. "auth.example.com"
    pub name:   String,   // e.g. "cesauth"
    pub origin: String,   // e.g. "https://auth.example.com"
}
