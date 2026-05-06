//! JWT issuance and verification (Ed25519 / EdDSA).
//!
//! Per spec §6:
//! * Signature alg is `EdDSA` only. We will not accept `HS256`/`RS256`
//!   tokens even if they validate, because that widens the attack
//!   surface for alg confusion (RFC 8725 §3.1).
//! * The private key lives in Workers Secrets and is loaded into
//!   [`signer::JwtSigner`] at startup.
//! * Public keys are published via `/jwks.json` (see `claims::Jwk`).

pub mod claims;
pub mod signer;

pub use claims::{AccessTokenClaims, IdTokenClaims, Jwk, JwksDocument};
pub use signer::{JwtSigner, verify_for_introspect};
