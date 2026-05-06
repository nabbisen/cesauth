//! Error types for the core domain.
//!
//! Per spec §10.3, we separate **internal errors** (what went wrong) from
//! **external responses** (what the client is told). The mapping to the
//! standardized OAuth / HTTP error codes happens in `cesauth-worker`, so
//! that `core` stays protocol-library-pure.

use thiserror::Error;

/// The canonical internal error enum for the core crate.
///
/// Variants are chosen to be *diagnostic* - each one carries enough
/// information for logs to tell us what happened, but not so much that
/// secrets leak into `Display`. Concretely: never put a full token or
/// raw private key bytes into a variant's payload.
#[derive(Debug, Error)]
pub enum CoreError {
    // --- Validation / input ------------------------------------------------
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),

    #[error("invalid grant: {0}")]
    InvalidGrant(&'static str),

    /// **v0.34.0** — Refresh token reuse detected (RFC 9700
    /// §4.14.2). Distinct from `InvalidGrant` because the
    /// worker MUST emit a different audit event for reuse vs
    /// for an already-revoked or expired family — operators
    /// monitoring for compromise need the signal isolated, and
    /// the BCP §4.13 explicitly recommends observable reuse
    /// detection. The variant carries the same forensic
    /// payload as `RotateOutcome::ReusedAndRevoked`, so the
    /// worker doesn't have to peek the family again.
    ///
    /// Maps to OAuth `invalid_grant` with `error_description`
    /// "refresh token reuse detected" at the wire layer — the
    /// same HTTP-visible response as the legitimate-revoked
    /// path, so attackers can't probe whether a presented
    /// jti is currently retired (which would let them
    /// distinguish "jti unknown" from "jti retired" externally).
    #[error("refresh token reuse detected (was_retired={was_retired})")]
    RefreshTokenReuse {
        reused_jti:  String,
        was_retired: bool,
    },

    #[error("invalid client")]
    InvalidClient,

    /// **v0.37.0** — Rate-limit threshold exceeded (ADR-011
    /// §Q1 resolution). Used by `rotate_refresh` when too
    /// many attempts have been made against one
    /// `family_id` in the configured window. `retry_after_secs`
    /// is the number of seconds the caller should wait before
    /// trying again — sourced from the rate-limit store's
    /// `resets_in`.
    ///
    /// Distinct from `RefreshTokenReuse`: rate-limit bounds
    /// rapid retry, reuse atomically burns the family. The
    /// two can co-occur (an attacker rotating in a tight
    /// loop with a leaked-then-rotated-out jti would hit
    /// reuse on the first non-current jti they present); rate
    /// limit fires earlier and is purely about request
    /// volume.
    ///
    /// Maps to HTTP 429 with `Retry-After` header at the wire
    /// layer.
    #[error("rate limited (retry after {retry_after_secs} seconds)")]
    RateLimited {
        retry_after_secs: i64,
    },

    #[error("invalid scope: {0}")]
    InvalidScope(&'static str),

    #[error("unsupported grant type: {0}")]
    UnsupportedGrantType(String),

    // --- PKCE --------------------------------------------------------------
    #[error("pkce verification failed")]
    PkceMismatch,

    // --- WebAuthn ---------------------------------------------------------
    #[error("webauthn ceremony failed: {0}")]
    WebAuthn(&'static str),

    // --- JWT --------------------------------------------------------------
    /// Covers signature failure, bad algorithm, expired, aud/iss/nonce mismatch.
    #[error("jwt validation failed: {0}")]
    JwtValidation(&'static str),

    #[error("jwt signing failed")]
    JwtSigning,

    // --- Magic link / OTP -------------------------------------------------
    #[error("magic link expired")]
    MagicLinkExpired,

    #[error("magic link verification failed")]
    MagicLinkMismatch,

    // --- OIDC interactive policy ------------------------------------------
    /// `prompt=none` was requested but there is no usable active session,
    /// or `max_age` has been exceeded and interaction is required. Per
    /// OIDC §3.1.2.6 this maps to the `login_required` error code, and
    /// per §3.1.2.1 the Authorization Server "MUST NOT display any
    /// authentication or consent user interface pages".
    #[error("login required")]
    LoginRequired,

    // --- Serialization ----------------------------------------------------
    #[error("serialization error")]
    Serialization,

    // --- Unexpected -------------------------------------------------------
    /// Use sparingly. Anything that hits this should be promoted to its own
    /// variant as we understand more failure modes.
    #[error("internal error")]
    Internal,
}

impl From<serde_json::Error> for CoreError {
    fn from(_: serde_json::Error) -> Self {
        // Deliberately drop the underlying message - serde errors occasionally
        // include snippets of the input, which for us could be credentials.
        CoreError::Serialization
    }
}

pub type CoreResult<T> = Result<T, CoreError>;
