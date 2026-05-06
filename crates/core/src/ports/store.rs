//! DO-shaped, per-key serialized state machines.
//!
//! **Contract.** An implementation of any trait in this module MUST
//! serialize operations on the same key. Two concurrent `rotate()`
//! calls with the same `family_id` must be ordered; the first wins, the
//! second sees the updated state. Cloudflare Durable Objects provide
//! this naturally; in-memory adapters use a mutex per key.
//!
//! The operations are intentionally not exposed as a generic
//! "transaction" primitive (per architecture addendum §3). Each trait
//! method names a domain operation: *rotate*, *consume*, *revoke*.
//! Callers cannot sequence arbitrary reads/writes under a lock through
//! this surface, which is exactly the point - any operation that needs
//! such sequencing gets promoted to its own dedicated method.

use serde::{Deserialize, Serialize};

use super::PortResult;
use crate::types::Scopes;

// -------------------------------------------------------------------------
// Shared challenge payload. Moved here from the DO crate so the domain
// layer owns the type; adapters serialize it, they do not redefine it.
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Challenge {
    AuthCode {
        client_id:             String,
        redirect_uri:          String,
        user_id:               String,
        scopes:                Scopes,
        nonce:                 Option<String>,
        code_challenge:        String,
        code_challenge_method: String,
        issued_at:             i64,
        expires_at:            i64,
    },
    /// A parked authorization request waiting for the user to complete
    /// authentication. The post-auth handler reads this, mints an
    /// `AuthCode`, and redirects to the client's `redirect_uri`.
    ///
    /// The DO storage is the only place the parked request lives. The
    /// user's browser only carries the *handle*, inside a signed cookie.
    PendingAuthorize {
        client_id:             String,
        redirect_uri:          String,
        /// Space-separated scope string as the client originally sent it.
        /// We keep the original form (not `Scopes`) so any echoing back
        /// to the client or audit log is byte-identical.
        scope:                 Option<String>,
        state:                 Option<String>,
        nonce:                 Option<String>,
        code_challenge:        String,
        code_challenge_method: String,
        expires_at:            i64,
    },
    WebauthnRegister {
        user_id:    String,
        challenge:  String,      // base64url of 32 random bytes
        expires_at: i64,
    },
    WebauthnAuthenticate {
        pinned_user_id: Option<String>,
        challenge:      String,
        expires_at:     i64,
    },
    MagicLink {
        email_or_user: String,
        code_hash:     String,   // sha256(otp) base64url
        attempts:      u32,
        expires_at:    i64,
    },
    /// Intermediate state between successful primary auth (Magic
    /// Link) and a fully-issued session, when the user has TOTP
    /// configured. Parked by `complete_auth` when it detects a
    /// confirmed TOTP authenticator; consumed by the TOTP verify
    /// route. The handle goes into a short-lived `__Host-cesauth_totp`
    /// cookie scoped to the TOTP prompt page; on successful
    /// verification the original `complete_auth` flow resumes
    /// (session start, AR resolution, redirect).
    ///
    /// `pending_ar_handle` is the handle of any parked
    /// `PendingAuthorize` challenge that the TOTP prompt must
    /// resolve once the user proves possession. None when the
    /// user landed at `/login` directly without an OAuth `/authorize`
    /// chain.
    ///
    /// ADR-009 §Q7. Wire-up in v0.27.0.
    PendingTotp {
        user_id:           String,
        auth_method:       AuthMethod,
        pending_ar_handle: Option<String>,
        attempts:          u32,
        expires_at:        i64,
    },
}

impl Challenge {
    pub fn expires_at(&self) -> i64 {
        match self {
            Self::AuthCode             { expires_at, .. } => *expires_at,
            Self::PendingAuthorize     { expires_at, .. } => *expires_at,
            Self::WebauthnRegister     { expires_at, .. } => *expires_at,
            Self::WebauthnAuthenticate { expires_at, .. } => *expires_at,
            Self::MagicLink            { expires_at, .. } => *expires_at,
            Self::PendingTotp          { expires_at, .. } => *expires_at,
        }
    }
}

/// Short-lived single-consumption challenges: authorization codes,
/// WebAuthn ceremony nonces, and Magic Link OTP hashes.
///
/// Implementations MUST:
/// * Reject `put` when a value already exists (no overwrite).
/// * Make `take` atomic: if the caller receives `Some(value)`, no
///   other caller will ever see that same value from `take` or `peek`.
/// * Treat entries past `expires_at` as absent (`None`).
pub trait AuthChallengeStore {
    async fn put(&self, handle: &str, challenge: &Challenge) -> PortResult<()>;
    async fn peek(&self, handle: &str) -> PortResult<Option<Challenge>>;
    async fn take(&self, handle: &str) -> PortResult<Option<Challenge>>;

    /// Increment the attempt counter on a MagicLink challenge without
    /// consuming it. Returns the new attempt count, or `NotFound` if
    /// absent / expired / not a MagicLink variant.
    async fn bump_magic_link_attempts(&self, handle: &str) -> PortResult<u32>;
}

// -------------------------------------------------------------------------
// Refresh token family.
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyState {
    pub family_id:       String,
    pub user_id:         String,
    pub client_id:       String,
    pub scopes:          Vec<String>,
    pub current_jti:     String,
    pub retired_jtis:    Vec<String>,
    pub created_at:      i64,
    pub last_rotated_at: i64,
    pub revoked_at:      Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyInit {
    pub family_id: String,
    pub user_id:   String,
    pub client_id: String,
    pub scopes:    Vec<String>,
    pub first_jti: String,
    pub now_unix:  i64,
}

/// Outcome of a rotation attempt.
///
/// `Mismatch` is *not* an error from the port's perspective - it's a
/// domain signal that the caller must react to by revoking the family
/// (the store does this itself internally before returning). We return
/// an enum rather than `Result<_, PortError>` so the caller cannot
/// accidentally `?`-propagate a reuse event into a generic error path.
#[derive(Debug, Clone)]
pub enum RotateOutcome {
    /// Happy path. `new_current_jti` is what the caller should now sign.
    Rotated { new_current_jti: String },
    /// The family was already revoked before this rotation attempt.
    AlreadyRevoked,
    /// The presented jti is not the current one. The family has been
    /// revoked as a side effect.
    ReusedAndRevoked,
}

pub trait RefreshTokenFamilyStore {
    /// Create a fresh family. Returns `Conflict` if the id is already in
    /// use - callers must mint a new id rather than retry.
    async fn init(&self, init: &FamilyInit) -> PortResult<()>;

    /// Rotate. On success the DO's current_jti is now `new_jti`. On
    /// reuse, the family is atomically marked revoked *and then* the
    /// outcome is returned.
    async fn rotate(
        &self,
        family_id:     &str,
        presented_jti: &str,
        new_jti:       &str,
        now_unix:      i64,
    ) -> PortResult<RotateOutcome>;

    async fn revoke(&self, family_id: &str, now_unix: i64) -> PortResult<()>;

    async fn peek(&self, family_id: &str) -> PortResult<Option<FamilyState>>;
}

// -------------------------------------------------------------------------
// Active session.
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Passkey,
    MagicLink,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id:   String,
    pub user_id:      String,
    pub client_id:    String,
    pub scopes:       Vec<String>,
    pub auth_method:  AuthMethod,
    pub created_at:   i64,
    pub last_seen_at: i64,
    pub revoked_at:   Option<i64>,
}

#[derive(Debug, Clone)]
pub enum SessionStatus {
    NotStarted,
    Active(SessionState),
    Revoked(SessionState),
}

pub trait ActiveSessionStore {
    async fn start(&self, state: &SessionState) -> PortResult<()>;
    async fn touch(&self, session_id: &str, now_unix: i64) -> PortResult<SessionStatus>;
    async fn status(&self, session_id: &str) -> PortResult<SessionStatus>;
    async fn revoke(&self, session_id: &str, now_unix: i64) -> PortResult<SessionStatus>;
}

// -------------------------------------------------------------------------
// Rate limiter.
// -------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RateLimitDecision {
    pub allowed:   bool,
    pub count:     u32,
    pub limit:     u32,
    pub resets_in: i64,
    /// Signals the worker layer to require Turnstile on next attempt.
    pub escalate:  bool,
}

pub trait RateLimitStore {
    /// Record one hit against `bucket_key` and return the decision.
    /// `window_secs` and `limit` define the current regime; the same
    /// bucket can be polled by multiple regimes as long as they agree
    /// per call (in practice each endpoint passes its own fixed pair).
    async fn hit(
        &self,
        bucket_key:     &str,
        now_unix:       i64,
        window_secs:    i64,
        limit:          u32,
        escalate_after: u32,
    ) -> PortResult<RateLimitDecision>;

    async fn reset(&self, bucket_key: &str) -> PortResult<()>;
}
