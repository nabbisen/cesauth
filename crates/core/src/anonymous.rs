//! Anonymous trial principals (introduced v0.16.0, ADR-004).
//!
//! An *anonymous* principal is a thin auth surface for the
//! "visitor without an account" case. Unlike a `HumanUser`,
//! an anonymous principal:
//!
//! - has no email and is not registered;
//! - authenticates with a single short-lived bearer token
//!   (24h TTL, not refreshable);
//! - is automatically reaped 7 days post-creation if it is
//!   not promoted to `HumanUser` first;
//! - cannot reach any `/admin/*` route.
//!
//! The promotion ceremony is the only way an anonymous user
//! becomes permanent: visitor supplies an email, the standard
//! Magic Link verification confirms ownership, and the
//! existing user row is **updated in place** (id preserved,
//! `account_type` flipped, `email`/`email_verified` filled
//! in). All foreign keys pointing at the user — memberships,
//! role assignments, audit subject ids — survive without
//! remapping. ADR-004 §Q4 walks through the rejected
//! alternatives.
//!
//! This module ships as foundation only in v0.16.0:
//!
//! - the `AnonymousSession` value type,
//! - the `AnonymousSessionRepository` port,
//! - new `EventKind` variants (`AnonymousCreated`,
//!   `AnonymousExpired`, `AnonymousPromoted`).
//!
//! HTTP routes (`/api/v1/anonymous/begin`, `/promote`) and
//! the daily retention sweep ship in v0.17.0 and v0.6.05
//! respectively.

use serde::{Deserialize, Serialize};

use crate::ports::PortResult;
use crate::types::{Id, UnixSeconds};

// -------------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------------

/// Default TTL for an anonymous bearer token. ADR-004 §Q2 — short
/// enough that an unattended browser tab doesn't carry a working
/// session indefinitely, long enough to cover normal "I came back
/// after lunch" patterns. The retention sweep (§Q3, ships in
/// v0.6.05) uses a longer 7-day window for the user row itself.
pub const ANONYMOUS_TOKEN_TTL_SECONDS: i64 = 24 * 60 * 60;

/// Default retention window for an unpromoted anonymous user row.
/// ADR-004 §Q3. Promoted rows survive — the sweep checks
/// `email IS NULL` to avoid touching them.
pub const ANONYMOUS_USER_RETENTION_SECONDS: i64 = 7 * 24 * 60 * 60;

// -------------------------------------------------------------------------
// AnonymousSession value type
// -------------------------------------------------------------------------

/// One row in `anonymous_sessions`. Captures the state needed to
/// resolve an anonymous bearer token to a `User` row at request
/// time, plus the lifecycle metadata that the retention sweep and
/// the promotion path care about.
///
/// Field semantics mirror migration `0006_anonymous.sql` 1:1 —
/// changes here imply a schema change and a new migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnonymousSession {
    /// SHA-256 hex of the bearer-token plaintext. The plaintext is
    /// shown once at creation and never recoverable — same posture
    /// as `admin_tokens`.
    pub token_hash: String,

    /// The `users.id` this session authenticates as. The user row
    /// has `account_type='anonymous'` and `email IS NULL` until
    /// promotion flips both.
    pub user_id: Id,

    /// Issued-at, Unix seconds. Set by the server at /begin time.
    pub created_at: UnixSeconds,

    /// Expires-at, Unix seconds. Default `created_at +
    /// ANONYMOUS_TOKEN_TTL_SECONDS`. The application enforces — DB
    /// only stores. A request arriving after this timestamp is
    /// rejected before any business logic runs.
    pub expires_at: UnixSeconds,

    /// Tenant id. Denormalized from `users.tenant_id` here so that
    /// IP-rate-limit lookups and per-tenant diagnostics don't need
    /// a JOIN. Cascades from `tenants.id` so a tenant deletion
    /// clears its anonymous sessions automatically (anonymous
    /// principals never outlive their tenant).
    pub tenant_id: Id,
}

impl AnonymousSession {
    /// True if `now_unix` is past `expires_at`.
    ///
    /// The repository methods do not pre-filter on this; callers
    /// (route handlers) compare explicitly so a freshly-revoked
    /// token (`expires_at` set to `now_unix - 1` by the promotion
    /// path) is treated identically to a naturally-expired one.
    pub fn is_expired(&self, now_unix: UnixSeconds) -> bool {
        self.expires_at <= now_unix
    }
}

// -------------------------------------------------------------------------
// AnonymousSessionRepository port
// -------------------------------------------------------------------------

/// Storage for anonymous-session bearer tokens.
///
/// Shape mirrors `admin::ports::AdminTokenRepository` — same
/// "plaintext-out-once, hash-stored" model, same `now_unix`
/// argument convention, same `PortError` mapping. The differences:
///
/// - No `Role` parameter. Anonymous principals carry no admin
///   role; `Role` is irrelevant here.
/// - `find_by_hash` is the hot path (every anonymous request
///   resolves through it), so the index in 0006 covers it.
/// - `revoke_for_user` exists for the promotion path: when a row
///   is promoted, any outstanding anonymous tokens for that user
///   are nuked, forcing the freshly-promoted user to log in again
///   through the regular OIDC flow. Defense in depth for the
///   case where the promotion was triggered by an attacker
///   holding the anonymous bearer.
pub trait AnonymousSessionRepository {
    /// Insert a new anonymous-session row. Returns the persisted
    /// `AnonymousSession`. Caller mints the plaintext bearer and
    /// passes the SHA-256 hash here; the plaintext itself never
    /// crosses this boundary.
    ///
    /// `Conflict` indicates a hash collision (vanishingly unlikely
    /// in practice — caller picks a fresh handle and retries).
    /// `NotFound` indicates the named `user_id` does not exist or
    /// is not anonymous.
    async fn create(
        &self,
        token_hash: &str,
        user_id:    &str,
        tenant_id:  &str,
        now_unix:   UnixSeconds,
        ttl_secs:   i64,
    ) -> PortResult<AnonymousSession>;

    /// Look up a session by its token hash. The hot path: every
    /// request bearing an anonymous token resolves through this.
    /// Returns `None` for unknown tokens — the route layer maps
    /// that to a 401, same as any other unknown-bearer case.
    async fn find_by_hash(&self, token_hash: &str)
        -> PortResult<Option<AnonymousSession>>;

    /// Delete every session for the named user. Used by the
    /// promotion path to invalidate the anonymous bearer at the
    /// moment of promotion — a freshly-promoted `human_user` must
    /// log in through the normal OIDC ceremony, not continue
    /// holding the anonymous token.
    ///
    /// Returns the number of rows deleted. `Ok(0)` is not an
    /// error (the caller may have already lost the bearer; the
    /// idempotency is convenient).
    async fn revoke_for_user(&self, user_id: &str) -> PortResult<usize>;

    /// Delete every session whose `expires_at` is at or before
    /// `now_unix`. Called by the daily sweep handler (v0.6.05).
    /// Returns the number of rows deleted.
    ///
    /// The user-row sweep is a separate operation against the
    /// `users` table. This method only touches `anonymous_sessions`
    /// — the foreign-key cascade in 0006 ensures session rows
    /// disappear when their user does, so this method is the
    /// "tokens-without-users" cleanup path, not the dominant one.
    async fn delete_expired(&self, now_unix: UnixSeconds) -> PortResult<usize>;
}

// =====================================================================
// Tests for type-level invariants
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_constants_match_adr_004() {
        // ADR-004 §Q2 — 24h token TTL.
        assert_eq!(ANONYMOUS_TOKEN_TTL_SECONDS, 86_400);
        // ADR-004 §Q3 — 7d row retention.
        assert_eq!(ANONYMOUS_USER_RETENTION_SECONDS, 604_800);
        // The retention window must be strictly longer than the
        // token TTL — a token surviving its row would be a
        // dangling reference. The 0006 FK cascade prevents this
        // at the DB level, but documenting the inequality at
        // the constants level is cheap insurance.
        assert!(
            ANONYMOUS_USER_RETENTION_SECONDS > ANONYMOUS_TOKEN_TTL_SECONDS,
            "retention window must outlive any single token"
        );
    }

    #[test]
    fn anonymous_session_serializes_round_trip() {
        // The struct crosses the wire only at internal boundaries
        // (D1 row → port type), not at the HTTP surface, but a
        // serde round-trip catches accidental field renames.
        let s = AnonymousSession {
            token_hash: "h".into(),
            user_id:    "u-1".into(),
            tenant_id:  "tenant-default".into(),
            created_at: 1_700_000_000,
            expires_at: 1_700_086_400,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: AnonymousSession = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn is_expired_boundary_inclusive() {
        // Boundary: now_unix == expires_at counts as expired.
        // ADR-004 §Q2 — "a request arriving after this timestamp
        // is rejected". `<=` is the load-bearing operator;
        // a future refactor that flips this to `<` would let
        // a token live one second past its window.
        let s = AnonymousSession {
            token_hash: "h".into(), user_id: "u".into(),
            tenant_id: "t".into(), created_at: 0, expires_at: 100,
        };
        assert!(!s.is_expired(50));
        assert!(!s.is_expired(99));
        assert!( s.is_expired(100), "expires_at == now must count as expired");
        assert!( s.is_expired(200));
    }
}
