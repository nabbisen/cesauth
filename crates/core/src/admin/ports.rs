//! Port traits for the admin console.
//!
//! Each trait describes one persistence responsibility. Concrete
//! implementations live in `cesauth-adapter-cloudflare::admin` (D1 / R2)
//! and `cesauth-adapter-test::admin` (in-memory).
//!
//! These are NOT folded into [`crate::ports`] because:
//!
//! 1. The admin surface does not exist in the authentication hot-path;
//!    keeping it off the main port namespace keeps the auth engineer's
//!    view small.
//! 2. We lean on a slightly wider set of return types (audit entries,
//!    threshold rows) than anything in the core auth flow needs.
//!
//! All fallible paths return `PortResult<T>` from the main ports module,
//! which the service layer maps to `CoreError` as usual.
//!
//! Style matches `crate::ports::store`: native `async fn` in trait
//! (stable since Rust 1.75), no `async-trait` crate, generic
//! monomorphization at the call site.

use crate::ports::{PortError, PortResult};

use super::types::{
    AdminAuditEntry, AdminPrincipal, AuditQuery, BucketSafetyChange, BucketSafetyState,
    CostSnapshot, Role, ServiceId, Threshold,
};

// -------------------------------------------------------------------------
// Principal resolution
// -------------------------------------------------------------------------

/// Resolves an incoming bearer token to an admin principal.
///
/// Implementations typically:
///   * compare the token (constant-time) to `ADMIN_API_KEY` and return a
///     synthetic "super-bootstrap" principal on match,
///   * otherwise SHA-256-hash the token and look it up in the
///     `admin_tokens` D1 table.
///
/// Returns `NotFound` for unknown or disabled tokens. The worker layer
/// translates this to 401.
pub trait AdminPrincipalResolver {
    async fn resolve(&self, bearer: &str) -> PortResult<AdminPrincipal>;

    /// Record that this principal just successfully authenticated, so
    /// the UI can show `last_used_at`. Best-effort; failure here must
    /// NOT block the request.
    async fn touch_last_used(&self, principal_id: &str, now_unix: i64) -> PortResult<()>;
}

// -------------------------------------------------------------------------
// Usage metrics
// -------------------------------------------------------------------------

/// Live read of current metrics for one service.
pub trait UsageMetricsSource {
    async fn snapshot(&self, service: ServiceId, now_unix: i64) -> PortResult<CostSnapshot>;
}

/// Persistent store of past snapshots, used by the dashboard to show
/// trend. Implementations typically write to D1 `cost_snapshots` and
/// read back the last N rows for a given service.
pub trait CostSnapshotRepository {
    /// Append a snapshot. Implementations deduplicate by the
    /// `taken_at / 3600` bucket - calling this more than once per hour
    /// for the same service MUST be idempotent.
    async fn put(&self, snapshot: &CostSnapshot) -> PortResult<()>;

    /// Return the most recent snapshot for this service, OR `None` if
    /// none has been recorded.
    async fn latest(&self, service: ServiceId) -> PortResult<Option<CostSnapshot>>;

    /// Return up to `limit` most recent snapshots for this service,
    /// newest first.
    async fn recent(&self, service: ServiceId, limit: u32) -> PortResult<Vec<CostSnapshot>>;
}

// -------------------------------------------------------------------------
// Bucket safety
// -------------------------------------------------------------------------

pub trait BucketSafetyRepository {
    async fn list(&self) -> PortResult<Vec<BucketSafetyState>>;

    async fn get(&self, bucket: &str) -> PortResult<Option<BucketSafetyState>>;

    /// Stamp `last_verified_at` + `last_verified_by` without changing
    /// the attested booleans. Called by the Security / Operations /
    /// Super re-verify button.
    async fn verify(
        &self,
        bucket:    &str,
        now_unix:  i64,
        verifier:  &str,
    ) -> PortResult<BucketSafetyState>;

    /// Atomic write of a new attested state. `updated_at` is bumped,
    /// `last_verified_at` is bumped to `now_unix`, `last_verified_by`
    /// is set. Returns the before + after states so the caller can
    /// render a before/after confirmation.
    async fn apply_change(
        &self,
        change:    &BucketSafetyChange,
        now_unix:  i64,
        verifier:  &str,
    ) -> PortResult<(BucketSafetyState, BucketSafetyState)>;
}

// -------------------------------------------------------------------------
// Thresholds
// -------------------------------------------------------------------------

pub trait ThresholdRepository {
    async fn list(&self) -> PortResult<Vec<Threshold>>;

    async fn get(&self, name: &str) -> PortResult<Option<Threshold>>;

    async fn update(
        &self,
        name:       &str,
        new_value:  i64,
        now_unix:   i64,
    ) -> PortResult<Threshold>;
}

// -------------------------------------------------------------------------
// Audit query
// -------------------------------------------------------------------------

/// Read-side of the audit log, used by the Audit Log page (§4.4) and
/// the Overview page's "recent events" strip.
///
/// The audit WRITE side is `crate::audit::*` in the worker crate - the
/// existing R2 NDJSON sink. This trait does not write; it only reads.
pub trait AuditQuerySource {
    async fn search(&self, q: &AuditQuery) -> PortResult<Vec<AdminAuditEntry>>;
}

// -------------------------------------------------------------------------
// Admin token management (Super only)
// -------------------------------------------------------------------------

/// Storage for admin principals themselves. Used by the
/// /admin/tokens surface.
pub trait AdminTokenRepository {
    async fn list(&self) -> PortResult<Vec<AdminPrincipal>>;

    /// Create a new admin token. `token_hash` is SHA-256 of the plaintext
    /// the caller minted; the plaintext itself is never stored.
    async fn create(
        &self,
        token_hash: &str,
        role:       Role,
        name:       Option<&str>,
        now_unix:   i64,
    ) -> PortResult<AdminPrincipal>;

    /// Soft-disable: row stays, `disabled_at` is stamped.
    async fn disable(&self, id: &str, now_unix: i64) -> PortResult<()>;

    /// Create a user-bound admin token. Same as `create` but stamps
    /// the row with a `user_id` linking to a row in `users`.
    /// Resulting `AdminPrincipal` has `user_id == Some(user_id)`,
    /// which `is_system_admin()` reads as "tenant-admin, not
    /// system-admin" per ADR-002.
    ///
    /// Added in v0.13.0 alongside the tenant-scoped admin surface.
    /// The token-mint *flow* (who can mint, what audit trail it
    /// emits, what UI exposes the operation) is not part of this
    /// method — adapters just persist what they're told. The
    /// caller (a route handler in the worker, or a test) is
    /// responsible for authorization on the mint operation.
    ///
    /// `token_hash` is SHA-256 of the plaintext the caller minted;
    /// the plaintext itself is never stored.
    async fn create_user_bound(
        &self,
        token_hash: &str,
        role:       Role,
        name:       Option<&str>,
        user_id:    &str,
        now_unix:   i64,
    ) -> PortResult<AdminPrincipal>;
}

// -------------------------------------------------------------------------
// Helper: uniform auth-failure response for the worker layer
// -------------------------------------------------------------------------

/// What the worker layer should do when a principal lookup fails.
/// Keeping this as a type rather than a stringly result makes the
/// route code obvious.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    /// Bearer header missing or malformed.
    MissingBearer,
    /// Bearer present but no match in `admin_tokens` and no match for
    /// `ADMIN_API_KEY`.
    UnknownToken,
    /// Token matched a row with `disabled_at IS NOT NULL`.
    DisabledToken,
    /// Bearer present, matched a principal, but the principal's role is
    /// not allowed for the requested action.
    InsufficientRole,
}

impl AuthFailure {
    /// Human-safe message. The admin UI may display this; nothing
    /// sensitive is revealed.
    pub fn message(self) -> &'static str {
        match self {
            AuthFailure::MissingBearer    => "missing bearer token",
            AuthFailure::UnknownToken     => "unknown admin token",
            AuthFailure::DisabledToken    => "admin token is disabled",
            AuthFailure::InsufficientRole => "role not permitted",
        }
    }
}

impl From<PortError> for AuthFailure {
    /// Convenience: most adapters return `NotFound` for unknown/disabled
    /// tokens; map to `UnknownToken` by default. Adapters that can
    /// distinguish disabled from unknown return `PreconditionFailed`,
    /// which we treat as `DisabledToken`.
    fn from(e: PortError) -> Self {
        match e {
            PortError::NotFound              => AuthFailure::UnknownToken,
            PortError::PreconditionFailed(_) => AuthFailure::DisabledToken,
            _                                => AuthFailure::UnknownToken,
        }
    }
}
