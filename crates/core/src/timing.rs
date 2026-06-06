//! TTL and timing constants for cesauth (RFC 103).
//!
//! All time-to-live values live here so operators can audit expiry
//! policy in one place. Each constant documents:
//!   - **Surface**: what user-visible behaviour it controls
//!   - **Rationale**: why this value
//!   - **Sensitivity**: whether changing it is a security decision
//!
//! Units are always seconds (`i64` for compatibility with
//! `OffsetDateTime::unix_timestamp()` arithmetic; values are
//! always non-negative).

// ─── OIDC token lifetimes ─────────────────────────────────────────────────

/// ID token (OIDC) validity window.
///
/// Surface: relying parties check `exp` on the ID token to decide
/// whether to accept it. RFC 103 replaces two independent `3600`
/// literals in `oidc/id_token.rs` and `service/token.rs`.
/// Sensitivity: low — clients must already handle expiry gracefully.
pub const ID_TOKEN_TTL_SECS: i64 = 3600;

// ─── Magic-link verification ──────────────────────────────────────────────

/// How long a magic-link one-time token remains valid after issue.
///
/// Surface: end-user who received the email has this window to click.
/// Rationale: 10 minutes balances deliverability variance against replay
/// window if the message is intercepted. ADR-005.
/// Sensitivity: high — shorter is more secure.
pub const MAGIC_LINK_VERIFY_WINDOW_SECS: i64 = 600;

// ─── Invitation tokens ────────────────────────────────────────────────────

/// Default expiry for tenant member invitation tokens.
///
/// Surface: tenant admin sends an invite; the invitee must accept
/// within this window. RFC 046.
/// Rationale: 72 h covers weekends and timezone-delayed reads.
pub const INVITATION_TTL_SECS: i64 = 72 * 3600;

// ─── TOTP flow ────────────────────────────────────────────────────────────

/// Post-auth TOTP gate cookie lifetime.
///
/// Surface: after a successful primary auth, the user has this window
/// to complete the TOTP second factor. The gate cookie is the signal.
/// Sensitivity: high — longer windows expand the social-engineering
/// blast radius for stolen primary credentials.
pub const TOTP_GATE_TTL_SECS: i64 = 300;

/// TOTP enrollment flow context lifetime.
///
/// Surface: user initiates `/me/security/totp/enroll`; the enrollment
/// context (shared secret + challenge handle) survives for this long.
/// Rationale: 15 min is enough to scan the QR code and enter the
/// first code; short enough to limit abandoned-enrollment clutter.
pub const TOTP_ENROLL_TTL_SECS: i64 = 900;

// ─── Anonymous trial ──────────────────────────────────────────────────────

/// Anonymous trial account access token validity.
///
/// Surface: anonymous-trial UX — the session a guest user sees in
/// their browser. ADR-004.
/// Rationale: 24 h = one day of continuous trial exploration.
/// Sensitivity: low (anonymous accounts cannot access protected data).
pub const ANONYMOUS_TOKEN_TTL_SECS: i64 = 86_400;

// ─── Login flow ───────────────────────────────────────────────────────────

/// "Next URL" redirect cookie lifetime across a login attempt.
///
/// Surface: when an unauthenticated user hits a protected page, the
/// original URL is stashed in a cookie. After successful login they
/// are redirected there. This TTL caps how long the stash survives.
pub const LOGIN_NEXT_TTL_SECS: i64 = 300;

// ─── Admin preview ────────────────────────────────────────────────────────

/// Config-preview token validity.
///
/// Surface: an admin generates a preview token to share a proposed
/// config change for review. The token is valid for this window.
/// Rationale: 10 min is enough for a second pair of eyes to confirm;
/// short enough that forgotten tokens don't linger.
pub const PREVIEW_TOKEN_TTL_SECS: i64 = 600;

// ─── Operational ─────────────────────────────────────────────────────────

/// Cron pass status KV record TTL.
///
/// Surface: the `/admin/console/operations` page reads KV records
/// written by each cron pass. If a record is older than this, the
/// pass is shown as "no recent run". RFC 090.
pub const CRON_STATUS_KV_TTL_SECS: i64 = 8 * 24 * 3600;
