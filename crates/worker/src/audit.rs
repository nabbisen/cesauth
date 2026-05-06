//! Audit logging to D1 (ADR-010, v0.32.0).
//!
//! Design choices:
//!
//! * **D1 with hash chain.** v0.32.0 moved audit events from R2
//!   to a D1 table `audit_events` with a SHA-256 hash chain
//!   over the rows (ADR-010). Each row is tamper-evident: any
//!   modification of a past row invalidates every subsequent
//!   row's `chain_hash`.
//! * **No token material ever.** Spec §10.4: we log identifiers,
//!   not secrets. A JWT's `jti` is fine; its signature bytes are
//!   not.
//! * **Writes are best-effort at the worker layer.** An audit
//!   write failure must not break the authentication request
//!   that triggered it. We log a warning and continue. This is
//!   a deliberate trade-off: availability of auth over
//!   completeness of audit. The chain itself doesn't tolerate
//!   gaps in seq, so a "best-effort" failure here means the
//!   event is dropped entirely (not written to a partial chain).
//!   The next event continues the chain from the last-good
//!   tail; the missing event simply isn't there to verify.
//!
//! ## Migration from v0.31.x R2
//!
//! v0.31.x and earlier wrote audit events as one-NDJSON-object-
//! per-event in the R2 `AUDIT` bucket. v0.32.0 removes the R2
//! binding entirely. Operators with historical R2 audit data
//! retain the bucket on their Cloudflare account but cesauth no
//! longer reads or writes it. The `cesauth_core::audit::chain`
//! module documents the chain semantics and the genesis row
//! that anchors the v0.32.0+ chain.

use cesauth_cf::ports::audit::CloudflareAuditEventRepository;
use cesauth_core::audit::chain::compute_payload_hash;
use cesauth_core::ports::audit::{AuditEventRepository, NewAuditEvent};
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Env, Result};

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    // Authentication attempts
    AuthSucceeded,
    AuthFailed,
    // Admin operations
    AdminUserCreated,
    AdminSessionRevoked,
    AdminClientCreated,
    // Admin console (v0.3.0)
    AdminLoginFailed,
    AdminConsoleViewed,
    AdminBucketSafetyVerified,
    AdminBucketSafetyChanged,
    AdminThresholdUpdated,
    // Admin token management (v0.4.0)
    AdminTokenCreated,
    AdminTokenDisabled,
    // tenancy-service API (v0.7.0)
    TenantCreated,
    TenantUpdated,
    TenantStatusChanged,
    OrganizationCreated,
    OrganizationUpdated,
    OrganizationStatusChanged,
    GroupCreated,
    GroupDeleted,
    MembershipAdded,
    MembershipRemoved,
    RoleGranted,
    RoleRevoked,
    SubscriptionPlanChanged,
    SubscriptionStatusChanged,
    // Token lifecycle
    TokenIssued,
    TokenRefreshed,
    TokenRefreshRejected,
    /// **v0.34.0** — Refresh-token reuse detected (RFC 9700
    /// §4.14.2 / OAuth 2.0 Security BCP §4.13). Distinct from
    /// `TokenRefreshRejected` because reuse detection is a
    /// security-critical signal that operators monitor for
    /// compromise. The payload includes `family_id`,
    /// `presented_jti`, `was_retired` (true if the presented
    /// jti was a real-but-rotated-out token, false if wholly
    /// unknown), and the family's `client_id`. The HTTP-visible
    /// response is the same `invalid_grant` as legitimate
    /// revocation; only audit + Workers logs see the
    /// distinction (spec §10.3 internal/external separation).
    RefreshTokenReuseDetected,
    RevocationRequested,
    // WebAuthn
    WebauthnRegistered,
    WebauthnVerified,
    WebauthnFailed,
    // Magic Link
    MagicLinkIssued,
    MagicLinkVerified,
    MagicLinkFailed,
    // Sessions
    SessionStarted,
    SessionRevoked,
    // Anonymous trial (v0.16.0, ADR-004)
    AnonymousCreated,
    AnonymousExpired,
    AnonymousPromoted,
}

impl EventKind {
    /// Snake-case discriminant string used as the `kind` value
    /// in `audit_events`. Matches the `serde(rename_all =
    /// "snake_case")` shape so old R2 NDJSON and new D1 rows
    /// agree on the spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthSucceeded                => "auth_succeeded",
            Self::AuthFailed                   => "auth_failed",
            Self::AdminUserCreated             => "admin_user_created",
            Self::AdminSessionRevoked          => "admin_session_revoked",
            Self::AdminClientCreated           => "admin_client_created",
            Self::AdminLoginFailed             => "admin_login_failed",
            Self::AdminConsoleViewed           => "admin_console_viewed",
            Self::AdminBucketSafetyVerified    => "admin_bucket_safety_verified",
            Self::AdminBucketSafetyChanged     => "admin_bucket_safety_changed",
            Self::AdminThresholdUpdated        => "admin_threshold_updated",
            Self::AdminTokenCreated            => "admin_token_created",
            Self::AdminTokenDisabled           => "admin_token_disabled",
            Self::TenantCreated                => "tenant_created",
            Self::TenantUpdated                => "tenant_updated",
            Self::TenantStatusChanged          => "tenant_status_changed",
            Self::OrganizationCreated          => "organization_created",
            Self::OrganizationUpdated          => "organization_updated",
            Self::OrganizationStatusChanged    => "organization_status_changed",
            Self::GroupCreated                 => "group_created",
            Self::GroupDeleted                 => "group_deleted",
            Self::MembershipAdded              => "membership_added",
            Self::MembershipRemoved            => "membership_removed",
            Self::RoleGranted                  => "role_granted",
            Self::RoleRevoked                  => "role_revoked",
            Self::SubscriptionPlanChanged      => "subscription_plan_changed",
            Self::SubscriptionStatusChanged    => "subscription_status_changed",
            Self::TokenIssued                  => "token_issued",
            Self::TokenRefreshed               => "token_refreshed",
            Self::TokenRefreshRejected         => "token_refresh_rejected",
            Self::RefreshTokenReuseDetected    => "refresh_token_reuse_detected",
            Self::RevocationRequested          => "revocation_requested",
            Self::WebauthnRegistered           => "webauthn_registered",
            Self::WebauthnVerified             => "webauthn_verified",
            Self::WebauthnFailed               => "webauthn_failed",
            Self::MagicLinkIssued              => "magic_link_issued",
            Self::MagicLinkVerified            => "magic_link_verified",
            Self::MagicLinkFailed              => "magic_link_failed",
            Self::SessionStarted               => "session_started",
            Self::SessionRevoked               => "session_revoked",
            Self::AnonymousCreated             => "anonymous_created",
            Self::AnonymousExpired             => "anonymous_expired",
            Self::AnonymousPromoted            => "anonymous_promoted",
        }
    }
}

/// Borrowed event view used at call sites. Serializes to the
/// canonical JSON `payload` stored in the `audit_events` table.
/// The chain `payload_hash` covers the exact bytes produced by
/// `serde_json::to_vec(&Event)`.
#[derive(Debug, Clone, Serialize)]
pub struct Event<'a> {
    pub ts:         i64,
    pub id:         String,
    pub kind:       EventKind,
    /// User or subject identifier if known. Do NOT put PII in here
    /// (no raw emails); a user id / auth handle is fine.
    pub subject:    Option<&'a str>,
    pub client_id:  Option<&'a str>,
    pub ip:         Option<&'a str>,
    pub user_agent: Option<&'a str>,
    /// Machine-readable reason code. For successes, this is usually
    /// omitted; for failures it's a short slug like "pkce_mismatch".
    pub reason:     Option<&'a str>,
}

impl<'a> Event<'a> {
    pub fn new(kind: EventKind) -> Self {
        Self {
            ts:         OffsetDateTime::now_utc().unix_timestamp(),
            id:         Uuid::new_v4().to_string(),
            kind,
            subject:    None,
            client_id:  None,
            ip:         None,
            user_agent: None,
            reason:     None,
        }
    }

    pub fn with_subject(mut self, s: &'a str) -> Self      { self.subject    = Some(s);  self }
    pub fn with_client(mut self, c: &'a str) -> Self       { self.client_id  = Some(c);  self }
    pub fn with_ip(mut self, ip: &'a str) -> Self          { self.ip         = Some(ip); self }
    pub fn with_user_agent(mut self, ua: &'a str) -> Self  { self.user_agent = Some(ua); self }
    pub fn with_reason(mut self, r: &'a str) -> Self       { self.reason     = Some(r);  self }
}

/// Append an event to the chain. Best-effort: a write failure
/// drops the event silently rather than failing the request.
///
/// The chain semantics live in the repository: `append` reads the
/// tail, computes the new row's `chain_hash`, and INSERTs.
/// Concurrent writers are handled by the repository's small
/// retry loop (see ADR-010 §"Concurrency").
pub async fn write(env: &Env, ev: &Event<'_>) {
    let repo = CloudflareAuditEventRepository::new(env);

    // Serialize once. The exact bytes here are what `payload_hash`
    // covers — any later re-encoding (pretty-print, whitespace
    // normalization) would invalidate the chain.
    let payload_bytes = match serde_json::to_vec(ev) {
        Ok(v)  => v,
        Err(_) => return,
    };
    let payload = match std::str::from_utf8(&payload_bytes) {
        Ok(s)  => s,
        Err(_) => return,  // serde_json never produces non-UTF-8, but defend
    };
    let payload_hash = compute_payload_hash(&payload_bytes);

    let new_event = NewAuditEvent {
        id:           &ev.id,
        ts:           ev.ts,
        kind:         ev.kind.as_str(),
        subject:      ev.subject,
        client_id:    ev.client_id,
        ip:           ev.ip,
        user_agent:   ev.user_agent,
        reason:       ev.reason,
        payload,
        payload_hash: &payload_hash,
        created_at:   ev.ts,
    };

    if let Err(_e) = repo.append(&new_event).await {
        // Can't audit the audit failure here without risking a
        // loop. Rely on Workers' platform-level logging for this
        // signal.
    }
}

/// Convenience for writing a non-borrowed event (when the caller
/// has already built the String form). Saves a lifetime battle
/// at call sites.
pub async fn write_owned(
    env:     &Env,
    kind:    EventKind,
    subject: Option<String>,
    client:  Option<String>,
    reason:  Option<String>,
) -> Result<()> {
    let ev = Event {
        ts:         OffsetDateTime::now_utc().unix_timestamp(),
        id:         Uuid::new_v4().to_string(),
        kind,
        subject:    subject.as_deref(),
        client_id:  client.as_deref(),
        ip:         None,
        user_agent: None,
        reason:     reason.as_deref(),
    };
    write(env, &ev).await;
    Ok(())
}
