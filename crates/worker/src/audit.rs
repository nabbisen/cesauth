//! Audit logging to R2 (spec §6.5).
//!
//! Design choices:
//!
//! * **NDJSON, one line per event.** Cheap to append, cheap to grep.
//! * **Date-partitioned keys.** `audit/YYYY/MM/DD/<uuid>.ndjson` lets us
//!   set R2 lifecycle rules per day without inspecting file bodies.
//! * **No token material ever.** Spec §10.4: we log identifiers, not
//!   secrets. A JWT's `jti` is fine; its signature bytes are not.
//! * **Writes are best-effort.** An audit write failure must not break
//!   the authentication request that triggered it. We log a warning and
//!   continue. This is a deliberate trade-off: availability of auth
//!   over completeness of audit, and the calling resource server can
//!   always reconstruct activity from its own logs if needed.

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

    pub fn with_subject(mut self, s: &'a str) -> Self   { self.subject   = Some(s); self }
    pub fn with_client(mut self, c: &'a str) -> Self    { self.client_id = Some(c); self }
    pub fn with_ip(mut self, ip: &'a str) -> Self       { self.ip        = Some(ip); self }
    pub fn with_user_agent(mut self, ua: &'a str) -> Self { self.user_agent = Some(ua); self }
    pub fn with_reason(mut self, r: &'a str) -> Self    { self.reason    = Some(r); self }
}

/// Append-write an event to the `AUDIT` bucket.
///
/// The key format `audit/YYYY/MM/DD/<uuid>.ndjson` treats each event as
/// a tiny object. That is wasteful for R2 at very high volume; if the
/// deployment ever gets there, swap to a batching layer in Durable
/// Object form. For now, clarity wins.
pub async fn write(env: &Env, ev: &Event<'_>) {
    let bucket = match env.bucket("AUDIT") {
        Ok(b) => b,
        Err(_) => return,   // see module-level comment re: best-effort
    };

    let now = OffsetDateTime::now_utc();
    let key = format!(
        "audit/{y:04}/{m:02}/{d:02}/{id}.ndjson",
        y  = now.year(),
        m  = u8::from(now.month()),
        d  = now.day(),
        id = ev.id,
    );

    let body = match serde_json::to_vec(ev) {
        Ok(v) => {
            let mut v = v;
            v.push(b'\n');
            v
        }
        Err(_) => return,
    };

    if let Err(_e) = bucket.put(&key, body).execute().await {
        // Can't audit the audit failure here without risking a loop.
        // Rely on Workers' platform-level logging for this signal.
    }
}

/// Convenience for writing a non-borrowed event (when the caller has
/// already built the String form). Saves a lifetime battle at call
/// sites.
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
