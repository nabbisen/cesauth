//! Invitation token system — RFC 043.
//!
//! Enables tenant admins to invite users by email.
//! The invited user completes registration independently.
//!
//! ## States
//!
//! ```text
//!               issue_invitation()
//!                      │
//!                  [pending]
//!                 /         \
//! verify_invitation()      revoke_invitation()
//!         │                        │
//!    [accepted]               [revoked]
//! ```
//!
//! Expired invitations are not a separate persisted state; they are
//! pending rows where `now > expires_at`.  The service layer rejects
//! them at `verify_invitation` time.
//!
//! ## Default TTL
//!
//! 72 hours.  Configurable via the `grace_secs` parameter to
//! `issue_invitation`.  Short enough to reduce abandoned-invite
//! accumulation; long enough to survive weekend gaps.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, CoreResult};
use crate::ports::{PortError, PortResult};
use crate::types::UnixSeconds;

// ---------------------------------------------------------------------------
// Default TTL
// ---------------------------------------------------------------------------

/// Default invitation TTL: 72 hours.
pub const DEFAULT_INVITE_TTL_SECS: i64 = crate::timing::INVITATION_TTL_SECS;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// An invitation as persisted to the database.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Invitation {
    pub id:          String,
    pub tenant_id:   String,
    pub email:       String,
    pub role:        String,
    pub issued_by:   String,
    pub issued_at:   UnixSeconds,
    pub expires_at:  UnixSeconds,
    pub accepted_at: Option<UnixSeconds>,
    pub accepted_by: Option<String>,
    pub revoked_at:  Option<UnixSeconds>,
    pub revoked_by:  Option<String>,
}

impl Invitation {
    /// True when the invitation is pending and not yet expired.
    pub fn is_valid_at(&self, now: UnixSeconds) -> bool {
        self.accepted_at.is_none()
            && self.revoked_at.is_none()
            && now <= self.expires_at
    }
}

/// The outcome of `verify_invitation`.
#[derive(Debug, Clone, PartialEq)]
pub enum InvitationVerifyOutcome {
    /// The invitation is valid and the caller may proceed with registration.
    Valid(Invitation),
    /// The invitation has expired (was pending but `now > expires_at`).
    Expired,
    /// The invitation was revoked by an admin before it was accepted.
    Revoked,
    /// The invitation was already accepted (single-use).
    AlreadyAccepted,
    /// No invitation found for the given id (wrong id or email).
    NotFound,
}

// ---------------------------------------------------------------------------
// Port
// ---------------------------------------------------------------------------

/// Repository interface for invitation tokens.
pub trait InvitationRepository {
    async fn create(&self, inv: &Invitation) -> PortResult<()>;
    async fn find_by_id(&self, id: &str) -> PortResult<Option<Invitation>>;
    async fn find_pending_by_tenant_email(
        &self, tenant_id: &str, email: &str, now: UnixSeconds,
    ) -> PortResult<Option<Invitation>>;
    async fn mark_accepted(&self, id: &str, user_id: &str, now: UnixSeconds) -> PortResult<()>;
    async fn mark_revoked(&self, id: &str, revoked_by: &str, now: UnixSeconds) -> PortResult<()>;
    async fn list_pending_by_tenant(
        &self, tenant_id: &str, now: UnixSeconds,
    ) -> PortResult<Vec<Invitation>>;
}

// ---------------------------------------------------------------------------
// Service functions
// ---------------------------------------------------------------------------

/// Issue a new invitation.
///
/// Returns `Err(CoreError::Conflict)` when a pending invitation for the
/// same `(tenant_id, email)` pair already exists.  The caller should
/// surface this as "an invitation is already pending for this address".
///
/// `role` is validated as non-empty; deeper role validation is the
/// caller's responsibility (check against the tenant's allowed roles).
pub async fn issue_invitation<IR>(
    repo:       &IR,
    tenant_id:  &str,
    email:      &str,
    role:       &str,
    issued_by:  &str,
    grace_secs: i64,
    now:        UnixSeconds,
) -> CoreResult<Invitation>
where
    IR: InvitationRepository,
{
    if role.is_empty() {
        return Err(CoreError::InvalidRequest("role must not be empty"));
    }

    // One-pending-per-email guard (defence above the unique index).
    if let Ok(Some(_)) = repo.find_pending_by_tenant_email(tenant_id, email, now).await {
        return Err(CoreError::Conflict);
    }

    let inv = Invitation {
        id:          Uuid::new_v4().to_string(),
        tenant_id:   tenant_id.to_owned(),
        email:       email.to_owned(),
        role:        role.to_owned(),
        issued_by:   issued_by.to_owned(),
        issued_at:   now,
        expires_at:  now + grace_secs,
        accepted_at: None,
        accepted_by: None,
        revoked_at:  None,
        revoked_by:  None,
    };

    repo.create(&inv).await.map_err(|e| match e {
        PortError::Conflict => CoreError::Conflict,
        _                   => CoreError::Internal,
    })?;

    Ok(inv)
}

/// Verify an invitation by id and email match, then check its state.
///
/// The caller provides both `id` and `email` — binding verification
/// to the email address prevents a leaked invite link from being used
/// by anyone other than the intended recipient (the link carries both
/// `id=...&email=...` or `id=...` with the email confirmed on the
/// accept page form).
pub async fn verify_invitation<IR>(
    repo:  &IR,
    id:    &str,
    email: &str,
    now:   UnixSeconds,
) -> PortResult<InvitationVerifyOutcome>
where
    IR: InvitationRepository,
{
    let inv = match repo.find_by_id(id).await? {
        None => return Ok(InvitationVerifyOutcome::NotFound),
        Some(i) => i,
    };

    // Email must match (case-insensitive; COLLATE NOCASE in the schema
    // ensures DB-level consistency but we check here for defence-in-depth).
    if !inv.email.eq_ignore_ascii_case(email) {
        return Ok(InvitationVerifyOutcome::NotFound);
    }

    if inv.accepted_at.is_some() {
        return Ok(InvitationVerifyOutcome::AlreadyAccepted);
    }
    if inv.revoked_at.is_some() {
        return Ok(InvitationVerifyOutcome::Revoked);
    }
    if now > inv.expires_at {
        return Ok(InvitationVerifyOutcome::Expired);
    }

    Ok(InvitationVerifyOutcome::Valid(inv))
}

/// Mark an invitation as accepted.  The caller must have already called
/// `verify_invitation` and received `Valid(inv)`.
pub async fn accept_invitation<IR>(
    repo:    &IR,
    id:      &str,
    user_id: &str,
    now:     UnixSeconds,
) -> CoreResult<()>
where
    IR: InvitationRepository,
{
    repo.mark_accepted(id, user_id, now).await.map_err(|_| CoreError::Internal)
}

/// Revoke a pending invitation.  `revoked_by` should be the admin's user_id.
pub async fn revoke_invitation<IR>(
    repo:       &IR,
    id:         &str,
    revoked_by: &str,
    now:        UnixSeconds,
) -> CoreResult<()>
where
    IR: InvitationRepository,
{
    repo.mark_revoked(id, revoked_by, now).await.map_err(|_| CoreError::Internal)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    // ── Stub ──────────────────────────────────────────────────────────────

    #[derive(Default)]
    struct StubRepo(RefCell<HashMap<String, Invitation>>);

    impl InvitationRepository for StubRepo {
        async fn create(&self, inv: &Invitation) -> PortResult<()> {
            let mut m = self.0.borrow_mut();
            if m.contains_key(&inv.id) { return Err(PortError::Conflict); }
            m.insert(inv.id.clone(), inv.clone());
            Ok(())
        }
        async fn find_by_id(&self, id: &str) -> PortResult<Option<Invitation>> {
            Ok(self.0.borrow().get(id).cloned())
        }
        async fn find_pending_by_tenant_email(&self, tid: &str, email: &str, now: i64) -> PortResult<Option<Invitation>> {
            Ok(self.0.borrow().values()
                .find(|i| i.tenant_id == tid
                    && i.email.eq_ignore_ascii_case(email)
                    && i.is_valid_at(now))
                .cloned())
        }
        async fn mark_accepted(&self, id: &str, user_id: &str, now: i64) -> PortResult<()> {
            if let Some(inv) = self.0.borrow_mut().get_mut(id) {
                inv.accepted_at = Some(now);
                inv.accepted_by = Some(user_id.to_owned());
            }
            Ok(())
        }
        async fn mark_revoked(&self, id: &str, revoked_by: &str, now: i64) -> PortResult<()> {
            if let Some(inv) = self.0.borrow_mut().get_mut(id) {
                inv.revoked_at = Some(now);
                inv.revoked_by = Some(revoked_by.to_owned());
            }
            Ok(())
        }
        async fn list_pending_by_tenant(&self, tid: &str, now: i64) -> PortResult<Vec<Invitation>> {
            Ok(self.0.borrow().values()
                .filter(|i| i.tenant_id == tid && i.is_valid_at(now))
                .cloned()
                .collect())
        }
    }

    const NOW: i64 = 1_700_000_000;

    // ── issue_invitation tests ────────────────────────────────────────────

    #[tokio::test]
    async fn issue_creates_valid_invitation() {
        let repo = StubRepo::default();
        let inv = issue_invitation(&repo, "t-1", "alice@example.com", "tenant_member",
                                   "admin-1", DEFAULT_INVITE_TTL_SECS, NOW).await.unwrap();
        assert_eq!(inv.tenant_id, "t-1");
        assert_eq!(inv.email, "alice@example.com");
        assert_eq!(inv.role, "tenant_member");
        assert_eq!(inv.issued_by, "admin-1");
        assert!(inv.is_valid_at(NOW));
    }

    #[tokio::test]
    async fn issue_conflict_when_pending_exists() {
        let repo = StubRepo::default();
        issue_invitation(&repo, "t-1", "alice@example.com", "tenant_member",
                         "admin-1", DEFAULT_INVITE_TTL_SECS, NOW).await.unwrap();
        let result = issue_invitation(&repo, "t-1", "alice@example.com", "tenant_member",
                                      "admin-1", DEFAULT_INVITE_TTL_SECS, NOW).await;
        assert!(matches!(result, Err(CoreError::Conflict)),
            "duplicate pending invite must return Conflict");
    }

    #[tokio::test]
    async fn issue_allowed_after_previous_revoked() {
        let repo = StubRepo::default();
        let inv = issue_invitation(&repo, "t-1", "alice@example.com", "member",
                                   "admin", DEFAULT_INVITE_TTL_SECS, NOW).await.unwrap();
        revoke_invitation(&repo, &inv.id, "admin", NOW + 1).await.unwrap();
        // Now a new invite should succeed.
        let inv2 = issue_invitation(&repo, "t-1", "alice@example.com", "member",
                                    "admin", DEFAULT_INVITE_TTL_SECS, NOW + 2).await;
        assert!(inv2.is_ok(), "new invite allowed after revoke: {inv2:?}");
    }

    #[tokio::test]
    async fn empty_role_is_rejected() {
        let repo = StubRepo::default();
        let result = issue_invitation(&repo, "t-1", "a@example.com", "",
                                      "admin", DEFAULT_INVITE_TTL_SECS, NOW).await;
        assert!(result.is_err());
    }

    // ── verify_invitation tests ───────────────────────────────────────────

    #[tokio::test]
    async fn verify_valid_invitation() {
        let repo = StubRepo::default();
        let inv = issue_invitation(&repo, "t-1", "bob@example.com", "member",
                                   "admin", DEFAULT_INVITE_TTL_SECS, NOW).await.unwrap();
        let outcome = verify_invitation(&repo, &inv.id, "bob@example.com", NOW + 10).await.unwrap();
        assert!(matches!(outcome, InvitationVerifyOutcome::Valid(_)));
    }

    #[tokio::test]
    async fn verify_expired_invitation() {
        let repo = StubRepo::default();
        let inv = issue_invitation(&repo, "t-1", "c@example.com", "member",
                                   "admin", 60, NOW).await.unwrap(); // 60s TTL
        let outcome = verify_invitation(&repo, &inv.id, "c@example.com", NOW + 61).await.unwrap();
        assert_eq!(outcome, InvitationVerifyOutcome::Expired);
    }

    #[tokio::test]
    async fn verify_revoked_invitation() {
        let repo = StubRepo::default();
        let inv = issue_invitation(&repo, "t-1", "d@example.com", "member",
                                   "admin", DEFAULT_INVITE_TTL_SECS, NOW).await.unwrap();
        revoke_invitation(&repo, &inv.id, "admin", NOW + 1).await.unwrap();
        let outcome = verify_invitation(&repo, &inv.id, "d@example.com", NOW + 2).await.unwrap();
        assert_eq!(outcome, InvitationVerifyOutcome::Revoked);
    }

    #[tokio::test]
    async fn verify_already_accepted() {
        let repo = StubRepo::default();
        let inv = issue_invitation(&repo, "t-1", "e@example.com", "member",
                                   "admin", DEFAULT_INVITE_TTL_SECS, NOW).await.unwrap();
        accept_invitation(&repo, &inv.id, "u-new", NOW + 1).await.unwrap();
        let outcome = verify_invitation(&repo, &inv.id, "e@example.com", NOW + 2).await.unwrap();
        assert_eq!(outcome, InvitationVerifyOutcome::AlreadyAccepted);
    }

    #[tokio::test]
    async fn verify_email_case_insensitive() {
        let repo = StubRepo::default();
        let inv = issue_invitation(&repo, "t-1", "Alice@Example.com", "member",
                                   "admin", DEFAULT_INVITE_TTL_SECS, NOW).await.unwrap();
        // Lowercase should still match.
        let outcome = verify_invitation(&repo, &inv.id, "alice@example.com", NOW + 1).await.unwrap();
        assert!(matches!(outcome, InvitationVerifyOutcome::Valid(_)),
            "email check must be case-insensitive");
    }

    #[tokio::test]
    async fn verify_wrong_email_returns_not_found() {
        let repo = StubRepo::default();
        let inv = issue_invitation(&repo, "t-1", "alice@example.com", "member",
                                   "admin", DEFAULT_INVITE_TTL_SECS, NOW).await.unwrap();
        let outcome = verify_invitation(&repo, &inv.id, "mallory@example.com", NOW + 1).await.unwrap();
        assert_eq!(outcome, InvitationVerifyOutcome::NotFound,
            "wrong email must return NotFound (not reveal the invite exists)");
    }

    #[tokio::test]
    async fn invitation_is_valid_at_boundary() {
        let inv = Invitation {
            id: "i".into(), tenant_id: "t".into(), email: "x@y.com".into(),
            role: "r".into(), issued_by: "a".into(),
            issued_at: NOW, expires_at: NOW + 100,
            accepted_at: None, accepted_by: None, revoked_at: None, revoked_by: None,
        };
        assert!(inv.is_valid_at(NOW + 100), "valid exactly at boundary");
        assert!(!inv.is_valid_at(NOW + 101), "invalid one second past boundary");
    }
}
