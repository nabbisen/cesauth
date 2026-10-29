//! Tenancy service layer.
//!
//! Each function here takes the ports it needs, composes them into
//! one business operation, and returns a typed result. The service
//! layer is where transaction-shape decisions live: "create a tenant
//! and its owner membership atomically" is one call here, even though
//! the two rows land in two tables.
//!
//! The layer is port-generic, not Cloudflare-specific — it is
//! unit-testable against the in-memory adapters.

use crate::error::CoreError;
use crate::ports::repo::UserRepository;
use crate::ports::{PortError, PortResult};
use crate::types::UnixSeconds;
use uuid::Uuid;

use super::ports::{
    MembershipRepository, NewGroupInput, NewTenantInput, OrganizationRepository,
    GroupRepository, TenantRepository,
};
use super::types::{
    DEFAULT_TENANT_ID, Group, GroupMembership, GroupStatus, Organization,
    OrganizationMembership, OrganizationRole, OrganizationStatus, Tenant,
    TenantMembership, TenantStatus,
};

/// Outcome of assigning a newly-created tenant's owner to that tenant's
/// `users.tenant_id` — the home-tenant column `resolve_tenant_admin`
/// gates `/admin/t/:slug/*` on (RFC 158).
///
/// **One-to-one with [`crate::deletion::ScrubOutcome`]**, for the same
/// reason: a secondary write after a primary one that already
/// succeeded must not collapse into a bare `Err`, because the caller
/// (`create_tenant`) must not report "creation failed" once the tenant
/// and membership rows already exist.
#[must_use = "a Failed owner-home outcome must be logged and recorded in \
              the tenant_created audit detail (RFC 158), not discarded"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerHomeOutcome {
    /// The owner's home tenant was the default, and is now this one.
    Assigned,
    /// The owner already had a different, non-default home tenant.
    /// **Not a failure** — RFC 158 §5.4: overwriting it would revoke
    /// their admin access to the tenant they already administer, which
    /// this RFC exists to fix, not inflict on someone else. Left
    /// untouched.
    KeptExistingHome,
    /// The owner's home could not be assigned. Covers three cases the
    /// caller cannot tell apart from the inside, and must not pretend
    /// to: the owner row could not be found (a storage inconsistency —
    /// `add_tenant_membership` already succeeded against the same id,
    /// so this is not "no such user"), the read failed, or the
    /// `assign_tenant` write itself failed. **Must be surfaced loudly**
    /// — logged, and recorded in the `tenant_created` audit event's
    /// detail — never silently treated as equivalent to
    /// [`Self::KeptExistingHome`].
    Failed,
}

impl OwnerHomeOutcome {
    /// Snake-case form for log lines and audit detail strings.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Assigned         => "assigned",
            Self::KeptExistingHome => "kept_existing_home",
            Self::Failed           => "failed",
        }
    }
}

/// Decide what happens to the owner's home tenant when a new tenant is
/// created for them, and do it. Reads the owner's current `tenant_id`
/// and, only if it is still the default, writes the new one via
/// [`UserRepository::assign_tenant`].
///
/// **Testable without creating a tenant** — seed a `UserRepository`
/// double with zero or one user (home tenant default, or not) and call
/// this directly; no `TenantRepository`/`MembershipRepository` needed.
/// **Never returns `Err`** — every failure this call can hit is already
/// an [`OwnerHomeOutcome`] variant, for the same reason
/// [`crate::deletion::execute_deletion`]'s scrub outcome is a value, not
/// a propagated error.
async fn decide_owner_home<U: UserRepository>(
    users:         &U,
    owner_user_id: &str,
    new_tenant_id: &str,
    now_unix:      UnixSeconds,
) -> OwnerHomeOutcome {
    let owner = match users.find_by_id(owner_user_id).await {
        Ok(Some(u)) => u,
        Ok(None) | Err(_) => return OwnerHomeOutcome::Failed,
    };
    if owner.tenant_id != DEFAULT_TENANT_ID {
        return OwnerHomeOutcome::KeptExistingHome;
    }
    match users.assign_tenant(owner_user_id, new_tenant_id, now_unix).await {
        Ok(())  => OwnerHomeOutcome::Assigned,
        Err(_)  => OwnerHomeOutcome::Failed,
    }
}

/// Outcome of [`create_tenant`]. A struct (not a bare `Tenant`) so a
/// future field can join `owner_home` without another signature
/// change, and so `let _ = create_tenant(...)` discards a named thing
/// rather than an anonymous one.
#[must_use = "a Failed owner-home outcome must be logged and recorded in \
              the tenant_created audit detail (RFC 158), not discarded"]
#[derive(Debug, Clone)]
pub struct CreateTenantOutcome {
    pub tenant:     Tenant,
    pub owner_home: OwnerHomeOutcome,
}

/// Create a tenant plus its owner membership and home-tenant
/// assignment as one operation.
///
/// The new tenant is written first; if that fails, nothing else is.
/// If the tenant-write succeeds but the membership write fails, the
/// tenant row is left in place (the caller can retry the membership).
/// This mirrors how D1 batch semantics behave: no multi-row
/// transactionality, idempotent retry instead.
///
/// **RFC 158.** The owner's `users.tenant_id` is decided and, if
/// appropriate, assigned **last** — after the tenant and the
/// membership both succeed — via [`decide_owner_home`]. Before this,
/// no path ever moved a tenant's owner's home tenant off the default,
/// so `/admin/t/:slug/*` — gated on exactly that column — was
/// unreachable for every tenant but one.
///
/// **The owner is read after both inserts, not before.** A pre-flight
/// read would also fix the pre-existing "a bad owner id leaves an
/// orphan tenant row" defect (`add_tenant_membership`'s foreign-key
/// failure happens after `tenants.create()` already succeeded) — but
/// that defect is not this RFC's, and fixing it here would be a second,
/// un-reviewed design choice riding along with this one. Left exactly
/// as it behaves today.
pub async fn create_tenant<T, M, U>(
    tenants:     &T,
    memberships: &M,
    users:       &U,
    input:       &NewTenantInput<'_>,
    now_unix:    UnixSeconds,
) -> PortResult<CreateTenantOutcome>
where
    T: TenantRepository,
    M: MembershipRepository,
    U: UserRepository,
{
    validate_slug(input.slug)?;
    let tenant = Tenant {
        id:           Uuid::new_v4().to_string(),
        slug:         input.slug.to_owned(),
        display_name: input.display_name.to_owned(),
        status:       TenantStatus::Active,
        created_at:   now_unix,
        updated_at:   now_unix,
    };
    tenants.create(&tenant).await?;

    memberships.add_tenant_membership(&TenantMembership {
        tenant_id: tenant.id.clone(),
        user_id:   input.owner_user_id.to_owned(),
        role:      input.owner_role,
        joined_at: now_unix,
    }).await?;

    let owner_home = decide_owner_home(users, input.owner_user_id, &tenant.id, now_unix).await;

    Ok(CreateTenantOutcome { tenant, owner_home })
}

/// Add a user to an existing tenant with the given membership role.
///
/// Returns `Conflict` if the user is already a member of the tenant.
pub async fn add_user_to_tenant<M: MembershipRepository>(
    memberships: &M,
    m:           &TenantMembership,
) -> PortResult<()> {
    memberships.add_tenant_membership(m).await
}

/// Create an organization inside a tenant. The tenant must exist and
/// be active; we check here rather than trusting the caller, because
/// a dangling `tenant_id` in an org row is hard to diagnose later.
pub async fn create_organization<T, O>(
    tenants: &T,
    orgs:    &O,
    tenant_id:    &str,
    slug:         &str,
    display_name: &str,
    now_unix:     UnixSeconds,
) -> PortResult<Organization>
where
    T: TenantRepository,
    O: OrganizationRepository,
{
    validate_slug(slug)?;
    match tenants.get(tenant_id).await? {
        Some(t) if matches!(t.status, TenantStatus::Active)  => {}
        Some(_) => return Err(PortError::Conflict),  // suspended/deleted/pending
        None    => return Err(PortError::NotFound),
    }

    let org = Organization {
        id:                    Uuid::new_v4().to_string(),
        tenant_id:             tenant_id.to_owned(),
        slug:                  slug.to_owned(),
        display_name:          display_name.to_owned(),
        status:                OrganizationStatus::Active,
        parent_organization_id: None,
        created_at:            now_unix,
        updated_at:            now_unix,
    };
    orgs.create(&org).await?;
    Ok(org)
}

/// Add a user to an organization.
///
/// The caller is expected to have already confirmed the user is a
/// tenant member; the service does NOT enforce that here because
/// "must be tenant member first" is an authorization decision, not a
/// data-integrity one.
pub async fn add_user_to_organization<M: MembershipRepository>(
    memberships: &M,
    org_id:      &str,
    user_id:     &str,
    role:        OrganizationRole,
    now_unix:    UnixSeconds,
) -> PortResult<()> {
    memberships.add_organization_membership(&OrganizationMembership {
        organization_id: org_id.to_owned(),
        user_id:         user_id.to_owned(),
        role,
        joined_at:       now_unix,
    }).await
}

/// Create a group under a tenant or organization.
pub async fn create_group<G>(
    groups: &G,
    input:  &NewGroupInput<'_>,
    now_unix: UnixSeconds,
) -> PortResult<Group>
where
    G: GroupRepository,
{
    validate_slug(input.slug)?;
    validate_group_tenant_boundary(input)?;
    let group = Group {
        id:                Uuid::new_v4().to_string(),
        tenant_id:         input.tenant_id.to_owned(),
        parent:            input.parent.clone(),
        slug:              input.slug.to_owned(),
        display_name:      input.display_name.to_owned(),
        status:            GroupStatus::Active,
        parent_group_id:   None,
        created_at:        now_unix,
        updated_at:        now_unix,
    };
    groups.create(&group).await?;
    Ok(group)
}

/// Validate that a [`NewGroupInput`] does not reference parents from a
/// different tenant (RFC 023, defense-in-depth layer above the schema FK).
///
/// Returns `Err(PortError::PreconditionFailed)` when the resolved
/// `organization_tenant_id` does not match `input.tenant_id`.
/// Returns `Ok(())` when the field is absent (the schema FK is the
/// ultimate guard in that case).
///
/// A typed `CoreError::CrossTenantReference` is available for worker
/// handlers that need to emit a structured audit event or API error body.
pub fn validate_group_tenant_boundary(input: &NewGroupInput<'_>) -> PortResult<()> {
    if let Some(org_tid) = input.organization_tenant_id {
        if org_tid != input.tenant_id {
            return Err(PortError::PreconditionFailed(
                "organization belongs to a different tenant",
            ));
        }
    }
    Ok(())
}

/// Produce a [`CoreError::CrossTenantReference`] for the given input when
/// the organization tenant does not match.  Used by worker handlers to emit
/// the structured audit event and a 422 response body.
pub fn cross_tenant_error_for_group(input: &NewGroupInput<'_>) -> Option<CoreError> {
    let org_tid = input.organization_tenant_id?;
    if org_tid == input.tenant_id {
        return None;
    }
    Some(CoreError::CrossTenantReference {
        kind:               "organization",
        expected_tenant_id: input.tenant_id.to_owned(),
        actual_tenant_id:   org_tid.to_owned(),
    })
}

/// Add a user to a group.
pub async fn add_user_to_group<M: MembershipRepository>(
    memberships: &M,
    group_id:    &str,
    user_id:     &str,
    now_unix:    UnixSeconds,
) -> PortResult<()> {
    memberships.add_group_membership(&GroupMembership {
        group_id:  group_id.to_owned(),
        user_id:   user_id.to_owned(),
        joined_at: now_unix,
    }).await
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Slugs are lowercase ASCII, hyphen-separated, 1-63 chars. Reject
/// early so bad data never reaches D1's CHECK constraint and surfaces
/// as a generic "constraint failed".
fn validate_slug(s: &str) -> PortResult<()> {
    if s.is_empty() || s.len() > 63 {
        return Err(PortError::PreconditionFailed("slug length must be 1..=63"));
    }
    if !s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        return Err(PortError::PreconditionFailed("slug must be [a-z0-9-]"));
    }
    // No leading/trailing hyphen.
    if s.starts_with('-') || s.ends_with('-') {
        return Err(PortError::PreconditionFailed("slug must not start/end with '-'"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RFC 056 — Soft-delete service functions (SaaS guide §9.4)
// ---------------------------------------------------------------------------
// Soft-delete transitions set status to `Deleted` using the existing
// `set_status` port methods. The row is retained for audit trail and
// potential restore; physical deletion requires a separate GDPR flow
// (RFC 044 handles users; org/group physical deletion is operator-only).
// ---------------------------------------------------------------------------

/// Soft-delete a tenant.  Sets status to `TenantStatus::Deleted`.
///
/// Returns `Err(PortError::NotFound)` if the tenant does not exist.
/// A tenant that is already deleted is a no-op (idempotent).
pub async fn soft_delete_tenant<T: TenantRepository>(
    tenants:  &T,
    id:       &str,
    now_unix: UnixSeconds,
) -> PortResult<()> {
    tenants.set_status(id, TenantStatus::Deleted, now_unix).await
}

/// Soft-delete an organization.  Sets status to `OrganizationStatus::Deleted`.
pub async fn soft_delete_organization<O: OrganizationRepository>(
    orgs:     &O,
    id:       &str,
    now_unix: UnixSeconds,
) -> PortResult<()> {
    orgs.set_status(id, OrganizationStatus::Deleted, now_unix).await
}

/// Soft-delete a group.  Calls `GroupRepository::delete` which sets
/// `status = 'deleted'` and records `deleted_at` in the D1 row.
pub async fn soft_delete_group<G: GroupRepository>(
    groups:   &G,
    id:       &str,
    now_unix: UnixSeconds,
) -> PortResult<()> {
    groups.delete(id, now_unix).await
}

/// Suspend a tenant (e.g. for billing non-payment or ToS violation).
/// Sets status to `TenantStatus::Suspended`.
pub async fn suspend_tenant<T: TenantRepository>(
    tenants:  &T,
    id:       &str,
    now_unix: UnixSeconds,
) -> PortResult<()> {
    tenants.set_status(id, TenantStatus::Suspended, now_unix).await
}

/// Restore a suspended or deleted tenant back to `Active`.
pub async fn restore_tenant<T: TenantRepository>(
    tenants:  &T,
    id:       &str,
    now_unix: UnixSeconds,
) -> PortResult<()> {
    tenants.set_status(id, TenantStatus::Active, now_unix).await
}



#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::GroupParent;

    fn org_input<'a>(
        tenant_id: &'a str,
        org_tenant_id: Option<&'a str>,
    ) -> NewGroupInput<'a> {
        NewGroupInput {
            tenant_id,
            parent: GroupParent::Tenant,
            slug: "test-group",
            display_name: "Test",
            organization_tenant_id: org_tenant_id,
        }
    }

    // ── validate_group_tenant_boundary ────────────────────────────────────

    #[test]
    fn boundary_passes_when_no_org_tenant() {
        let input = org_input("t-1", None);
        assert!(validate_group_tenant_boundary(&input).is_ok(),
            "no organization_tenant_id: boundary is unconstrained");
    }

    #[test]
    fn boundary_passes_when_org_tenant_matches() {
        let input = org_input("t-1", Some("t-1"));
        assert!(validate_group_tenant_boundary(&input).is_ok());
    }

    #[test]
    fn boundary_fails_when_org_tenant_differs() {
        let input = org_input("t-1", Some("t-2"));
        let result = validate_group_tenant_boundary(&input);
        assert!(result.is_err(),
            "org from different tenant must fail boundary check");
    }

    // ── cross_tenant_error_for_group ──────────────────────────────────────

    #[test]
    fn cross_tenant_error_none_when_no_org_tenant() {
        let input = org_input("t-1", None);
        assert!(cross_tenant_error_for_group(&input).is_none());
    }

    #[test]
    fn cross_tenant_error_none_when_same_tenant() {
        let input = org_input("t-1", Some("t-1"));
        assert!(cross_tenant_error_for_group(&input).is_none());
    }

    #[test]
    fn cross_tenant_error_some_when_different_tenant() {
        let input = org_input("t-1", Some("t-2"));
        let err = cross_tenant_error_for_group(&input);
        assert!(err.is_some(), "different tenants must produce an error");
        match err.unwrap() {
            CoreError::CrossTenantReference { kind, expected_tenant_id, actual_tenant_id } => {
                assert_eq!(kind, "organization");
                assert_eq!(expected_tenant_id, "t-1");
                assert_eq!(actual_tenant_id, "t-2");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    // ── validate_slug ─────────────────────────────────────────────────────

    #[test]
    fn slug_valid_examples() {
        assert!(validate_slug("my-tenant").is_ok());
        assert!(validate_slug("a").is_ok());
        assert!(validate_slug("123").is_ok());
        assert!(validate_slug(&"a".repeat(63)).is_ok());
    }

    #[test]
    fn slug_empty_is_rejected() {
        assert!(validate_slug("").is_err());
    }

    #[test]
    fn slug_too_long_is_rejected() {
        assert!(validate_slug(&"a".repeat(64)).is_err());
    }

    #[test]
    fn slug_uppercase_is_rejected() {
        assert!(validate_slug("MyTenant").is_err());
    }

    #[test]
    fn slug_spaces_are_rejected() {
        assert!(validate_slug("my tenant").is_err());
    }

    #[test]
    fn slug_special_chars_are_rejected() {
        assert!(validate_slug("my_tenant").is_err()); // underscore not allowed
        assert!(validate_slug("my.tenant").is_err()); // dot not allowed
    }

    // ── decide_owner_home ───────────────────────────────────────────────
    // RFC 158: "testable without creating a tenant" — a tiny local
    // `UserRepository` stub, no `TenantRepository`/`MembershipRepository`
    // in sight, same shape as `core::tenant_admin::tests::StubUsers`.

    use crate::ports::repo::UserRepository;
    use crate::ports::PortError;
    use crate::types::{User, UserStatus};
    use std::cell::RefCell;

    #[derive(Default)]
    struct StubUsers {
        rows: RefCell<Vec<User>>,
        fail: std::cell::Cell<bool>,
    }
    impl StubUsers {
        fn seed(&self, u: User) { self.rows.borrow_mut().push(u); }
    }
    impl UserRepository for StubUsers {
        async fn find_by_id(&self, id: &str) -> PortResult<Option<User>> {
            if self.fail.get() { return Err(PortError::Unavailable); }
            Ok(self.rows.borrow().iter().find(|u| u.id == id).cloned())
        }
        async fn find_by_email(&self, _: &str) -> PortResult<Option<User>> { Ok(None) }
        async fn create(&self, _: &User) -> PortResult<()> { Ok(()) }
        async fn update(&self, _: &User) -> PortResult<()> { Ok(()) }
        async fn assign_tenant(&self, user_id: &str, tenant_id: &str, now: UnixSeconds) -> PortResult<()> {
            let mut rows = self.rows.borrow_mut();
            match rows.iter_mut().find(|u| u.id == user_id) {
                Some(u) => { u.tenant_id = tenant_id.to_owned(); u.updated_at = now; Ok(()) }
                None    => Err(PortError::NotFound),
            }
        }
        async fn list_by_tenant(&self, _: &str) -> PortResult<Vec<User>> { Ok(vec![]) }
        async fn list_anonymous_expired(&self, _: i64) -> PortResult<Vec<User>> { Ok(vec![]) }
        async fn delete_by_id(&self, _: &str) -> PortResult<()> { Ok(()) }
    }

    fn stub_user(id: &str, tenant_id: &str) -> User {
        User {
            id: id.to_owned(), tenant_id: tenant_id.to_owned(),
            email: None, email_verified: false, display_name: None,
            account_type: crate::tenancy::AccountType::HumanUser,
            status: UserStatus::Active, created_at: 0, updated_at: 0,
        }
    }

    #[tokio::test]
    async fn decide_owner_home_assigns_when_owner_is_on_the_default_tenant() {
        let users = StubUsers::default();
        users.seed(stub_user("u-1", DEFAULT_TENANT_ID));
        let outcome = decide_owner_home(&users, "u-1", "t-new", 100).await;
        assert_eq!(outcome, OwnerHomeOutcome::Assigned);
        assert_eq!(users.rows.borrow()[0].tenant_id, "t-new");
    }

    #[tokio::test]
    async fn decide_owner_home_keeps_an_existing_non_default_home() {
        let users = StubUsers::default();
        users.seed(stub_user("u-1", "t-other"));
        let outcome = decide_owner_home(&users, "u-1", "t-new", 100).await;
        assert_eq!(outcome, OwnerHomeOutcome::KeptExistingHome);
        assert_eq!(users.rows.borrow()[0].tenant_id, "t-other",
            "the existing home must be untouched");
    }

    #[tokio::test]
    async fn decide_owner_home_fails_when_owner_is_not_found() {
        let users = StubUsers::default();
        let outcome = decide_owner_home(&users, "u-ghost", "t-new", 100).await;
        assert_eq!(outcome, OwnerHomeOutcome::Failed);
    }

    #[tokio::test]
    async fn decide_owner_home_fails_when_the_read_itself_fails() {
        let users = StubUsers::default();
        users.seed(stub_user("u-1", DEFAULT_TENANT_ID));
        users.fail.set(true);
        let outcome = decide_owner_home(&users, "u-1", "t-new", 100).await;
        assert_eq!(outcome, OwnerHomeOutcome::Failed);
    }
}
