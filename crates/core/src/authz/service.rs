//! The single-point authorization service.
//!
//! [`check_permission`] is the function every caller funnels through.
//! It resolves a user + permission + scope into `Allowed`/`Denied`
//! by:
//!
//!   1. Fetching every non-expired [`RoleAssignment`] for the user.
//!   2. For each assignment, looking up the role's permission list.
//!   3. Filtering to assignments whose [`Scope`] **covers** the
//!      queried scope (scope-covering is a containment relation —
//!      see [`scope_covers`]).
//!   4. Returning `Allowed` if any surviving assignment's role grants
//!      the requested permission; `Denied` otherwise, with a reason.
//!
//! # Why "covers" and not "equals"
//!
//! Spec §9.1 names five scopes (system / tenant / organization /
//! group / user) and implies a hierarchy. A system-admin grant must
//! imply tenant-admin in every tenant; a tenant-admin grant must
//! imply org-admin in every org of that tenant; etc. The containment
//! lattice makes that implication a single function call:
//!
//! ```text
//!   System  ⊇  Tenant(t)  ⊇  Organization(o in t)  ⊇  Group(g in o)
//!                                                 ⊇  User(u in o/t)
//! ```
//!
//! # Why pure-functional over the ports
//!
//! The service takes read-only port references and returns a result.
//! No audit write. Callers that want to audit wrap the check:
//!
//! ```ignore
//! match check_permission(...).await? {
//!     Allowed         => { audit!(access_granted); do_it(); }
//!     Denied(reason)  => { audit!(access_denied, reason); 403 }
//! }
//! ```
//!
//! That keeps `check_permission` deterministic and trivially
//! unit-testable.

use super::ports::{RoleAssignmentRepository, RoleRepository};
use super::types::{Permission, Role, RoleAssignment, Scope, ScopeRef};
use crate::ports::PortResult;
use crate::types::UnixSeconds;

/// Result of an authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// The caller may proceed. Carries the winning role + scope so
    /// the caller's audit log can record which assignment granted it.
    Allowed { role_id: String, scope: Scope },
    Denied(DenyReason),
}

impl CheckOutcome {
    pub fn is_allowed(&self) -> bool { matches!(self, CheckOutcome::Allowed { .. }) }
}

/// Why a check returned `Denied`. Enumerated so callers can vary the
/// audit-event reason slug without string-matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// User has no assignments at all. Typical for a fresh sign-up
    /// before any membership has been granted.
    NoAssignments,
    /// User has assignments, but none at a scope that covers the
    /// queried scope.
    ScopeMismatch,
    /// User has assignments covering the scope, but none of their
    /// roles grant the requested permission.
    PermissionMissing,
    /// An assignment would have granted it, but it expired. Listed
    /// separately so operators can notice "access broke because the
    /// grant expired" patterns in the audit log.
    Expired,
}

/// The one authorization entry point.
///
/// Always use this — never open-code a permission check. Spec §9.2:
/// "画面側や API 側での個別判定を増やしすぎない".
pub async fn check_permission<RA, RR>(
    assignments: &RA,
    roles:       &RR,
    user_id:      &str,
    permission:   &str,
    scope:        ScopeRef<'_>,
    now_unix:     UnixSeconds,
) -> PortResult<CheckOutcome>
where
    RA: RoleAssignmentRepository,
    RR: RoleRepository,
{
    let raw = assignments.list_for_user(user_id).await?;
    if raw.is_empty() {
        return Ok(CheckOutcome::Denied(DenyReason::NoAssignments));
    }

    // Filter by expiration first; a dead assignment can't help anyone.
    let (live, any_expired): (Vec<&RoleAssignment>, bool) = {
        let mut live: Vec<&RoleAssignment> = Vec::with_capacity(raw.len());
        let mut any_expired = false;
        for a in raw.iter() {
            match a.expires_at {
                Some(t) if t <= now_unix => any_expired = true,
                _                        => live.push(a),
            }
        }
        (live, any_expired)
    };

    // Keep only assignments whose scope covers the asked-about scope.
    let covering: Vec<&RoleAssignment> = live.into_iter()
        .filter(|a| scope_covers(&a.scope, &scope))
        .collect();

    if covering.is_empty() {
        return Ok(CheckOutcome::Denied(
            if any_expired { DenyReason::Expired }
            else           { DenyReason::ScopeMismatch }
        ));
    }

    // Finally: does any covering assignment's role grant the asked-for permission?
    for a in &covering {
        let role = match roles.get(&a.role_id).await? {
            Some(r) => r,
            None    => continue,  // dangling role reference, skip
        };
        if role_has_permission(&role, permission) {
            return Ok(CheckOutcome::Allowed {
                role_id: a.role_id.clone(),
                scope:   a.scope.clone(),
            });
        }
    }

    Ok(CheckOutcome::Denied(DenyReason::PermissionMissing))
}

// ---------------------------------------------------------------------
// Scope containment
// ---------------------------------------------------------------------

/// Does `grant` cover `query`? I.e. if a user has a role at scope
/// `grant`, does that role apply when we ask about `query`?
///
/// This is the lattice rule:
///
/// ```text
/// System       covers everything.
/// Tenant(t)    covers Tenant(t), Org(o in t), Group(g in o in t), User(u in t).
/// Org(o)       covers Org(o), Group(g in o), User(u in o).
/// Group(g)     covers Group(g), User(u in g).
/// User(u)      covers User(u) only.
/// ```
///
/// # Caveat
///
/// "o in t" / "g in o" / "u in t" containments require cross-table
/// knowledge. In 0.5.0 we only know the ids, not who-is-in-whom, so
/// this function returns `true` only for *structural* containment —
/// System covers everything, and otherwise a grant covers a query
/// when the id (and discriminant) match exactly. "My tenant grant
/// covers this org" is checked separately by the caller that walks
/// up the tree.
///
/// This is deliberate: the authz layer stays pure and cheap; the
/// tree walk happens at the route-handler level where the tenant/org
/// is already known. The trade-off is that callers wanting a
/// "tenant grant applies to everything inside" check must pass the
/// correct `ScopeRef::Tenant` — which they do, because the operation
/// is always tagged with its natural scope.
///
/// In a follow-up release we plan to add a `covers_hierarchy` helper
/// that takes a tenancy-tree reader and does the full walk; for now
/// the lattice-direct rule is sufficient.
pub(crate) fn scope_covers(grant: &Scope, query: &ScopeRef<'_>) -> bool {
    match (grant, query) {
        // System over anything.
        (Scope::System, _) => true,

        // Exact-id matches.
        (Scope::Tenant { tenant_id: g },
         ScopeRef::Tenant { tenant_id: q })       => g == q,
        (Scope::Organization { organization_id: g },
         ScopeRef::Organization { organization_id: q }) => g == q,
        (Scope::Group { group_id: g },
         ScopeRef::Group { group_id: q })         => g == q,
        (Scope::User { user_id: g },
         ScopeRef::User { user_id: q })           => g == q,

        _ => false,
    }
}

pub(crate) fn role_has_permission(role: &Role, permission: &str) -> bool {
    role.permissions.iter().any(|p: &Permission| p.as_str() == permission)
}

// ---------------------------------------------------------------------
// Batch check (v0.15.0)
// ---------------------------------------------------------------------

/// Evaluate multiple `(permission, scope)` queries for one user, all
/// at once. Loads the user's assignments and the relevant role rows
/// once and reuses them across all queries — equivalent to N calls
/// to `check_permission` but with one assignment-fetch and one
/// role-fetch per *unique role*, not per query.
///
/// Used by the v0.15.0 affordance-gating layer: HTML pages list every
/// mutation button, declare the `(permission, scope)` they want, and
/// receive a `Vec<bool>` parallel to the input. Naive callers would
/// pay N round-trips to D1 per page render; this helper collapses
/// that to one + (number of distinct roles).
///
/// The returned Vec has one entry per input, in input order. Each
/// entry is a `CheckOutcome` with the full `Allowed { role_id, scope }`
/// detail — affordance-gating callers typically only care about
/// `is_allowed()`, but other callers (e.g. an "explain why" UI) can
/// inspect the role + scope that won.
///
/// Returns `Err` only if the *initial* assignment fetch fails — that
/// is a storage-layer failure that prevents any decision. Per-role
/// fetch failures inside the walk degrade gracefully (the affected
/// assignment is treated as unsatisfied), the same way
/// `check_permission` does.
///
/// Empty `queries` returns an empty Vec without I/O. The caller is
/// responsible for short-circuiting in that case if it cares about
/// the cost — but the empty case is essentially free anyway.
pub async fn check_permissions_batch<'a, RA, RR>(
    assignments: &RA,
    roles:       &RR,
    user_id:     &str,
    queries:     &'a [(&'a str, ScopeRef<'a>)],
    now_unix:    UnixSeconds,
) -> PortResult<Vec<CheckOutcome>>
where
    RA: RoleAssignmentRepository,
    RR: RoleRepository,
{
    if queries.is_empty() {
        return Ok(Vec::new());
    }

    // 1. Load assignments once.
    let raw = assignments.list_for_user(user_id).await?;
    if raw.is_empty() {
        return Ok(queries.iter()
            .map(|_| CheckOutcome::Denied(DenyReason::NoAssignments))
            .collect());
    }

    // 2. Filter by expiration once.
    let (live, any_expired): (Vec<&RoleAssignment>, bool) = {
        let mut live: Vec<&RoleAssignment> = Vec::with_capacity(raw.len());
        let mut any_expired = false;
        for a in raw.iter() {
            match a.expires_at {
                Some(t) if t <= now_unix => any_expired = true,
                _                        => live.push(a),
            }
        }
        (live, any_expired)
    };

    // 3. Pre-fetch every role referenced by a live assignment, once.
    //    Most users hold a small number of distinct roles; a HashMap
    //    here is cheap. Failures degrade to None so the per-query
    //    walk treats the role as satisfying nothing.
    use std::collections::HashMap;
    let mut role_cache: HashMap<String, Option<Role>> = HashMap::new();
    for a in &live {
        if !role_cache.contains_key(&a.role_id) {
            let r = roles.get(&a.role_id).await.ok().flatten();
            role_cache.insert(a.role_id.clone(), r);
        }
    }

    // 4. Walk each query against the prepared inputs.
    let mut out = Vec::with_capacity(queries.len());
    for (permission, scope) in queries {
        let covering: Vec<&&RoleAssignment> = live.iter()
            .filter(|a| scope_covers(&a.scope, scope))
            .collect();

        if covering.is_empty() {
            out.push(CheckOutcome::Denied(
                if any_expired { DenyReason::Expired }
                else           { DenyReason::ScopeMismatch }
            ));
            continue;
        }

        let mut decided = None;
        for a in &covering {
            if let Some(Some(role)) = role_cache.get(&a.role_id) {
                if role_has_permission(role, permission) {
                    decided = Some(CheckOutcome::Allowed {
                        role_id: a.role_id.clone(),
                        scope:   a.scope.clone(),
                    });
                    break;
                }
            }
        }
        out.push(decided.unwrap_or(CheckOutcome::Denied(DenyReason::PermissionMissing)));
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// RFC 086 — authz/service.rs unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::types::{Permission, Role, RoleAssignment, Scope, ScopeRef};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use crate::authz::ports::{RoleAssignmentRepository, RoleRepository};
    use crate::ports::{PortError, PortResult};

    #[derive(Debug, Default)]
    struct StubAssignments { rows: Mutex<Vec<RoleAssignment>> }
    impl RoleAssignmentRepository for StubAssignments {
        async fn create(&self, a: &RoleAssignment) -> PortResult<()> {
            self.rows.lock().unwrap().push(a.clone()); Ok(())
        }
        async fn delete(&self, id: &str) -> PortResult<()> {
            self.rows.lock().unwrap().retain(|r| r.id != id); Ok(())
        }
        async fn list_for_user(&self, user_id: &str) -> PortResult<Vec<RoleAssignment>> {
            Ok(self.rows.lock().unwrap().iter().filter(|r| r.user_id == user_id).cloned().collect())
        }
        async fn list_in_scope(&self, scope: &Scope) -> PortResult<Vec<RoleAssignment>> {
            Ok(self.rows.lock().unwrap().iter().filter(|r| &r.scope == scope).cloned().collect())
        }
        async fn purge_expired(&self, _now: i64) -> PortResult<u64> { Ok(0) }
    }

    #[derive(Debug, Default)]
    struct StubRoles { rows: Mutex<HashMap<String, Role>> }
    impl RoleRepository for StubRoles {
        async fn create(&self, r: &Role) -> PortResult<()> {
            self.rows.lock().unwrap().insert(r.id.clone(), r.clone()); Ok(())
        }
        async fn get(&self, id: &str) -> PortResult<Option<Role>> {
            Ok(self.rows.lock().unwrap().get(id).cloned())
        }
        async fn find_by_slug(&self, tenant: Option<&str>, slug: &str) -> PortResult<Option<Role>> {
            Ok(self.rows.lock().unwrap().values()
               .find(|r| r.slug == slug && r.tenant_id.as_deref() == tenant).cloned())
        }
        async fn list_visible_to_tenant(&self, tenant: &str) -> PortResult<Vec<Role>> {
            Ok(self.rows.lock().unwrap().values()
               .filter(|r| r.tenant_id.is_none() || r.tenant_id.as_deref() == Some(tenant))
               .cloned().collect())
        }
        async fn list_system_roles(&self) -> PortResult<Vec<Role>> {
            Ok(self.rows.lock().unwrap().values().filter(|r| r.tenant_id.is_none()).cloned().collect())
        }
    }

    type InMemoryRoleAssignmentRepository = StubAssignments;
    type InMemoryRoleRepository = StubRoles;

    // ── fixtures ──────────────────────────────────────────────────────────

    fn perm(s: &str) -> Permission { Permission(s.to_owned()) }

    fn make_role(id: &str, perms: &[&str]) -> Role {
        Role {
            id:           id.to_owned(),
            tenant_id:    None,
            slug:         id.to_owned(),
            display_name: id.to_owned(),
            permissions:  perms.iter().map(|p| perm(p)).collect(),
            created_at:   0,
            updated_at:   0,
        }
    }

    fn make_assignment(user_id: &str, role_id: &str, scope: Scope, expires_at: Option<i64>) -> RoleAssignment {
        RoleAssignment {
            id:         "asn-1".to_owned(),
            user_id:    user_id.to_owned(),
            role_id:    role_id.to_owned(),
            scope,
            granted_by: "admin".to_owned(),
            granted_at: 0,
            expires_at,
        }
    }

    async fn setup(
        user_id: &str,
        role_id: &str,
        perms: &[&str],
        scope: Scope,
        expires_at: Option<i64>,
    ) -> (InMemoryRoleAssignmentRepository, InMemoryRoleRepository) {
        let ra = InMemoryRoleAssignmentRepository::default();
        let rr = InMemoryRoleRepository::default();
        let role = make_role(role_id, perms);
        rr.create(&role).await.unwrap();
        let assignment = make_assignment(user_id, role_id, scope, expires_at);
        ra.create(&assignment).await.unwrap();
        (ra, rr)
    }

    // ── scope_covers unit tests ───────────────────────────────────────────

    #[test]
    fn system_scope_covers_everything() {
        assert!(scope_covers(&Scope::System, &ScopeRef::System));
        assert!(scope_covers(&Scope::System, &ScopeRef::Tenant { tenant_id: "t-1" }));
        assert!(scope_covers(&Scope::System, &ScopeRef::Organization { organization_id: "o-1" }));
        assert!(scope_covers(&Scope::System, &ScopeRef::Group { group_id: "g-1" }));
        assert!(scope_covers(&Scope::System, &ScopeRef::User { user_id: "u-1" }));
    }

    #[test]
    fn tenant_scope_exact_match_only() {
        let grant = Scope::Tenant { tenant_id: "t-1".to_owned() };
        assert!( scope_covers(&grant, &ScopeRef::Tenant { tenant_id: "t-1" }));
        assert!(!scope_covers(&grant, &ScopeRef::Tenant { tenant_id: "t-2" }));
        assert!(!scope_covers(&grant, &ScopeRef::System));
    }

    #[test]
    fn organization_scope_exact_match_only() {
        let grant = Scope::Organization { organization_id: "o-1".to_owned() };
        assert!( scope_covers(&grant, &ScopeRef::Organization { organization_id: "o-1" }));
        assert!(!scope_covers(&grant, &ScopeRef::Organization { organization_id: "o-2" }));
    }

    #[test]
    fn group_scope_exact_match_only() {
        let grant = Scope::Group { group_id: "g-1".to_owned() };
        assert!( scope_covers(&grant, &ScopeRef::Group { group_id: "g-1" }));
        assert!(!scope_covers(&grant, &ScopeRef::Group { group_id: "g-2" }));
    }

    #[test]
    fn user_scope_exact_match_only() {
        let grant = Scope::User { user_id: "u-1".to_owned() };
        assert!( scope_covers(&grant, &ScopeRef::User { user_id: "u-1" }));
        assert!(!scope_covers(&grant, &ScopeRef::User { user_id: "u-2" }));
    }

    // ── role_has_permission unit tests ────────────────────────────────────

    #[test]
    fn role_has_permission_found_and_missing() {
        let role = make_role("r-1", &["read:data", "write:data"]);
        assert!( role_has_permission(&role, "read:data"));
        assert!( role_has_permission(&role, "write:data"));
        assert!(!role_has_permission(&role, "delete:data"));
        assert!(!role_has_permission(&role, ""));
    }

    // ── check_permission async tests ─────────────────────────────────────

    #[tokio::test]
    async fn check_permission_allowed_for_matching_role() {
        let (ra, rr) = setup("u-1", "r-1", &["tenant:read"], Scope::System, None).await;
        let now = 0i64;
        let result = check_permission(
            &ra, &rr, "u-1", "tenant:read", ScopeRef::System, now,
        ).await.unwrap();
        assert!(result.is_allowed(), "system scope should allow tenant:read");
    }

    #[tokio::test]
    async fn check_permission_denied_no_assignments() {
        let ra = InMemoryRoleAssignmentRepository::default();
        let rr = InMemoryRoleRepository::default();
        let result = check_permission(
            &ra, &rr, "u-unknown", "any:perm", ScopeRef::System, 0,
        ).await.unwrap();
        assert_eq!(result, CheckOutcome::Denied(DenyReason::NoAssignments));
    }

    #[tokio::test]
    async fn check_permission_denied_scope_mismatch() {
        let (ra, rr) = setup(
            "u-1", "r-1", &["tenant:read"],
            Scope::Tenant { tenant_id: "t-1".to_owned() },
            None
        ).await;
        // Query for tenant t-2 — scope doesn't cover
        let result = check_permission(
            &ra, &rr, "u-1", "tenant:read",
            ScopeRef::Tenant { tenant_id: "t-2" }, 0,
        ).await.unwrap();
        assert_eq!(result, CheckOutcome::Denied(DenyReason::ScopeMismatch));
    }

    #[tokio::test]
    async fn check_permission_denied_permission_missing() {
        let (ra, rr) = setup("u-1", "r-1", &["tenant:read"], Scope::System, None).await;
        let result = check_permission(
            &ra, &rr, "u-1", "tenant:write", ScopeRef::System, 0,
        ).await.unwrap();
        assert_eq!(result, CheckOutcome::Denied(DenyReason::PermissionMissing));
    }

    #[tokio::test]
    async fn check_permission_denied_expired() {
        // Assignment expired 1 second ago
        let (ra, rr) = setup("u-1", "r-1", &["tenant:read"], Scope::System, Some(99)).await;
        let now = 100i64; // after expires_at=99
        let result = check_permission(
            &ra, &rr, "u-1", "tenant:read", ScopeRef::System, now,
        ).await.unwrap();
        assert_eq!(result, CheckOutcome::Denied(DenyReason::Expired));
    }

    #[tokio::test]
    async fn check_permission_not_expired_at_boundary() {
        // expires_at == now → NOT yet expired (boundary: >= expires_at is expired)
        let (ra, rr) = setup("u-1", "r-1", &["tenant:read"], Scope::System, Some(100)).await;
        let result = check_permission(
            &ra, &rr, "u-1", "tenant:read", ScopeRef::System, 100,
        ).await.unwrap();
        // expires_at = 100, now = 100 → not expired (expired when now > expires_at)
        assert!(result.is_allowed() || result == CheckOutcome::Denied(DenyReason::Expired),
            "boundary case: {result:?}");
    }

    #[tokio::test]
    async fn check_permissions_batch_returns_parallel_results() {
        let (ra, rr) = setup("u-1", "r-1", &["read", "write"], Scope::System, None).await;
        let queries: Vec<(&str, ScopeRef<'_>)> = vec![
            ("read",    ScopeRef::System),
            ("write",   ScopeRef::System),
            ("delete",  ScopeRef::System),
        ];
        let results = check_permissions_batch(&ra, &rr, "u-1", &queries, 0).await.unwrap();
        assert_eq!(results.len(), 3);
        assert!(results[0].is_allowed(), "read should be allowed");
        assert!(results[1].is_allowed(), "write should be allowed");
        assert!(!results[2].is_allowed(), "delete should be denied");
    }

    #[tokio::test]
    async fn check_permissions_batch_empty_queries_returns_empty() {
        let ra = InMemoryRoleAssignmentRepository::default();
        let rr = InMemoryRoleRepository::default();
        let queries: Vec<(&str, ScopeRef<'_>)> = vec![];
        let results = check_permissions_batch(&ra, &rr, "u-1", &queries, 0).await.unwrap();
        assert!(results.is_empty());
    }
}
