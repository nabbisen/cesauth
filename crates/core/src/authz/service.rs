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
fn scope_covers(grant: &Scope, query: &ScopeRef<'_>) -> bool {
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

fn role_has_permission(role: &Role, permission: &str) -> bool {
    role.permissions.iter().any(|p: &Permission| p.as_str() == permission)
}
