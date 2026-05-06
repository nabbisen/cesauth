//! Tenant-scoped admin surface domain.
//!
//! Introduced in v0.13.0. Builds on the v0.11.0 ADR foundation
//! (`AdminPrincipal::user_id`, `is_system_admin()`, the
//! `admin_tokens.user_id` column) to gate the new
//! `/admin/t/<slug>/...` route surface.
//!
//! The surface is entirely separate from `/admin/tenancy/*`
//! (the system-admin operator console). Per ADR-003, there is no
//! mode switch and no in-page elevation — the two surfaces share
//! no view code, no auth state, no precedence rules. To do
//! system-admin work, an operator visits `/admin/tenancy/...`;
//! to do tenant-admin work for a specific tenant, an operator (or
//! tenant admin) visits `/admin/t/<slug>/...`.
//!
//! The functions here are pure (in the sense that the rest of
//! `cesauth-core` is pure): they take repository ports as
//! arguments, they never call the network themselves, and the
//! decisions they make are testable on the host.
//!
//! ## Authorization model
//!
//! Every tenant-scoped admin route runs through
//! [`resolve_tenant_admin`] before any other work. That function
//! enforces three invariants:
//!
//! 1. **The principal is a user-as-bearer token, not a
//!    system-admin token** (`principal.user_id.is_some()`,
//!    equivalently `!principal.is_system_admin()`). Per ADR-003,
//!    a system-admin token presented at `/admin/t/<slug>/...`
//!    is refused — the operator should be using the system-admin
//!    surface at `/admin/tenancy/...` instead.
//! 2. **The URL slug resolves to a real tenant.** Unknown slug
//!    → `UnknownTenant`.
//! 3. **The principal's user belongs to the resolved tenant**
//!    (`user.tenant_id == tenant.id`). Cross-tenant access
//!    attempts → `WrongTenant`. This is the structural defense
//!    against tenant-boundary leakage that ADR-003 promises.
//!
//! Once those invariants hold, route-specific authorization
//! (whether this user can perform this *action* on this *resource*)
//! is delegated to [`crate::authz::check_permission`] per spec
//! §9.2 — the principal now carries the `user_id` that
//! `check_permission` needs.

use crate::admin::types::AdminPrincipal;
use crate::ports::PortError;
use crate::ports::repo::UserRepository;
use crate::tenancy::ports::TenantRepository;
use crate::tenancy::types::Tenant;
use crate::types::User;

/// Outcome of a successful auth-gate pass on a tenant-scoped
/// admin route. Carries the resolved tenant and user so route
/// handlers can use them without re-fetching.
#[derive(Debug, Clone)]
pub struct TenantAdminContext {
    pub principal: AdminPrincipal,
    pub tenant:    Tenant,
    pub user:      User,
}

/// Typed failure modes for the tenant-scoped auth gate. The
/// worker layer turns these into HTTP responses; keeping the
/// type sharp here means the route code reads as a switch rather
/// than as nested string-matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantAdminFailure {
    /// Principal has no `user_id` — it's a system-admin token.
    /// Per ADR-003, system-admin tokens are refused at the
    /// tenant-scoped surface. The system-admin should be using
    /// `/admin/tenancy/...` instead.
    NotUserBound,
    /// The URL slug did not resolve to a row in `tenants`.
    UnknownTenant,
    /// `users.id == principal.user_id` did not resolve. The
    /// principal carries a stale `user_id`, or the row was
    /// deleted out from under it. Either way the principal is
    /// no longer valid.
    UnknownUser,
    /// The principal's user exists but belongs to a different
    /// tenant. **This is the cross-tenant access attempt
    /// signal.** Should never happen for a well-behaved client;
    /// when it does, audit it.
    WrongTenant,
    /// A repository call failed (storage layer error). Maps to
    /// HTTP 503 in the worker layer.
    Unavailable,
}

impl TenantAdminFailure {
    /// Human-safe message. Like `AuthFailure::message`, this is
    /// safe to render to the requester — nothing sensitive is
    /// revealed (we never echo the slug or user_id back).
    pub fn message(self) -> &'static str {
        match self {
            TenantAdminFailure::NotUserBound  => "system-admin tokens are not valid here; \
                                                  use the operator surface instead",
            TenantAdminFailure::UnknownTenant => "tenant not found",
            TenantAdminFailure::UnknownUser   => "principal is not associated with a known user",
            TenantAdminFailure::WrongTenant   => "principal belongs to a different tenant",
            TenantAdminFailure::Unavailable   => "storage layer unavailable",
        }
    }

    /// HTTP status code the worker layer should return.
    /// `WrongTenant` is 403 (the request is well-formed but
    /// forbidden); `UnknownTenant` is 404 (the resource doesn't
    /// exist for *anyone*); `NotUserBound` is 403; `UnknownUser`
    /// is 401 (the principal's authentication state is broken);
    /// `Unavailable` is 503.
    pub fn status_code(self) -> u16 {
        match self {
            TenantAdminFailure::NotUserBound  => 403,
            TenantAdminFailure::UnknownTenant => 404,
            TenantAdminFailure::UnknownUser   => 401,
            TenantAdminFailure::WrongTenant   => 403,
            TenantAdminFailure::Unavailable   => 503,
        }
    }
}

impl From<PortError> for TenantAdminFailure {
    /// Default mapping: most port failures collapse to
    /// `Unavailable`. `NotFound` is *not* mapped here because
    /// the call site needs to distinguish "the row's missing,
    /// which means the auth gate failed" from "storage broke".
    fn from(_: PortError) -> Self {
        TenantAdminFailure::Unavailable
    }
}

/// Run the auth gate. Returns `Ok(TenantAdminContext)` if
/// everything is in order, `Err(TenantAdminFailure)` otherwise.
///
/// This is the only function in this module the worker layer
/// should call — it owns the entire decision. Route handlers
/// that need additional context (e.g., the organizations within
/// the tenant) call their own repositories *after* this returns
/// `Ok`, scoping further queries to `ctx.tenant.id`.
///
/// Three I/O calls in the happy path: tenant lookup, user
/// lookup, and one comparison. Both lookups are short and use
/// indexed columns, so the latency budget is small.
pub async fn resolve_tenant_admin<T, U>(
    principal:   AdminPrincipal,
    slug:        &str,
    tenants:     &T,
    users:       &U,
) -> Result<TenantAdminContext, TenantAdminFailure>
where
    T: TenantRepository,
    U: UserRepository,
{
    // 1. The principal must be user-bound (ADR-003).
    let user_id = match &principal.user_id {
        Some(id) => id.clone(),
        None     => return Err(TenantAdminFailure::NotUserBound),
    };

    // 2. The slug must resolve to a tenant.
    let tenant = match tenants.find_by_slug(slug).await {
        Ok(Some(t)) => t,
        Ok(None)    => return Err(TenantAdminFailure::UnknownTenant),
        Err(_)      => return Err(TenantAdminFailure::Unavailable),
    };

    // 3. The principal's user must exist…
    let user = match users.find_by_id(&user_id).await {
        Ok(Some(u)) => u,
        Ok(None)    => return Err(TenantAdminFailure::UnknownUser),
        Err(_)      => return Err(TenantAdminFailure::Unavailable),
    };

    // …and belong to *this* tenant. This is the structural
    // tenant-boundary check; without it, an Acme user could
    // peek at Beta's data by visiting /admin/t/beta/.
    if user.tenant_id != tenant.id {
        return Err(TenantAdminFailure::WrongTenant);
    }

    Ok(TenantAdminContext { principal, tenant, user })
}

#[cfg(test)]
mod tests;
