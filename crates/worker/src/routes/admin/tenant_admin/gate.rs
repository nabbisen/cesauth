//! Worker glue for the v0.13.0 tenant-admin auth gate.
//!
//! The gate's actual decision logic is `cesauth_core::tenant_admin::
//! resolve_tenant_admin` (pure, host-testable). This module wires that
//! function up to the worker's request/response types: it pulls the
//! slug out of the route context, builds the Cloudflare D1 repository
//! adapters, calls the core gate, and turns either the resolved
//! context or a typed failure into the right HTTP response.
//!
//! Audit emission for `WrongTenant` happens here. Per ADR-003, a
//! cross-tenant access attempt is a structural boundary violation and
//! must not pass silently — even though the gate refuses the request,
//! the attempt itself is forensically interesting.

use cesauth_cf::tenancy::CloudflareTenantRepository;
use cesauth_cf::ports::repo::CloudflareUserRepository;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::tenant_admin::{
    TenantAdminContext, TenantAdminFailure, resolve_tenant_admin,
};
use worker::{Env, Response, Result, RouteContext};

use crate::audit::{self, EventKind};

/// Resolve a tenant-admin context for the current request, or
/// produce the appropriate HTTP response.
///
/// On success, returns `Ok(Ok(ctx))`. On any auth-gate failure,
/// returns `Ok(Err(response))` where `response` carries the right
/// status code and a short human-safe message. The double-Result
/// matches the `auth::resolve_or_respond` pattern used elsewhere
/// in the worker layer.
///
/// Caller contract: the principal must have already been resolved
/// via `auth::resolve_or_respond`. This function does not re-do
/// the bearer lookup; it picks up where that left off.
pub async fn resolve_or_respond<D>(
    principal: AdminPrincipal,
    ctx:       &RouteContext<D>,
) -> Result<std::result::Result<TenantAdminContext, Response>> {
    // The `:slug` parameter is registered in lib.rs's route table.
    // If it's missing, that's a routing-config bug, not a runtime
    // concern — but we defend anyway.
    let slug = match ctx.param("slug") {
        Some(s) => s.clone(),
        None    => {
            // Should not happen if routes are registered correctly.
            return Ok(Err(Response::error("missing tenant slug", 400)?));
        }
    };

    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let users   = CloudflareUserRepository::new(&ctx.env);

    let outcome = resolve_tenant_admin(
        principal.clone(),
        &slug,
        &tenants,
        &users,
    ).await;

    match outcome {
        Ok(ok) => Ok(Ok(ok)),
        Err(failure) => {
            // Audit emission. Cross-tenant access attempts and
            // missing-user (stale principal) cases are noteworthy
            // even when refused; the other failures are routine
            // (slug mistyped, system-admin used the wrong surface).
            if matches!(failure,
                TenantAdminFailure::WrongTenant
                | TenantAdminFailure::UnknownUser
            ) {
                emit_audit(&ctx.env, &principal, &slug, failure).await;
            }
            Ok(Err(error_response(failure)?))
        }
    }
}

fn error_response(failure: TenantAdminFailure) -> Result<Response> {
    Response::error(failure.message(), failure.status_code())
}

/// Gate one action (read or write) against the resolved tenant
/// context. Wraps `cesauth_core::authz::check_permission` for the
/// worker layer.
///
/// Per ADR-002 + the v0.11.0 foundation, the tenant-scoped surface
/// uses `check_permission` (spec §9.2 scope-walk) for action-level
/// authorization rather than `Role::can_*` (the system-admin
/// surface's mechanism). This is what makes the principal's
/// `user_id` actually do work — it's the input the scope-walk
/// needs.
///
/// `permission` is one of the slugs in
/// `cesauth_core::authz::types::PermissionCatalog::*`. Examples:
/// - read: `TENANT_READ`, `ORGANIZATION_READ`, `USER_READ`,
///   `SUBSCRIPTION_READ`
/// - write: `ORGANIZATION_CREATE`, `ROLE_ASSIGN`,
///   `MEMBERSHIP_ADD`, etc.
///
/// `scope` is the resource scope to evaluate against. v0.13.0 read
/// pages always pass `Tenant { tenant_id: ctx.tenant.id }`. v0.14.0
/// mutation forms pass narrower scopes when the action is on a
/// child resource (Organization, Group) — the scope-walk picks up
/// any role assignment that *covers* the requested scope, so a
/// tenant-scoped role still grants child-scope actions.
///
/// Returns `Ok(Ok(()))` if allowed, `Ok(Err(response))` if denied
/// (with a 403). The double-Result follows the same convention as
/// `resolve_or_respond`.
pub async fn check_action<D>(
    ctx_ta:     &TenantAdminContext,
    permission: &str,
    scope:      cesauth_core::authz::types::ScopeRef<'_>,
    ctx:        &RouteContext<D>,
) -> Result<std::result::Result<(), Response>> {
    use cesauth_cf::authz::{CloudflareRoleAssignmentRepository, CloudflareRoleRepository};
    use cesauth_core::authz::service::check_permission;

    let assignments = CloudflareRoleAssignmentRepository::new(&ctx.env);
    let roles       = CloudflareRoleRepository::new(&ctx.env);

    let user_id = match &ctx_ta.principal.user_id {
        Some(id) => id.as_str(),
        // Cannot happen — gate enforces this — but defend anyway.
        None     => return Ok(Err(Response::error(
            "principal not user-bound", 403)?)),
    };

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let outcome = check_permission(
        &assignments,
        &roles,
        user_id,
        permission,
        scope,
        now,
    ).await;

    match outcome {
        Ok(o) if o.is_allowed() => Ok(Ok(())),
        Ok(_) => {
            // Denied. Audit it — denied requests at the tenant
            // surface are interesting (a tenant admin probing for
            // capabilities they don't have).
            let detail = format!(
                "principal {} denied {} on tenant {}",
                ctx_ta.principal.id, permission, ctx_ta.tenant.id,
            );
            let ev = audit::Event::new(EventKind::AdminLoginFailed)
                .with_subject(&ctx_ta.principal.id)
                .with_reason(&detail);
            audit::write(&ctx.env, &ev).await;
            Ok(Err(Response::error("permission denied", 403)?))
        }
        Err(_) => Ok(Err(Response::error("authorization storage error", 503)?)),
    }
}

/// Convenience wrapper for the common case of "permission at the
/// current tenant's scope". Read routes use this; mutation forms
/// that operate on a child resource (Organization, Group) generally
/// call `check_action` directly with a narrower scope.
pub async fn check_read<D>(
    ctx_ta:     &TenantAdminContext,
    permission: &str,
    ctx:        &RouteContext<D>,
) -> Result<std::result::Result<(), Response>> {
    use cesauth_core::authz::types::ScopeRef;
    check_action(
        ctx_ta,
        permission,
        ScopeRef::Tenant { tenant_id: &ctx_ta.tenant.id },
        ctx,
    ).await
}

async fn emit_audit(
    env:       &Env,
    principal: &AdminPrincipal,
    slug:      &str,
    failure:   TenantAdminFailure,
) {
    let detail = match failure {
        TenantAdminFailure::WrongTenant => format!(
            "principal {} attempted /admin/t/{} (cross-tenant)",
            principal.id, slug,
        ),
        TenantAdminFailure::UnknownUser => format!(
            "principal {} carries stale user_id, refused at /admin/t/{}",
            principal.id, slug,
        ),
        _ => return,
    };
    // Best-effort: a failure to emit the audit must not break the
    // already-failing request. The auth gate's job is to refuse;
    // the audit is observability.
    let ev = audit::Event::new(EventKind::AdminLoginFailed)
        .with_subject(&principal.id)
        .with_reason(&detail);
    audit::write(env, &ev).await;
}
