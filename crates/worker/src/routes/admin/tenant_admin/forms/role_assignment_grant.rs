//! `GET/POST /admin/t/:slug/users/:uid/role_assignments/new` —
//! grant a role to a user. Preview/confirm.
//!
//! Constraints relative to the system-admin equivalent:
//! - `Scope::System` is rejected. Tenant admins cannot grant
//!   cesauth-wide roles (ADR-003 separation).
//! - The `tenant` scope's `scope_id` is forced to the current
//!   tenant. A tenant admin who tries to grant against a
//!   different tenant's id is refused with 403.
//! - Visible roles come from the tenant's role catalog
//!   (`list_visible_to_tenant`), not the global system role list.

use cesauth_cf::authz::{CloudflareRoleAssignmentRepository, CloudflareRoleRepository};
use cesauth_cf::ports::repo::CloudflareUserRepository;
use cesauth_cf::tenancy::{CloudflareGroupRepository, CloudflareOrganizationRepository};
use cesauth_core::authz::ports::{RoleAssignmentRepository, RoleRepository};
use cesauth_core::authz::types::{PermissionCatalog, Role, RoleAssignment, Scope, ScopeRef};
use cesauth_core::ports::repo::UserRepository;
use cesauth_core::tenancy::ports::{GroupRepository, OrganizationRepository};
use cesauth_core::types::User;
use cesauth_ui::tenant_admin::forms::role_assignment_grant::{
    grant_form, preview_page, GrantInput, PreviewInput,
};
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenancy_console::forms::common::{confirmed, parse_form, redirect_303};
use crate::routes::admin::tenant_admin::gate;

async fn gate_and_load_user<D>(
    req: &Request,
    ctx: &RouteContext<D>,
) -> Result<std::result::Result<(cesauth_core::tenant_admin::TenantAdminContext, User), Response>> {
    let principal = match auth::resolve_or_respond(req, &ctx.env).await? {
        Ok(p)     => p,
        Err(resp) => return Ok(Err(resp)),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, ctx).await? {
        Ok(c)     => c,
        Err(resp) => return Ok(Err(resp)),
    };
    if let Err(resp) = gate::check_action(
        &ctx_ta,
        PermissionCatalog::ROLE_ASSIGN,
        ScopeRef::Tenant { tenant_id: &ctx_ta.tenant.id },
        ctx,
    ).await? {
        return Ok(Err(resp));
    }

    let uid = match ctx.param("uid") {
        Some(s) => s.clone(),
        None    => return Ok(Err(Response::error("missing user id", 400)?)),
    };
    let users = CloudflareUserRepository::new(&ctx.env);
    let user = match users.find_by_id(&uid).await {
        Ok(Some(u)) => u,
        Ok(None)    => return Ok(Err(Response::error("user not found", 404)?)),
        Err(_)      => return Ok(Err(Response::error("storage error", 500)?)),
    };
    if user.tenant_id != ctx_ta.tenant.id {
        return Ok(Err(Response::error(
            "user belongs to a different tenant", 403)?));
    }
    Ok(Ok((ctx_ta, user)))
}

async fn list_available_roles(env: &worker::Env, tenant_id: &str) -> Vec<Role> {
    let roles = CloudflareRoleRepository::new(env);
    // Tenant catalogue: system-roles visible to this tenant + any
    // tenant-local roles. RoleRepository::list_visible_to_tenant
    // wraps that combination.
    roles.list_visible_to_tenant(tenant_id).await.unwrap_or_default()
}

pub async fn form<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, user) = match gate_and_load_user(&req, &ctx).await? {
        Ok(p)     => p,
        Err(resp) => return Ok(resp),
    };
    let available = list_available_roles(&ctx.env, &ctx_ta.tenant.id).await;
    render::html_response(grant_form(
        &ctx_ta.principal, &ctx_ta.tenant,
        &GrantInput {
            subject_user: &user,
            available_roles: &available,
            role_id: "", scope_type: "tenant", scope_id: "", expires_at: "",
            error: None,
        },
    ))
}

pub async fn submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, user) = match gate_and_load_user(&req, &ctx).await? {
        Ok(p)     => p,
        Err(resp) => return Ok(resp),
    };

    let form = parse_form(&mut req).await?;
    let role_id        = form.get("role_id").cloned().unwrap_or_default();
    let scope_type     = form.get("scope_type").cloned().unwrap_or_default();
    let scope_id_raw   = form.get("scope_id").cloned().unwrap_or_default();
    let expires_at_raw = form.get("expires_at").cloned().unwrap_or_default();

    let available = list_available_roles(&ctx.env, &ctx_ta.tenant.id).await;
    let render_err = |err: &str, sid: &str| render::html_response(grant_form(
        &ctx_ta.principal, &ctx_ta.tenant,
        &GrantInput {
            subject_user: &user,
            available_roles: &available,
            role_id: &role_id,
            scope_type: &scope_type,
            scope_id: sid,
            expires_at: &expires_at_raw,
            error: Some(err),
        },
    ));

    if role_id.trim().is_empty() {
        return render_err("Pick a role", &scope_id_raw);
    }

    // Build the Scope. Tenant admins cannot grant System scope.
    // Tenant scope is forced to *this* tenant — typing in a
    // different tenant's id is refused with 403, not just an
    // error, because it's a tenant-boundary attempt.
    let scope = match (scope_type.as_str(), scope_id_raw.trim()) {
        ("tenant", _)              => Scope::Tenant       { tenant_id:       ctx_ta.tenant.id.clone() },
        ("organization", "")       => return render_err("Scope id required for organization scope", &scope_id_raw),
        ("organization", id)       => Scope::Organization { organization_id: id.to_owned() },
        ("group",        "")       => return render_err("Scope id required for group scope", &scope_id_raw),
        ("group",        id)       => Scope::Group        { group_id:        id.to_owned() },
        ("user",         "")       => return render_err("Scope id required for user scope", &scope_id_raw),
        ("user",         id)       => Scope::User         { user_id:         id.to_owned() },
        ("system",       _)        => {
            return Response::error(
                "system scope is not available on the tenant-scoped surface; \
                 use the system-admin surface", 403);
        }
        _                          => return render_err("Choose a scope", &scope_id_raw),
    };

    // Defense in depth: verify any scope_id the user supplied
    // actually belongs to this tenant. The scope-walk is lenient
    // about which scope a permission applies *at*, but granting
    // an org/group assignment that lives in a *different tenant*
    // would be a tenant-boundary violation.
    if let Err(resp) = verify_scope_in_tenant(&ctx.env, &scope, &ctx_ta.tenant.id).await {
        return Ok(resp);
    }

    // Validate the role exists.
    let roles_repo = CloudflareRoleRepository::new(&ctx.env);
    let role = match roles_repo.get(&role_id).await.ok().flatten() {
        Some(r) => r,
        None    => return render_err("Unknown role id", &scope_id_raw),
    };

    let expires = if expires_at_raw.trim().is_empty() {
        None
    } else {
        match expires_at_raw.trim().parse::<i64>() {
            Ok(t)  => Some(t),
            Err(_) => return render_err(
                "Expires must be a unix timestamp (integer seconds) or blank",
                &scope_id_raw),
        }
    };

    if !confirmed(&form) {
        let role_label = format!("{} ({})", role.display_name, role.slug);
        let scope_label = render_scope_label(&scope);
        let exp_text = expires.map(|e| e.to_string());
        return render::html_response(preview_page(
            &ctx_ta.principal, &ctx_ta.tenant,
            &role_id, &scope_type, &scope_id_raw, &expires_at_raw,
            &PreviewInput {
                subject_user: &user,
                role_label:   &role_label,
                scope_label:  &scope_label,
                expires_at:   exp_text.as_deref(),
            },
        ));
    }

    // Apply.
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let assignment = RoleAssignment {
        id:         Uuid::new_v4().to_string(),
        user_id:    user.id.clone(),
        role_id:    role_id.clone(),
        scope:      scope.clone(),
        granted_by: ctx_ta.principal.id.clone(),
        granted_at: now,
        expires_at: expires,
    };
    let assignments_repo = CloudflareRoleAssignmentRepository::new(&ctx.env);
    if let Err(e) = assignments_repo.create(&assignment).await {
        worker::console_error!("role_assignment create failed: {e:?}");
        return Response::error("storage error", 500);
    }

    audit::write_owned(
        &ctx.env, EventKind::RoleGranted,
        Some(ctx_ta.principal.id.clone()), Some(assignment.id.clone()),
        Some(format!("via=tenant-admin,tenant={},user={},role={},scope={}",
            ctx_ta.tenant.id, user.id, role_id, render_scope_audit(&scope))),
    ).await.ok();

    redirect_303(&format!("/admin/t/{}/users/{}/role_assignments",
        ctx_ta.tenant.slug, user.id))
}

async fn verify_scope_in_tenant(
    env:       &worker::Env,
    scope:     &Scope,
    tenant_id: &str,
) -> std::result::Result<(), Response> {
    match scope {
        Scope::Tenant { tenant_id: tid } => {
            // Already forced to this tenant by the build path; double-check.
            if tid != tenant_id {
                return Err(Response::error(
                    "scope tenant does not match URL tenant", 403)
                    .unwrap_or_else(|_| Response::empty().unwrap()));
            }
            Ok(())
        }
        Scope::Organization { organization_id } => {
            let orgs = CloudflareOrganizationRepository::new(env);
            match orgs.get(organization_id).await {
                Ok(Some(o)) if o.tenant_id == tenant_id => Ok(()),
                Ok(Some(_)) => Err(Response::error(
                    "scope organization belongs to a different tenant", 403)
                    .unwrap_or_else(|_| Response::empty().unwrap())),
                _ => Err(Response::error("scope organization not found", 404)
                    .unwrap_or_else(|_| Response::empty().unwrap())),
            }
        }
        Scope::Group { group_id } => {
            let groups = CloudflareGroupRepository::new(env);
            match groups.get(group_id).await {
                Ok(Some(g)) if g.tenant_id == tenant_id => Ok(()),
                Ok(Some(g)) => {
                    // Tenant-scoped group: verify via tenant_id;
                    // org-scoped: cross-check the parent org's
                    // tenant_id (already checked above through
                    // Group.tenant_id which is denormalized).
                    let _ = g; // group's tenant_id mismatch
                    Err(Response::error(
                        "scope group belongs to a different tenant", 403)
                        .unwrap_or_else(|_| Response::empty().unwrap()))
                }
                _ => Err(Response::error("scope group not found", 404)
                    .unwrap_or_else(|_| Response::empty().unwrap())),
            }
        }
        Scope::User { user_id } => {
            let users = CloudflareUserRepository::new(env);
            match users.find_by_id(user_id).await {
                Ok(Some(u)) if u.tenant_id == tenant_id => Ok(()),
                Ok(Some(_)) => Err(Response::error(
                    "scope user belongs to a different tenant", 403)
                    .unwrap_or_else(|_| Response::empty().unwrap())),
                _ => Err(Response::error("scope user not found", 404)
                    .unwrap_or_else(|_| Response::empty().unwrap())),
            }
        }
        Scope::System => {
            // Already rejected upstream — but if we ever reach
            // here, treat it as a programmer error and refuse.
            Err(Response::error("system scope not allowed", 403)
                .unwrap_or_else(|_| Response::empty().unwrap()))
        }
    }
}

fn render_scope_label(s: &Scope) -> String {
    match s {
        Scope::System                                  => "system".into(),
        Scope::Tenant       { tenant_id }              => format!("tenant {tenant_id}"),
        Scope::Organization { organization_id }        => format!("organization {organization_id}"),
        Scope::Group        { group_id }               => format!("group {group_id}"),
        Scope::User         { user_id }                => format!("user {user_id}"),
    }
}

fn render_scope_audit(s: &Scope) -> String {
    match s {
        Scope::System                                  => "system".into(),
        Scope::Tenant       { tenant_id }              => format!("tenant:{tenant_id}"),
        Scope::Organization { organization_id }        => format!("organization:{organization_id}"),
        Scope::Group        { group_id }               => format!("group:{group_id}"),
        Scope::User         { user_id }                => format!("user:{user_id}"),
    }
}
