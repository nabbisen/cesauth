//! `GET/POST /admin/t/:slug/role_assignments/:id/delete` —
//! revoke a role assignment. Preview/confirm.
//!
//! `user_id` rides on the query string (?user_id=...) — same
//! pattern as the system-admin equivalent, because the
//! repository does not expose `get_by_id` for assignments.

use cesauth_cf::authz::{CloudflareRoleAssignmentRepository, CloudflareRoleRepository};
use cesauth_cf::ports::repo::CloudflareUserRepository;
use cesauth_core::authz::ports::{RoleAssignmentRepository, RoleRepository};
use cesauth_core::authz::types::{PermissionCatalog, RoleAssignment, ScopeRef};
use cesauth_core::ports::repo::UserRepository;
use cesauth_core::types::User;
use cesauth_ui::tenant_admin::forms::role_assignment_revoke::{form_page, preview_page, RevokeInput};
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenancy_console::forms::common::{confirmed, parse_form, redirect_303};
use crate::routes::admin::tenant_admin::gate;

async fn fetch_assignment(env: &worker::Env, user_id: &str, id: &str)
    -> Option<RoleAssignment>
{
    let repo = CloudflareRoleAssignmentRepository::new(env);
    repo.list_for_user(user_id).await.unwrap_or_default()
        .into_iter().find(|a| a.id == id)
}

async fn role_label(env: &worker::Env, role_id: &str) -> String {
    let roles = CloudflareRoleRepository::new(env);
    match roles.get(role_id).await.ok().flatten() {
        Some(r) => format!("{} ({})", r.display_name, r.slug),
        None    => role_id.to_owned(),
    }
}

async fn gate_and_load<D>(
    req: &Request,
    ctx: &RouteContext<D>,
) -> Result<std::result::Result<(cesauth_core::tenant_admin::TenantAdminContext, RoleAssignment, User, String), Response>> {
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
        PermissionCatalog::ROLE_UNASSIGN,
        ScopeRef::Tenant { tenant_id: &ctx_ta.tenant.id },
        ctx,
    ).await? {
        return Ok(Err(resp));
    }

    let id = match ctx.param("id") {
        Some(s) => s.clone(),
        None    => return Ok(Err(Response::error("missing assignment id", 400)?)),
    };

    let url = req.url()?;
    let user_id = url.query_pairs()
        .find(|(k, _)| k == "user_id")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default();

    if user_id.is_empty() {
        return Ok(Err(Response::error("missing user_id query parameter", 400)?));
    }

    // Defense in depth: the user must belong to this tenant.
    let users = CloudflareUserRepository::new(&ctx.env);
    let user = match users.find_by_id(&user_id).await {
        Ok(Some(u)) => u,
        Ok(None)    => return Ok(Err(Response::error("user not found", 404)?)),
        Err(_)      => return Ok(Err(Response::error("storage error", 500)?)),
    };
    if user.tenant_id != ctx_ta.tenant.id {
        return Ok(Err(Response::error(
            "user belongs to a different tenant", 403)?));
    }

    let assignment = match fetch_assignment(&ctx.env, &user_id, &id).await {
        Some(a) => a,
        None    => return Ok(Err(Response::error("assignment not found", 404)?)),
    };

    let label = role_label(&ctx.env, &assignment.role_id).await;
    Ok(Ok((ctx_ta, assignment, user, label)))
}

pub async fn form<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, assignment, user, label) = match gate_and_load(&req, &ctx).await? {
        Ok(t)     => t,
        Err(resp) => return Ok(resp),
    };
    render::html_response(form_page(
        &ctx_ta.principal, &ctx_ta.tenant,
        &RevokeInput {
            assignment: &assignment,
            subject_user: &user,
            role_label: &label,
            error: None,
        },
    ))
}

pub async fn submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, assignment, user, label) = match gate_and_load(&req, &ctx).await? {
        Ok(t)     => t,
        Err(resp) => return Ok(resp),
    };

    let form = parse_form(&mut req).await?;
    if !confirmed(&form) {
        return render::html_response(preview_page(
            &ctx_ta.principal, &ctx_ta.tenant,
            &RevokeInput {
                assignment: &assignment,
                subject_user: &user,
                role_label: &label,
                error: None,
            },
        ));
    }

    let assignments_repo = CloudflareRoleAssignmentRepository::new(&ctx.env);
    if let Err(e) = assignments_repo.delete(&assignment.id).await {
        worker::console_error!("role_assignment delete failed: {e:?}");
        return Response::error("storage error", 500);
    }

    audit::write_owned(
        &ctx.env, EventKind::RoleRevoked,
        Some(ctx_ta.principal.id.clone()), Some(assignment.id.clone()),
        Some(format!("via=tenant-admin,tenant={},user={},role={}",
            ctx_ta.tenant.id, user.id, assignment.role_id)),
    ).await.ok();

    redirect_303(&format!("/admin/t/{}/users/{}/role_assignments",
        ctx_ta.tenant.slug, user.id))
}
