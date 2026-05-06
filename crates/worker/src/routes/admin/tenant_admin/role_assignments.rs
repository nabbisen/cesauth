//! `GET /admin/t/:slug/users/:uid/role_assignments` — every role
//! assignment held by one user, scoped to the current tenant.

use cesauth_cf::authz::{CloudflareRoleAssignmentRepository, CloudflareRoleRepository};
use cesauth_cf::ports::repo::CloudflareUserRepository;
use cesauth_core::authz::ports::{RoleAssignmentRepository, RoleRepository};
use cesauth_core::ports::repo::UserRepository;
use cesauth_ui::tenant_admin::{role_assignments_page, TenantUserRoleAssignmentsInput};
use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenant_admin::gate;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)     => p,
        Err(resp) => return Ok(resp),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c)     => c,
        Err(resp) => return Ok(resp),
    };

    if let Err(resp) = gate::check_read(
        &ctx_ta,
        cesauth_core::authz::types::PermissionCatalog::USER_READ,
        &ctx,
    ).await? {
        return Ok(resp);
    }

    let uid = match ctx.param("uid") {
        Some(s) => s.clone(),
        None    => return Response::error("missing user id", 400),
    };

    // Defense in depth, mirroring organization_detail.rs: even after
    // the slug gate passes, the :uid URL parameter could address a
    // user from a different tenant. Refuse with 403.
    let users_repo = CloudflareUserRepository::new(&ctx.env);
    let subject = match users_repo.find_by_id(&uid).await.ok().flatten() {
        Some(u) => u,
        None    => return Response::error("user not found", 404),
    };
    if subject.tenant_id != ctx_ta.tenant.id {
        return Response::error("user belongs to a different tenant", 403);
    }

    let assignments_repo = CloudflareRoleAssignmentRepository::new(&ctx.env);
    let assignments = assignments_repo.list_for_user(&uid).await
        .unwrap_or_default();

    // Build a (id, slug, display_name) dictionary covering every role
    // referenced in the assignments. System roles are loaded up
    // front (one query); tenant-local roles are fetched lazily.
    let roles_repo = CloudflareRoleRepository::new(&ctx.env);
    let mut role_labels: Vec<(String, String, String)> = Vec::new();
    if let Ok(rs) = roles_repo.list_system_roles().await {
        for r in rs {
            role_labels.push((r.id, r.slug, r.display_name));
        }
    }
    for a in &assignments {
        if role_labels.iter().any(|(id, _, _)| id == &a.role_id) {
            continue;
        }
        if let Ok(Some(r)) = roles_repo.get(&a.role_id).await {
            role_labels.push((r.id, r.slug, r.display_name));
        }
    }

    let input = TenantUserRoleAssignmentsInput {
        subject_user: &subject,
        assignments:  &assignments,
        role_labels:  &role_labels,
    };
    render::html_response(role_assignments_page(&ctx_ta.principal, &ctx_ta.tenant, &input))
}
