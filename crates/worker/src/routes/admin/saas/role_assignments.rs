//! `GET /admin/saas/users/:uid/role_assignments` — every role
//! assignment held by one user.

use cesauth_cf::authz::{CloudflareRoleAssignmentRepository, CloudflareRoleRepository};
use cesauth_core::admin::types::AdminAction;
use cesauth_core::authz::ports::{RoleAssignmentRepository, RoleRepository};
use cesauth_ui::saas::role_assignments::UserRoleAssignmentsInput;
use cesauth_ui::saas::user_role_assignments_page;
use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::auth;
use crate::routes::admin::console::render;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)    => p,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = auth::ensure_role_allows(&principal, AdminAction::ViewTenancy) {
        return Ok(resp);
    }
    let Some(uid) = ctx.param("uid") else { return Response::error("not found", 404); };

    let assignments_repo = CloudflareRoleAssignmentRepository::new(&ctx.env);
    let assignments = assignments_repo.list_for_user(uid).await.unwrap_or_default();

    // Fetch every role we've cited so the UI can show display names.
    // List system roles up front (the common case) plus any
    // tenant-local role referenced by the assignments. List_system
    // is one query; the per-tenant query happens lazily and we ignore
    // failures.
    let roles_repo = CloudflareRoleRepository::new(&ctx.env);
    let mut role_labels: Vec<(String, String, String)> = Vec::new();
    if let Ok(rs) = roles_repo.list_system_roles().await {
        for r in rs {
            role_labels.push((r.id, r.slug, r.display_name));
        }
    }
    // Pull any non-system role referenced but not yet labelled. We
    // don't know the role's tenant from the assignment alone, so
    // this is a per-id `get`; with system roles already loaded the
    // typical dictionary already covers most cases.
    for a in &assignments {
        if role_labels.iter().any(|(id, _, _)| id == &a.role_id) {
            continue;
        }
        if let Ok(Some(r)) = roles_repo.get(&a.role_id).await {
            role_labels.push((r.id, r.slug, r.display_name));
        }
    }

    render::html_response(user_role_assignments_page(&principal, &UserRoleAssignmentsInput {
        user_id:     uid,
        assignments: &assignments,
        role_labels: &role_labels,
    }))
}
