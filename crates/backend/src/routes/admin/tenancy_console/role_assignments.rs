//! `GET /admin/tenancy/users/:uid/role_assignments` — every role
//! assignment held by one user.

use cesauth_cf::authz::{CloudflareRoleAssignmentRepository, CloudflareRoleRepository};
use cesauth_core::admin::types::AdminAction;
use cesauth_core::authz::ports::{RoleAssignmentRepository, RoleRepository};
use cesauth_frontend::tenancy_console::role_assignments::UserRoleAssignmentsInput;
use cesauth_frontend::tenancy_console::user_role_assignments_page;
use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::console::render;

/// **RFC 145 cycle 3.** Used to return the Leptos shell with no
/// matching `app.rs` route — HTTP 200 rendering `<NotFound/>`.
/// Read-only: `resolve_admin` only, no `ensure_role_allows`.
pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(r) => return Ok(r),
    };

    let uid = match ctx.param("uid") {
        Some(s) => s.clone(),
        None    => return Response::error("missing user id", 400),
    };

    let assignments_repo = CloudflareRoleAssignmentRepository::new(&ctx.env);
    let assignments = assignments_repo.list_for_user(&uid).await.unwrap_or_default();

    let roles_repo = CloudflareRoleRepository::new(&ctx.env);
    let mut seen = std::collections::HashSet::new();
    let mut role_labels: Vec<(String, String, String)> = Vec::new();
    for a in &assignments {
        if !seen.insert(a.role_id.clone()) { continue; }
        if let Ok(Some(r)) = roles_repo.get(&a.role_id).await {
            role_labels.push((r.id, r.slug, r.display_name));
        }
    }

    let input = UserRoleAssignmentsInput {
        user_id:     &uid,
        assignments: &assignments,
        role_labels: &role_labels,
    };
    render::html_response(|| user_role_assignments_page(&admin, &input))
}

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let _admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    crate::routes::admin::operator_json_api::csrf_json()
}
