//! `GET /admin/tenancy/users/:uid/role_assignments` — every role
//! assignment held by one user.

use cesauth_cf::authz::{CloudflareRoleAssignmentRepository, CloudflareRoleRepository};
use cesauth_core::admin::types::AdminAction;
use cesauth_core::authz::ports::{RoleAssignmentRepository, RoleRepository};
use cesauth_frontend::tenancy_console::role_assignments::UserRoleAssignmentsInput;
use cesauth_frontend::tenancy_console::user_role_assignments_page;
use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::auth;
use crate::routes::admin::console::render;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::admin::operator_json_api::shell(&req, &ctx, "ロール割り当て — cesauth").await
}

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let _admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    crate::routes::admin::operator_json_api::csrf_json()
}
