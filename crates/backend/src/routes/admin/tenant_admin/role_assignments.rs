//! `GET /admin/t/:slug/users/:uid/role_assignments` — every role
//! assignment held by one user, scoped to the current tenant.

use cesauth_cf::authz::{CloudflareRoleAssignmentRepository, CloudflareRoleRepository};
use cesauth_cf::ports::repo::CloudflareUserRepository;
use cesauth_core::authz::ports::{RoleAssignmentRepository, RoleRepository};
use cesauth_core::ports::repo::UserRepository;
use cesauth_frontend::tenant_admin::{role_assignments_page, TenantUserRoleAssignmentsInput};
use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenant_admin::{gate, json_api};

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let ctx_ta = match json_api::resolve_ctx(&req, &ctx).await? {
        Ok(c)  => c,
        Err(r) => return Ok(r),
    };
    json_api::shell(&req, &ctx, "Role assignments — cesauth").await
}

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let ctx_ta = match json_api::resolve_ctx(&req, &ctx).await? {
        Ok(c)  => c,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    json_api::csrf_json()
}
