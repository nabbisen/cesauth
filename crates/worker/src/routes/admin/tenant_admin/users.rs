//! `GET /admin/t/:slug/users` — list users belonging to the current
//! tenant.

use cesauth_cf::ports::repo::CloudflareUserRepository;
use cesauth_core::ports::repo::UserRepository;
use cesauth_ui::tenant_admin::users_page;
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

    let users_repo = CloudflareUserRepository::new(&ctx.env);
    let users = users_repo.list_by_tenant(&ctx_ta.tenant.id).await
        .unwrap_or_default();

    render::html_response(users_page(&ctx_ta.principal, &ctx_ta.tenant, &users))
}
