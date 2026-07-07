//! `GET /admin/t/:slug/users` — list users belonging to the current
//! tenant.

use cesauth_cf::ports::repo::CloudflareUserRepository;
use cesauth_core::ports::repo::UserRepository;
use cesauth_frontend::tenant_admin::users_page;
use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenant_admin::{gate, json_api};

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let ctx_ta = match json_api::resolve_ctx(&req, &ctx).await? {
        Ok(c)  => c,
        Err(r) => return Ok(r),
    };
    if let Err(r) = gate::check_read(
        &ctx_ta,
        cesauth_core::authz::types::PermissionCatalog::TENANT_READ,
        &ctx,
    ).await? { return Ok(r); }
    json_api::shell(&req, &ctx, &format!("Users — {} — cesauth", ctx_ta.tenant.display_name)).await
}

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let ctx_ta = match json_api::resolve_ctx(&req, &ctx).await? {
        Ok(c)  => c,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    if let Err(_) = gate::check_read(
        &ctx_ta,
        cesauth_core::authz::types::PermissionCatalog::TENANT_READ,
        &ctx,
    ).await? { return Response::error("Forbidden", 403); }
    let users = {
        use cesauth_cf::ports::repo::CloudflareUserRepository;
        use cesauth_core::ports::repo::UserRepository;
        let repo = CloudflareUserRepository::new(&ctx.env);
        repo.list_for_tenant(&ctx_ta.tenant.id, 200).await.unwrap_or_default()
    };
    let mut resp = Response::from_json(&serde_json::json!({
        "tenant": ctx_ta.tenant,
        "users":  users,
    }))?;
    resp.headers_mut().set("cache-control", "no-store").ok();
    Ok(resp)
}
