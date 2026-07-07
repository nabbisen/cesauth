//! `GET /admin/tenancy/tenants` — list all non-deleted tenants.

use cesauth_cf::tenancy::CloudflareTenantRepository;
use cesauth_core::admin::types::AdminAction;
use cesauth_core::tenancy::ports::TenantRepository;
use cesauth_frontend::tenancy_console::tenants_page;
use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::auth;
use crate::routes::admin::console::render;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::admin::operator_json_api::shell(&req, &ctx, "テナント一覧 — cesauth").await
}

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let _admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    use cesauth_cf::tenancy::CloudflareTenantRepository;
    use cesauth_core::tenancy::TenantRepository;
    let repo = CloudflareTenantRepository::new(&ctx.env);
    let tenants = repo.list_active().await.unwrap_or_default();
    let mut resp = Response::from_json(&serde_json::json!({ "tenants": tenants }))?;
    resp.headers_mut().set("cache-control", "no-store").ok();
    Ok(resp)
}
