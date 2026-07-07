//! `GET /admin/t/:slug/organizations/:oid` — drill-in detail for a
//! single organization within the current tenant.

use cesauth_cf::tenancy::{CloudflareGroupRepository, CloudflareOrganizationRepository};
use cesauth_core::tenancy::ports::{GroupRepository, OrganizationRepository};
use cesauth_frontend::tenant_admin::organization_detail_page;
use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenant_admin::{gate, json_api};

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let ctx_ta = match json_api::resolve_ctx(&req, &ctx).await? {
        Ok(c)  => c,
        Err(r) => return Ok(r),
    };
    json_api::shell(&req, &ctx, "Organisation — cesauth").await
}

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let ctx_ta = match json_api::resolve_ctx(&req, &ctx).await? {
        Ok(c)  => c,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    json_api::csrf_json()
}
