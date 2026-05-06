//! `GET /admin/tenancy/tenants` — list all non-deleted tenants.

use cesauth_cf::tenancy::CloudflareTenantRepository;
use cesauth_core::admin::types::AdminAction;
use cesauth_core::tenancy::ports::TenantRepository;
use cesauth_ui::tenancy_console::tenants_page;
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

    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let rows = tenants.list_active().await.unwrap_or_default();
    render::html_response(tenants_page(&principal, &rows))
}
