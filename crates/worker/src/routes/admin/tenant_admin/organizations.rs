//! `GET /admin/t/:slug/organizations` — list organizations within
//! the current tenant.

use cesauth_cf::tenancy::CloudflareOrganizationRepository;
use cesauth_core::tenancy::ports::OrganizationRepository;
use cesauth_ui::tenant_admin::organizations_page;
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
        cesauth_core::authz::types::PermissionCatalog::ORGANIZATION_READ,
        &ctx,
    ).await? {
        return Ok(resp);
    }

    let orgs_repo = CloudflareOrganizationRepository::new(&ctx.env);
    let orgs = orgs_repo.list_for_tenant(&ctx_ta.tenant.id).await
        .unwrap_or_default();

    let aff = gate::build_affordances(&ctx_ta, &ctx).await?;
    render::html_response(organizations_page(&ctx_ta.principal, &ctx_ta.tenant, &orgs, &aff))
}
