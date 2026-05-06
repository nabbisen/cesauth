//! `GET /admin/t/:slug/organizations/:oid` — drill-in detail for a
//! single organization within the current tenant.

use cesauth_cf::tenancy::{CloudflareGroupRepository, CloudflareOrganizationRepository};
use cesauth_core::tenancy::ports::{GroupRepository, OrganizationRepository};
use cesauth_ui::tenant_admin::organization_detail_page;
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

    let oid = match ctx.param("oid") {
        Some(s) => s.clone(),
        None    => return Response::error("missing organization id", 400),
    };

    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let groups = CloudflareGroupRepository::new(&ctx.env);

    let org = match orgs.get(&oid).await.ok().flatten() {
        Some(o) => o,
        None    => return Response::error("organization not found", 404),
    };

    // Defense in depth: even though the resolver gated the URL slug
    // to the user's tenant, the :oid parameter could still address
    // an organization in a different tenant. Refuse with a 403 so
    // a curious tenant admin can't peek across the boundary by
    // typing in another tenant's organization id.
    if org.tenant_id != ctx_ta.tenant.id {
        return Response::error("organization belongs to a different tenant", 403);
    }

    let group_list = groups.list_for_organization(&oid).await
        .unwrap_or_default();

    render::html_response(organization_detail_page(
        &ctx_ta.principal, &ctx_ta.tenant, &org, &group_list,
    ))
}
