//! `GET /admin/t/:slug/organizations/:oid` — drill-in detail for a
//! single organization within the current tenant.
//!
//! **RFC 145 cycle 2.** This route used to return the Leptos shell
//! with no matching route in `app.rs`'s router — the browser's
//! `<NotFound/>` fallback rendered at HTTP 200, after the admin auth
//! check had already passed. `organization_detail_page` and
//! `render::html_response` were imported and unused; this wires them.
//! `page_json` is deleted with it: a `.json` sibling with no Leptos
//! page to call it had no consumer (`grep -rn 'detail.json'
//! crates/frontend/src/` → 0 hits), the same orphan class RFC 147 D10
//! removed `deletion-requests.json` for.

use cesauth_cf::tenancy::{CloudflareGroupRepository, CloudflareOrganizationRepository};
use cesauth_core::tenancy::ports::{GroupRepository, OrganizationRepository};
use cesauth_frontend::tenant_admin::organization_detail_page;
use worker::{Request, Response, Result, RouteContext};

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

    let oid = match ctx.param("oid") {
        Some(s) => s.clone(),
        None    => return Response::error("missing organization id", 400),
    };
    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let org = match orgs.get(&oid).await {
        Ok(Some(o)) => o,
        Ok(None)    => return Response::error("organization not found", 404),
        Err(_)      => return Response::error("storage error", 500),
    };
    if org.tenant_id != ctx_ta.tenant.id {
        return Response::error("organization belongs to a different tenant", 403);
    }

    let groups_repo = CloudflareGroupRepository::new(&ctx.env);
    let groups = groups_repo.list_for_organization(&org.id).await.unwrap_or_default();

    let aff = gate::build_affordances(&ctx_ta, &ctx).await?;

    render::html_response(|| organization_detail_page(
        &ctx_ta.principal, &ctx_ta.tenant, &org, &groups, &aff,
    ))
}
