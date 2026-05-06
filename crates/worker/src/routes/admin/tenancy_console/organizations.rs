//! `GET /admin/tenancy/organizations/:oid` — single organization view.

use cesauth_cf::tenancy::{
    CloudflareGroupRepository, CloudflareMembershipRepository,
    CloudflareOrganizationRepository,
};
use cesauth_core::admin::types::AdminAction;
use cesauth_core::tenancy::ports::{
    GroupRepository, MembershipRepository, OrganizationRepository,
};
use cesauth_ui::tenancy_console::organization_detail_page;
use cesauth_ui::tenancy_console::organizations::OrganizationDetailInput;
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
    let Some(oid) = ctx.param("oid") else { return Response::error("not found", 404); };

    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let org = match orgs.get(oid).await {
        Ok(Some(o)) => o,
        Ok(None)    => return Response::error("not found", 404),
        Err(_)      => return Response::error("storage error", 500),
    };

    let groups_repo  = CloudflareGroupRepository::new(&ctx.env);
    let members_repo = CloudflareMembershipRepository::new(&ctx.env);
    let groups       = groups_repo.list_for_organization(&org.id).await.unwrap_or_default();
    let members      = members_repo.list_organization_members(&org.id).await.unwrap_or_default();

    render::html_response(organization_detail_page(&principal, &OrganizationDetailInput {
        organization: &org,
        groups:       &groups,
        members:      &members,
    }))
}
