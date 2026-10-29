//! `GET /admin/tenancy/organizations/:oid` — single organization view.

use cesauth_cf::tenancy::{
    CloudflareGroupRepository, CloudflareMembershipRepository,
    CloudflareOrganizationRepository,
};
use cesauth_core::tenancy::ports::{
    GroupRepository, MembershipRepository, OrganizationRepository,
};
use cesauth_frontend::tenancy_console::organization_detail_page;
use cesauth_frontend::tenancy_console::organizations::OrganizationDetailInput;
use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::console::render;

/// **RFC 145 cycle 3.** Used to return the Leptos shell with no
/// matching `app.rs` route — HTTP 200 rendering `<NotFound/>`.
/// Read-only, same as the tenant/organization list pages: `resolve_admin`
/// only, no `ensure_role_allows` (ViewTenancy is open to every valid role).
pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let _admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(r) => return Ok(r),
    };

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

    let groups_repo = CloudflareGroupRepository::new(&ctx.env);
    let groups = groups_repo.list_for_organization(&org.id).await.unwrap_or_default();
    let members_repo = CloudflareMembershipRepository::new(&ctx.env);
    let members = members_repo.list_organization_members(&org.id).await.unwrap_or_default();

    render::html_response(|| organization_detail_page(&_admin, &OrganizationDetailInput {
        organization: &org,
        groups:       &groups,
        members:      &members,
    }))
}
