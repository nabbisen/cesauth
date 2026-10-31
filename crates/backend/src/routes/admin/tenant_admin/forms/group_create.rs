//! `GET/POST /admin/t/:slug/organizations/:oid/groups/new` —
//! tenant-scoped group create. One-click submit (additive).

use cesauth_cf::tenancy::{CloudflareGroupRepository, CloudflareOrganizationRepository};
use cesauth_core::authz::types::{PermissionCatalog, ScopeRef};
use cesauth_core::tenancy::ports::OrganizationRepository;
use cesauth_core::tenancy::service::create_group;
use cesauth_core::tenancy::types::Organization;
use cesauth_frontend::tenant_admin::forms::group_create::group_create_form;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenancy_console::forms::common::{
    attach_csrf_cookie, mint_csrf, parse_form, redirect_303, verify_csrf,
};
use crate::routes::admin::tenant_admin::gate;

async fn gate_and_load_org<D>(
    req: &Request,
    ctx: &RouteContext<D>,
) -> Result<std::result::Result<(cesauth_core::tenant_admin::TenantAdminContext, Organization), Response>> {
    let principal = match auth::resolve_or_respond(req, &ctx.env).await? {
        Ok(p)     => p,
        Err(resp) => return Ok(Err(resp)),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, ctx).await? {
        Ok(c)     => c,
        Err(resp) => return Ok(Err(resp)),
    };
    if let Err(resp) = gate::check_action(
        &ctx_ta,
        PermissionCatalog::GROUP_CREATE,
        ScopeRef::Tenant { tenant_id: &ctx_ta.tenant.id },
        ctx,
    ).await? {
        return Ok(Err(resp));
    }

    let oid = match ctx.param("oid") {
        Some(s) => s.clone(),
        None    => return Ok(Err(Response::error("missing organization id", 400)?)),
    };
    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let org = match orgs.get(&oid).await {
        Ok(Some(o)) => o,
        Ok(None)    => return Ok(Err(Response::error("organization not found", 404)?)),
        Err(_)      => return Ok(Err(Response::error("storage error", 500)?)),
    };
    if org.tenant_id != ctx_ta.tenant.id {
        return Ok(Err(Response::error("organization belongs to a different tenant", 403)?));
    }
    Ok(Ok((ctx_ta, org)))
}

/// **RFC 145 cycle 2.** Used to return the Leptos shell with no
/// matching `app.rs` route — HTTP 200 rendering `<NotFound/>`. Reuses
/// `gate_and_load_org` (the same opening `submit` below uses).
pub async fn form<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, org) = match gate_and_load_org(&req, &ctx).await? {
        Ok(pair)  => pair,
        Err(resp) => return Ok(resp),
    };
    let (csrf_token, csrf_cookie) = mint_csrf()?;
    let mut resp = render::html_response(|| group_create_form(
        &ctx_ta.principal, &ctx_ta.tenant, &org, "", "", None, &csrf_token,
    ))?;
    attach_csrf_cookie(&mut resp, &csrf_cookie);
    Ok(resp)
}

/// `GET .json` — CSRF token for the form form.
pub async fn form_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let _ctx_ta = match super::super::json_api::resolve_ctx(&req, &ctx).await? {
        Ok(c)  => c,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    super::super::json_api::csrf_json()
}

pub async fn submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, org) = match gate_and_load_org(&req, &ctx).await? {
        Ok(pair)  => pair,
        Err(resp) => return Ok(resp),
    };

    let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();
    let form = parse_form(&mut req).await?;
    if !verify_csrf(&form, &cookie_header) {
        return Response::error("Bad Request", 400);
    }
    let slug         = form.get("slug").cloned().unwrap_or_default();
    let display_name = form.get("display_name").cloned().unwrap_or_default();

    if slug.trim().is_empty() || display_name.trim().is_empty() {
        let (csrf_token, csrf_cookie) = mint_csrf()?;
        let mut resp = render::html_response(|| group_create_form(
            &ctx_ta.principal, &ctx_ta.tenant, &org, &slug, &display_name,
            Some("Slug and display name are required"), &csrf_token,
        ))?;
        attach_csrf_cookie(&mut resp, &csrf_cookie);
        return Ok(resp);
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let groups = CloudflareGroupRepository::new(&ctx.env);
    let input = cesauth_core::tenancy::ports::NewGroupInput {
        tenant_id:              &ctx_ta.tenant.id,
        parent:                 cesauth_core::tenancy::types::GroupParent::Organization {
            organization_id: org.id.clone(),
        },
        slug:                   &slug,
        display_name:           &display_name,
        organization_tenant_id: None,
    };
    let group = match create_group(&groups, &input, now).await {
        Ok(g)  => g,
        Err(e) => {
            let msg = match e {
                cesauth_core::ports::PortError::Conflict
                    => "Slug already taken in this organization".to_owned(),
                cesauth_core::ports::PortError::PreconditionFailed(m)
                    => m.to_owned(),
                _ => "Storage error".to_owned(),
            };
            let (csrf_token, csrf_cookie) = mint_csrf()?;
            let mut resp = render::html_response(|| group_create_form(
                &ctx_ta.principal, &ctx_ta.tenant, &org, &slug, &display_name, Some(&msg), &csrf_token,
            ))?;
            attach_csrf_cookie(&mut resp, &csrf_cookie);
            return Ok(resp);
        }
    };

    audit::write_owned(
        &ctx.env, EventKind::GroupCreated,
        Some(ctx_ta.principal.id.clone()), Some(group.id.clone()),
        Some(format!("via=tenant-admin,tenant={},org={},slug={}",
            ctx_ta.tenant.id, org.id, group.slug)),
    ).await.ok();

    redirect_303(&format!("/admin/t/{}/organizations/{}", ctx_ta.tenant.slug, org.id))
}
