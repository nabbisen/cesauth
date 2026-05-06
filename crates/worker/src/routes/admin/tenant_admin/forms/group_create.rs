//! `GET/POST /admin/t/:slug/organizations/:oid/groups/new` —
//! tenant-scoped group create. One-click submit (additive).

use cesauth_cf::tenancy::{CloudflareGroupRepository, CloudflareOrganizationRepository};
use cesauth_core::authz::types::{PermissionCatalog, ScopeRef};
use cesauth_core::tenancy::ports::OrganizationRepository;
use cesauth_core::tenancy::service::create_group;
use cesauth_core::tenancy::types::Organization;
use cesauth_ui::tenant_admin::forms::group_create::group_create_form;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenancy_console::forms::common::{parse_form, redirect_303};
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

pub async fn form<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, org) = match gate_and_load_org(&req, &ctx).await? {
        Ok(pair)  => pair,
        Err(resp) => return Ok(resp),
    };
    render::html_response(group_create_form(
        &ctx_ta.principal, &ctx_ta.tenant, &org, "", "", None,
    ))
}

pub async fn submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, org) = match gate_and_load_org(&req, &ctx).await? {
        Ok(pair)  => pair,
        Err(resp) => return Ok(resp),
    };

    let form = parse_form(&mut req).await?;
    let slug         = form.get("slug").cloned().unwrap_or_default();
    let display_name = form.get("display_name").cloned().unwrap_or_default();

    if slug.trim().is_empty() || display_name.trim().is_empty() {
        return render::html_response(group_create_form(
            &ctx_ta.principal, &ctx_ta.tenant, &org, &slug, &display_name,
            Some("Slug and display name are required"),
        ));
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let groups = CloudflareGroupRepository::new(&ctx.env);
    let input = cesauth_core::tenancy::ports::NewGroupInput {
        tenant_id:    &ctx_ta.tenant.id,
        parent:       cesauth_core::tenancy::types::GroupParent::Organization {
            organization_id: org.id.clone(),
        },
        slug:         &slug,
        display_name: &display_name,
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
            return render::html_response(group_create_form(
                &ctx_ta.principal, &ctx_ta.tenant, &org, &slug, &display_name, Some(&msg),
            ));
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
