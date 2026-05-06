//! `GET/POST /admin/t/:slug/organizations/:oid/status` —
//! tenant-scoped organization status change. Preview/confirm.

use cesauth_cf::tenancy::CloudflareOrganizationRepository;
use cesauth_core::authz::types::{PermissionCatalog, ScopeRef};
use cesauth_core::tenancy::ports::OrganizationRepository;
use cesauth_core::tenancy::types::{Organization, OrganizationStatus};
use cesauth_ui::tenant_admin::forms::organization_set_status::{form_page, preview_page};
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenancy_console::forms::common::{confirmed, parse_form, redirect_303};
use crate::routes::admin::tenant_admin::gate;

/// Common opening: gate + check_permission + load org + verify
/// the org actually belongs to this tenant. Defense-in-depth: an
/// :oid in the URL could address a different tenant's row even
/// though the slug gate passed.
async fn gate_and_load<D>(
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
        PermissionCatalog::ORGANIZATION_UPDATE,
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
    let (ctx_ta, org) = match gate_and_load(&req, &ctx).await? {
        Ok(pair)  => pair,
        Err(resp) => return Ok(resp),
    };
    render::html_response(form_page(
        &ctx_ta.principal, &ctx_ta.tenant, &org, None, "", None,
    ))
}

pub async fn submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, org) = match gate_and_load(&req, &ctx).await? {
        Ok(pair)  => pair,
        Err(resp) => return Ok(resp),
    };

    let form = parse_form(&mut req).await?;
    let target = match form.get("status").map(String::as_str) {
        Some("active")    => OrganizationStatus::Active,
        Some("suspended") => OrganizationStatus::Suspended,
        Some("deleted")   => OrganizationStatus::Deleted,
        _ => {
            return render::html_response(form_page(
                &ctx_ta.principal, &ctx_ta.tenant, &org, None, "",
                Some("Choose a target status"),
            ));
        }
    };
    let reason = form.get("reason").cloned().unwrap_or_default();

    if reason.trim().is_empty() {
        return render::html_response(form_page(
            &ctx_ta.principal, &ctx_ta.tenant, &org, Some(target), "",
            Some("Reason is required"),
        ));
    }

    if !confirmed(&form) {
        return render::html_response(preview_page(
            &ctx_ta.principal, &ctx_ta.tenant, &org, target, &reason,
        ));
    }

    let orgs_repo = CloudflareOrganizationRepository::new(&ctx.env);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if let Err(e) = orgs_repo.set_status(&org.id, target, now).await {
        worker::console_error!("org set_status failed: {e:?}");
        return Response::error("storage error", 500);
    }

    audit::write_owned(
        &ctx.env, EventKind::OrganizationStatusChanged,
        Some(ctx_ta.principal.id.clone()), Some(org.id.clone()),
        Some(format!("via=tenant-admin,tenant={},target={:?},reason={}",
            ctx_ta.tenant.id, target, reason).to_lowercase()),
    ).await.ok();

    redirect_303(&format!("/admin/t/{}/organizations/{}", ctx_ta.tenant.slug, org.id))
}
