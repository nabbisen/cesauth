//! `GET/POST /admin/tenancy/organizations/:oid/status` — organization status.

use cesauth_cf::tenancy::CloudflareOrganizationRepository;
use cesauth_core::tenancy::ports::OrganizationRepository;
use cesauth_core::tenancy::types::OrganizationStatus;
use cesauth_ui::tenancy_console::forms::organization_set_status::{confirm_page, form_page};
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::console::render;
use crate::routes::admin::tenancy_console::forms::common::{
    confirmed, parse_form, redirect_303, require_manage,
};

pub async fn form<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(oid) = ctx.param("oid") else { return Response::error("not found", 404); };
    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let org = match orgs.get(oid).await {
        Ok(Some(o)) => o,
        _ => return Response::error("not found", 404),
    };
    render::html_response(form_page(&principal, &org, None, "", None))
}

pub async fn submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(oid) = ctx.param("oid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };

    let form = parse_form(&mut req).await?;
    let target = match form.get("status").map(String::as_str) {
        Some("active")    => OrganizationStatus::Active,
        Some("suspended") => OrganizationStatus::Suspended,
        Some("deleted")   => OrganizationStatus::Deleted,
        _ => {
            let orgs = CloudflareOrganizationRepository::new(&ctx.env);
            let org = match orgs.get(&oid).await {
                Ok(Some(o)) => o, _ => return Response::error("not found", 404),
            };
            return render::html_response(form_page(
                &principal, &org, None, "", Some("Choose a target status"),
            ));
        }
    };
    let reason = form.get("reason").cloned().unwrap_or_default();

    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let org = match orgs.get(&oid).await {
        Ok(Some(o)) => o, _ => return Response::error("not found", 404),
    };

    if reason.trim().is_empty() {
        return render::html_response(form_page(
            &principal, &org, Some(target), "", Some("Reason is required"),
        ));
    }

    if !confirmed(&form) {
        return render::html_response(confirm_page(&principal, &org, target, &reason));
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    if let Err(e) = orgs.set_status(&oid, target, now).await {
        worker::console_error!("org set_status failed: {e:?}");
        return Response::error("storage error", 500);
    }

    audit::write_owned(
        &ctx.env, EventKind::OrganizationStatusChanged,
        Some(principal.id.clone()), Some(oid.clone()),
        Some(format!("via=tenancy-console,target={:?},reason={}",
            target, reason).to_lowercase()),
    ).await.ok();

    redirect_303(&format!("/admin/tenancy/organizations/{oid}"))
}
