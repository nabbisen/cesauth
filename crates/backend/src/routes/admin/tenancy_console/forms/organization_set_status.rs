//! `GET/POST /admin/tenancy/organizations/:oid/status` — organization status.

use cesauth_cf::tenancy::CloudflareOrganizationRepository;
use cesauth_core::tenancy::ports::OrganizationRepository;
use cesauth_core::tenancy::types::OrganizationStatus;
use cesauth_frontend::tenancy_console::forms::organization_set_status::{confirm_page, form_page};
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::console::render;
use crate::routes::admin::tenancy_console::forms::common::{
    attach_csrf_cookie, confirmed, mint_csrf, parse_form, redirect_303, require_manage,
    verify_csrf,
};

/// **RFC 145 cycle 3.** Used to return the Leptos shell with no
/// matching `app.rs` route — HTTP 200 rendering `<NotFound/>`.
pub async fn form<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(oid) = ctx.param("oid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let org = match orgs.get(&oid).await {
        Ok(Some(o)) => o, _ => return Response::error("not found", 404),
    };
    let (csrf_token, csrf_cookie) = mint_csrf()?;
    let mut resp = render::html_response(|| form_page(&principal, &org, None, "", None, &csrf_token))?;
    attach_csrf_cookie(&mut resp, &csrf_cookie);
    Ok(resp)
}

pub async fn submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(oid) = ctx.param("oid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };

    let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();
    let form = parse_form(&mut req).await?;
    if !verify_csrf(&form, &cookie_header) {
        return Response::error("Bad Request", 400);
    }
    let target = match form.get("status").map(String::as_str) {
        Some("active")    => OrganizationStatus::Active,
        Some("suspended") => OrganizationStatus::Suspended,
        Some("deleted")   => OrganizationStatus::Deleted,
        _ => {
            let orgs = CloudflareOrganizationRepository::new(&ctx.env);
            let org = match orgs.get(&oid).await {
                Ok(Some(o)) => o, _ => return Response::error("not found", 404),
            };
            let (csrf_token, csrf_cookie) = mint_csrf()?;
            let mut resp = render::html_response(|| form_page(
                &principal, &org, None, "", Some("Choose a target status"), &csrf_token,
            ))?;
            attach_csrf_cookie(&mut resp, &csrf_cookie);
            return Ok(resp);
        }
    };
    let reason = form.get("reason").cloned().unwrap_or_default();

    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let org = match orgs.get(&oid).await {
        Ok(Some(o)) => o, _ => return Response::error("not found", 404),
    };

    if reason.trim().is_empty() {
        let (csrf_token, csrf_cookie) = mint_csrf()?;
        let mut resp = render::html_response(|| form_page(
            &principal, &org, Some(target), "", Some("Reason is required"), &csrf_token,
        ))?;
        attach_csrf_cookie(&mut resp, &csrf_cookie);
        return Ok(resp);
    }

    if !confirmed(&form) {
        let (csrf_token, csrf_cookie) = mint_csrf()?;
        let mut resp = render::html_response(|| confirm_page(&principal, &org, target, &reason, &csrf_token))?;
        attach_csrf_cookie(&mut resp, &csrf_cookie);
        return Ok(resp);
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
