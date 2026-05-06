//! `GET/POST /admin/tenancy/tenants/:tid/status` — tenant status change.
//!
//! Two phases per the v0.4.0 pattern: first POST without
//! `confirm=yes` shows the diff/preview; second POST with
//! `confirm=yes` commits.

use cesauth_cf::tenancy::CloudflareTenantRepository;
use cesauth_core::tenancy::ports::TenantRepository;
use cesauth_core::tenancy::types::TenantStatus;
use cesauth_ui::tenancy_console::forms::tenant_set_status::{confirm_page, form_page};
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
    let Some(tid) = ctx.param("tid") else { return Response::error("not found", 404); };

    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let tenant = match tenants.get(tid).await {
        Ok(Some(t)) => t,
        Ok(None)    => return Response::error("not found", 404),
        Err(_)      => return Response::error("storage error", 500),
    };
    render::html_response(form_page(&principal, &tenant, None, "", None))
}

pub async fn submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };

    let form = parse_form(&mut req).await?;
    let target = match form.get("status").map(String::as_str) {
        Some("active")    => TenantStatus::Active,
        Some("suspended") => TenantStatus::Suspended,
        Some("deleted")   => TenantStatus::Deleted,
        Some("pending")   => TenantStatus::Pending,
        _ => {
            // Render form with error.
            let tenants = CloudflareTenantRepository::new(&ctx.env);
            let tenant = match tenants.get(&tid).await {
                Ok(Some(t)) => t,
                _           => return Response::error("not found", 404),
            };
            return render::html_response(form_page(
                &principal, &tenant, None, "", Some("Choose a target status"),
            ));
        }
    };
    let reason = form.get("reason").cloned().unwrap_or_default();
    if reason.trim().is_empty() {
        let tenants = CloudflareTenantRepository::new(&ctx.env);
        let tenant = match tenants.get(&tid).await {
            Ok(Some(t)) => t,
            _           => return Response::error("not found", 404),
        };
        return render::html_response(form_page(
            &principal, &tenant, Some(target), "", Some("Reason is required"),
        ));
    }

    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let tenant = match tenants.get(&tid).await {
        Ok(Some(t)) => t,
        Ok(None)    => return Response::error("not found", 404),
        Err(_)      => return Response::error("storage error", 500),
    };

    if !confirmed(&form) {
        // Step 2: render the confirm page with the diff.
        return render::html_response(confirm_page(&principal, &tenant, target, &reason));
    }

    // Step 3: commit.
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if let Err(e) = tenants.set_status(&tid, target, now).await {
        worker::console_error!("tenant set_status failed: {e:?}");
        return Response::error("storage error", 500);
    }

    audit::write_owned(
        &ctx.env, EventKind::TenantStatusChanged,
        Some(principal.id.clone()), Some(tid.clone()),
        Some(format!("via=tenancy-console,target={:?},reason={}",
            target, reason).to_lowercase()),
    ).await.ok();

    redirect_303(&format!("/admin/tenancy/tenants/{tid}"))
}
