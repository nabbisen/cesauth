//! `GET/POST /admin/tenancy/tenants/:tid/subscription/plan`.

use cesauth_cf::billing::{
    CloudflarePlanRepository, CloudflareSubscriptionHistoryRepository,
    CloudflareSubscriptionRepository,
};
use cesauth_cf::tenancy::CloudflareTenantRepository;
use cesauth_core::billing::ports::{PlanRepository, SubscriptionHistoryRepository, SubscriptionRepository};
use cesauth_core::billing::types::SubscriptionHistoryEntry;
use cesauth_core::tenancy::ports::TenantRepository;
use cesauth_frontend::tenancy_console::forms::subscription_set_plan::{confirm_page, form_page};
use time::OffsetDateTime;
use uuid::Uuid;
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
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let tenant = match tenants.get(&tid).await {
        Ok(Some(t)) => t, _ => return Response::error("not found", 404),
    };
    let subs = CloudflareSubscriptionRepository::new(&ctx.env);
    let current = match subs.current_for_tenant(&tid).await {
        Ok(Some(s)) => s,
        Ok(None)    => return Response::error("no subscription on file", 404),
        Err(_)      => return Response::error("storage error", 500),
    };
    let plans = CloudflarePlanRepository::new(&ctx.env);
    let current_plan = plans.get(&current.plan_id).await.ok().flatten();
    let available = plans.list_active().await.unwrap_or_default();
    let (csrf_token, csrf_cookie) = mint_csrf()?;
    let mut resp = render::html_response(|| form_page(
        &principal, &tenant.id, &tenant.slug, &current,
        current_plan.as_ref(), &available, "", None, &csrf_token,
    ))?;
    attach_csrf_cookie(&mut resp, &csrf_cookie);
    Ok(resp)
}

pub async fn submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };

    let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();
    let form = parse_form(&mut req).await?;
    if !verify_csrf(&form, &cookie_header) {
        return Response::error("Bad Request", 400);
    }
    let plan_id = form.get("plan_id").cloned().unwrap_or_default();

    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let tenant = match tenants.get(&tid).await {
        Ok(Some(t)) => t, _ => return Response::error("not found", 404),
    };
    let subs = CloudflareSubscriptionRepository::new(&ctx.env);
    let plans = CloudflarePlanRepository::new(&ctx.env);
    let current = match subs.current_for_tenant(&tid).await {
        Ok(Some(s)) => s,
        Ok(None)    => return Response::error("no subscription on file", 404),
        Err(_)      => return Response::error("storage error", 500),
    };
    let current_plan = plans.get(&current.plan_id).await.ok().flatten();

    if plan_id.trim().is_empty() {
        let available = plans.list_active().await.unwrap_or_default();
        let (csrf_token, csrf_cookie) = mint_csrf()?;
        let mut resp = render::html_response(|| form_page(
            &principal, &tenant.id, &tenant.slug, &current,
            current_plan.as_ref(), &available, "",
            Some("Select a target plan"), &csrf_token,
        ))?;
        attach_csrf_cookie(&mut resp, &csrf_cookie);
        return Ok(resp);
    }

    let target_plan = match plans.get(&plan_id).await.ok().flatten() {
        Some(p) => p,
        None => {
            let available = plans.list_active().await.unwrap_or_default();
            let (csrf_token, csrf_cookie) = mint_csrf()?;
            let mut resp = render::html_response(|| form_page(
                &principal, &tenant.id, &tenant.slug, &current,
                current_plan.as_ref(), &available, &plan_id,
                Some("Unknown plan id"), &csrf_token,
            ))?;
            attach_csrf_cookie(&mut resp, &csrf_cookie);
            return Ok(resp);
        }
    };

    if !confirmed(&form) {
        let (csrf_token, csrf_cookie) = mint_csrf()?;
        let mut resp = render::html_response(|| confirm_page(
            &principal, &tenant.id, &tenant.slug, current_plan.as_ref(), &target_plan, &csrf_token,
        ))?;
        attach_csrf_cookie(&mut resp, &csrf_cookie);
        return Ok(resp);
    }

    if !target_plan.active {
        let available = plans.list_active().await.unwrap_or_default();
        let (csrf_token, csrf_cookie) = mint_csrf()?;
        let mut resp = render::html_response(|| form_page(
            &principal, &tenant.id, &tenant.slug, &current,
            current_plan.as_ref(), &available, &plan_id,
            Some("Target plan is inactive — refusing"), &csrf_token,
        ))?;
        attach_csrf_cookie(&mut resp, &csrf_cookie);
        return Ok(resp);
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    if let Err(e) = subs.set_plan(&current.id, &plan_id, now).await {
        worker::console_error!("subscription set_plan failed: {e:?}");
        return Response::error("storage error", 500);
    }

    let history = CloudflareSubscriptionHistoryRepository::new(&ctx.env);
    history.append(&SubscriptionHistoryEntry {
        id:              Uuid::new_v4().to_string(),
        subscription_id: current.id.clone(),
        tenant_id:       tid.clone(),
        event:           "plan_changed".to_owned(),
        from_plan_id:    Some(current.plan_id.clone()),
        to_plan_id:      Some(plan_id.clone()),
        from_status:     None,
        to_status:       None,
        actor:           principal.id.clone(),
        occurred_at:     now,
    }).await.ok();

    audit::write_owned(
        &ctx.env, EventKind::SubscriptionPlanChanged,
        Some(principal.id.clone()), Some(tid.clone()),
        Some(format!("via=tenancy-console,from={},to={}", current.plan_id, plan_id)),
    ).await.ok();

    redirect_303(&format!("/admin/tenancy/tenants/{tid}"))
}
