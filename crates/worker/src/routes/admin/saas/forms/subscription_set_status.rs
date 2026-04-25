//! `GET/POST /admin/saas/tenants/:tid/subscription/status`.

use cesauth_cf::billing::{
    CloudflareSubscriptionHistoryRepository, CloudflareSubscriptionRepository,
};
use cesauth_cf::tenancy::CloudflareTenantRepository;
use cesauth_core::billing::ports::{SubscriptionHistoryRepository, SubscriptionRepository};
use cesauth_core::billing::types::{SubscriptionHistoryEntry, SubscriptionStatus};
use cesauth_core::tenancy::ports::TenantRepository;
use cesauth_ui::saas::forms::subscription_set_status::{confirm_page, form_page};
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::console::render;
use crate::routes::admin::saas::forms::common::{
    confirmed, parse_form, redirect_303, require_manage,
};

pub async fn form<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid") else { return Response::error("not found", 404); };
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let tenant = match tenants.get(tid).await {
        Ok(Some(t)) => t, _ => return Response::error("not found", 404),
    };
    let subs = CloudflareSubscriptionRepository::new(&ctx.env);
    let current = match subs.current_for_tenant(&tenant.id).await {
        Ok(Some(s)) => s,
        Ok(None)    => return Response::error("no subscription on file", 404),
        Err(_)      => return Response::error("storage error", 500),
    };
    render::html_response(form_page(
        &principal, &tenant.id, &tenant.slug, &current, None, None,
    ))
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
        Some("active")    => SubscriptionStatus::Active,
        Some("past_due")  => SubscriptionStatus::PastDue,
        Some("cancelled") => SubscriptionStatus::Cancelled,
        Some("expired")   => SubscriptionStatus::Expired,
        _ => {
            let tenants = CloudflareTenantRepository::new(&ctx.env);
            let tenant = match tenants.get(&tid).await {
                Ok(Some(t)) => t, _ => return Response::error("not found", 404),
            };
            let subs = CloudflareSubscriptionRepository::new(&ctx.env);
            let current = match subs.current_for_tenant(&tid).await {
                Ok(Some(s)) => s,
                _ => return Response::error("no subscription on file", 404),
            };
            return render::html_response(form_page(
                &principal, &tenant.id, &tenant.slug, &current, None,
                Some("Choose a target status"),
            ));
        }
    };

    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let tenant = match tenants.get(&tid).await {
        Ok(Some(t)) => t, _ => return Response::error("not found", 404),
    };
    let subs = CloudflareSubscriptionRepository::new(&ctx.env);
    let current = match subs.current_for_tenant(&tid).await {
        Ok(Some(s)) => s,
        _ => return Response::error("no subscription on file", 404),
    };

    if !confirmed(&form) {
        return render::html_response(confirm_page(
            &principal, &tenant.id, &tenant.slug, &current, target,
        ));
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    if let Err(e) = subs.set_status(&current.id, target, now).await {
        worker::console_error!("subscription set_status failed: {e:?}");
        return Response::error("storage error", 500);
    }

    let history = CloudflareSubscriptionHistoryRepository::new(&ctx.env);
    history.append(&SubscriptionHistoryEntry {
        id:              Uuid::new_v4().to_string(),
        subscription_id: current.id.clone(),
        tenant_id:       tid.clone(),
        event:           "status_changed".to_owned(),
        from_plan_id:    None,
        to_plan_id:      None,
        from_status:     Some(current.status),
        to_status:       Some(target),
        actor:           principal.id.clone(),
        occurred_at:     now,
    }).await.ok();

    audit::write_owned(
        &ctx.env, EventKind::SubscriptionStatusChanged,
        Some(principal.id.clone()), Some(tid.clone()),
        Some(format!("via=saas-console,from={:?},to={:?}",
            current.status, target).to_lowercase()),
    ).await.ok();

    redirect_303(&format!("/admin/saas/tenants/{tid}"))
}
