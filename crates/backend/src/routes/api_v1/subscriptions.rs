//! Subscription route handlers.
//!
//! - `GET  /api/v1/tenants/:tid/subscription`
//! - `POST /api/v1/tenants/:tid/subscription/plan`     { plan_id }
//! - `POST /api/v1/tenants/:tid/subscription/status`   { status }
//!
//! Every change is recorded both in the live `subscriptions` row and
//! as an append-only `subscription_history` entry. The history shape
//! matches `SubscriptionHistoryEntry` and is the deterministic answer
//! to "when did this tenant move plans / statuses?".

use cesauth_cf::billing::{
    CloudflarePlanRepository, CloudflareSubscriptionHistoryRepository,
    CloudflareSubscriptionRepository,
};
use cesauth_core::admin::types::AdminAction;
use cesauth_core::billing::ports::{
    PlanRepository, SubscriptionHistoryRepository, SubscriptionRepository,
};
use cesauth_core::billing::types::{
    SubscriptionHistoryEntry, SubscriptionStatus,
};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::api_v1::auth::{
    bad_request, json, not_found, port_error_response, require,
};

pub async fn get<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if let Err(r) = require(AdminAction::ViewTenancy, &req, &ctx.env).await? {
        return Ok(r);
    }
    let Some(tid) = ctx.param("tid") else { return not_found(); };
    let subs = CloudflareSubscriptionRepository::new(&ctx.env);
    match subs.current_for_tenant(tid).await {
        Ok(Some(s)) => json(200, &s),
        Ok(None)    => not_found(),
        Err(e)      => port_error_response(e),
    }
}

#[derive(Deserialize)]
struct SetPlanBody { plan_id: String }

pub async fn set_plan<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else { return not_found(); };
    let body: SetPlanBody = match req.json().await {
        Ok(b) => b, Err(_) => return bad_request("invalid_json"),
    };

    let subs = CloudflareSubscriptionRepository::new(&ctx.env);
    let plans = CloudflarePlanRepository::new(&ctx.env);
    let history = CloudflareSubscriptionHistoryRepository::new(&ctx.env);
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // Look up the current row for the from-plan_id audit field.
    let current = match subs.current_for_tenant(&tid).await {
        Ok(Some(c)) => c,
        Ok(None)    => return not_found(),
        Err(e)      => return port_error_response(e),
    };

    // Refuse plan changes that point at a non-existent / archived plan.
    let target = match plans.get(&body.plan_id).await {
        Ok(Some(p)) => p,
        Ok(None)    => return bad_request("unknown plan_id"),
        Err(e)      => return port_error_response(e),
    };
    if !target.active {
        return bad_request("plan_inactive");
    }

    if let Err(e) = subs.set_plan(&current.id, &body.plan_id, now).await {
        return port_error_response(e);
    }
    history.append(&SubscriptionHistoryEntry {
        id:              Uuid::new_v4().to_string(),
        subscription_id: current.id.clone(),
        tenant_id:       tid.clone(),
        event:           "plan_changed".to_owned(),
        from_plan_id:    Some(current.plan_id.clone()),
        to_plan_id:      Some(body.plan_id.clone()),
        from_status:     None,
        to_status:       None,
        actor:           principal.id.clone(),
        occurred_at:     now,
    }).await.ok();

    audit::write_owned(
        &ctx.env, EventKind::SubscriptionPlanChanged,
        Some(principal.id.clone()), Some(tid.clone()),
        Some(format!("from={},to={}", current.plan_id, body.plan_id)),
    ).await.ok();

    match subs.current_for_tenant(&tid).await {
        Ok(Some(s)) => json(200, &s),
        Ok(None)    => not_found(),
        Err(e)      => port_error_response(e),
    }
}

#[derive(Deserialize)]
struct SetStatusBody { status: SubscriptionStatus }

pub async fn set_status<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else { return not_found(); };
    let body: SetStatusBody = match req.json().await {
        Ok(b) => b, Err(_) => return bad_request("invalid_json"),
    };

    let subs = CloudflareSubscriptionRepository::new(&ctx.env);
    let history = CloudflareSubscriptionHistoryRepository::new(&ctx.env);
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let current = match subs.current_for_tenant(&tid).await {
        Ok(Some(c)) => c,
        Ok(None)    => return not_found(),
        Err(e)      => return port_error_response(e),
    };

    if let Err(e) = subs.set_status(&current.id, body.status, now).await {
        return port_error_response(e);
    }
    history.append(&SubscriptionHistoryEntry {
        id:              Uuid::new_v4().to_string(),
        subscription_id: current.id.clone(),
        tenant_id:       tid.clone(),
        event:           "status_changed".to_owned(),
        from_plan_id:    None,
        to_plan_id:      None,
        from_status:     Some(current.status),
        to_status:       Some(body.status),
        actor:           principal.id.clone(),
        occurred_at:     now,
    }).await.ok();

    audit::write_owned(
        &ctx.env, EventKind::SubscriptionStatusChanged,
        Some(principal.id.clone()), Some(tid.clone()),
        Some(format!("from={:?},to={:?}", current.status, body.status).to_lowercase()),
    ).await.ok();

    match subs.current_for_tenant(&tid).await {
        Ok(Some(s)) => json(200, &s),
        Ok(None)    => not_found(),
        Err(e)      => port_error_response(e),
    }
}

pub async fn list_history<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if let Err(r) = require(AdminAction::ViewTenancy, &req, &ctx.env).await? {
        return Ok(r);
    }
    let Some(tid) = ctx.param("tid") else { return not_found(); };
    let subs = CloudflareSubscriptionRepository::new(&ctx.env);
    let history = CloudflareSubscriptionHistoryRepository::new(&ctx.env);

    let current = match subs.current_for_tenant(tid).await {
        Ok(Some(s)) => s,
        Ok(None)    => return not_found(),
        Err(e)      => return port_error_response(e),
    };
    match history.list_for_subscription(&current.id).await {
        Ok(rows) => json(200, &rows),
        Err(e)   => port_error_response(e),
    }
}
