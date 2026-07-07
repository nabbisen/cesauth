//! `/api/v1/tenants/...` route handlers.

use cesauth_cf::tenancy::{
    CloudflareMembershipRepository, CloudflareTenantRepository,
};
use cesauth_core::admin::types::AdminAction;
use cesauth_core::ports::PortError;
use cesauth_core::tenancy::ports::{NewTenantInput, TenantRepository};
use cesauth_core::tenancy::service::create_tenant;
use cesauth_core::tenancy::types::{TenantMembershipRole, TenantStatus};
use serde::Deserialize;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::api_v1::auth::{
    bad_request, json, not_found, port_error_response, require,
};

// -------------------------------------------------------------------------
// POST /api/v1/tenants
// -------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateTenantBody {
    slug:          String,
    display_name:  String,
    /// The user who becomes the new tenant's owner. Required because
    /// the spec §8.1 forbids tenants without an owner. The user
    /// id MUST already exist in `users`; the API does not auto-
    /// create users.
    owner_user_id: String,
}

pub async fn create<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let body: CreateTenantBody = match req.json().await {
        Ok(b)  => b,
        Err(_) => return bad_request("invalid_json"),
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let members = CloudflareMembershipRepository::new(&ctx.env);

    let tenant = match create_tenant(&tenants, &members, &NewTenantInput {
        slug:          &body.slug,
        display_name:  &body.display_name,
        owner_user_id: &body.owner_user_id,
        owner_role:    TenantMembershipRole::Owner,
    }, now).await {
        Ok(t)  => t,
        Err(e) => return port_error_response(e),
    };

    audit::write_owned(
        &ctx.env, EventKind::TenantCreated,
        Some(principal.id.clone()), Some(tenant.id.clone()),
        Some(format!("slug={}", tenant.slug)),
    ).await.ok();

    json(201, &tenant)
}

// -------------------------------------------------------------------------
// GET /api/v1/tenants
// -------------------------------------------------------------------------

pub async fn list<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if let Err(r) = require(AdminAction::ViewTenancy, &req, &ctx.env).await? {
        return Ok(r);
    }
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    match tenants.list_active().await {
        Ok(rows) => json(200, &rows),
        Err(e)   => port_error_response(e),
    }
}

// -------------------------------------------------------------------------
// GET /api/v1/tenants/:tid
// -------------------------------------------------------------------------

pub async fn get<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if let Err(r) = require(AdminAction::ViewTenancy, &req, &ctx.env).await? {
        return Ok(r);
    }
    let Some(tid) = ctx.param("tid") else { return not_found(); };
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    match tenants.get(tid).await {
        Ok(Some(t)) => json(200, &t),
        Ok(None)    => not_found(),
        Err(e)      => port_error_response(e),
    }
}

// -------------------------------------------------------------------------
// PATCH /api/v1/tenants/:tid
// -------------------------------------------------------------------------

#[derive(Deserialize)]
struct UpdateTenantBody {
    display_name: Option<String>,
}

pub async fn update<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else { return not_found(); };
    let body: UpdateTenantBody = match req.json().await {
        Ok(b) => b, Err(_) => return bad_request("invalid_json"),
    };

    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let now = OffsetDateTime::now_utc().unix_timestamp();

    if let Some(name) = body.display_name {
        if let Err(e) = tenants.update_display_name(&tid, &name, now).await {
            return port_error_response(e);
        }
    }

    audit::write_owned(
        &ctx.env, EventKind::TenantUpdated,
        Some(principal.id.clone()), Some(tid.clone()), None,
    ).await.ok();

    match tenants.get(&tid).await {
        Ok(Some(t)) => json(200, &t),
        Ok(None)    => not_found(),
        Err(e)      => port_error_response(e),
    }
}

// -------------------------------------------------------------------------
// POST /api/v1/tenants/:tid/status
// -------------------------------------------------------------------------

#[derive(Deserialize)]
struct StatusBody { status: TenantStatus }

pub async fn set_status<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else { return not_found(); };
    let body: StatusBody = match req.json().await {
        Ok(b) => b, Err(_) => return bad_request("invalid_json"),
    };

    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if let Err(e) = tenants.set_status(&tid, body.status, now).await {
        return match e {
            PortError::NotFound => not_found(),
            other => port_error_response(other),
        };
    }

    audit::write_owned(
        &ctx.env, EventKind::TenantStatusChanged,
        Some(principal.id.clone()), Some(tid.clone()),
        Some(format!("{:?}", body.status).to_lowercase()),
    ).await.ok();

    match tenants.get(&tid).await {
        Ok(Some(t)) => json(200, &t),
        Ok(None)    => not_found(),
        Err(e)      => port_error_response(e),
    }
}
