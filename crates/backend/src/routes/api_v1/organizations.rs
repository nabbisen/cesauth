//! `/api/v1/tenants/:tid/organizations/...` route handlers.

use cesauth_cf::tenancy::{
    CloudflareOrganizationRepository, CloudflareTenantRepository,
};
use cesauth_core::admin::types::AdminAction;
use cesauth_core::tenancy::ports::OrganizationRepository;
use cesauth_core::tenancy::service::create_organization;
use cesauth_core::tenancy::types::OrganizationStatus;
use serde::Deserialize;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::api_v1::auth::{
    bad_request, conflict, json, not_found, port_error_response, require,
};
use crate::routes::api_v1::quota;

#[derive(Deserialize)]
struct CreateOrgBody {
    slug:         String,
    display_name: String,
}

pub async fn create<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else { return not_found(); };
    let body: CreateOrgBody = match req.json().await {
        Ok(b) => b, Err(_) => return bad_request("invalid_json"),
    };

    // Plan-quota: max_organizations.
    let current = match quota::count_organizations(&ctx.env, &tid).await {
        Ok(n)  => n,
        Err(e) => return port_error_response(e),
    };
    let outcome = match quota::check_quota(&ctx.env, &tid, "max_organizations", current).await {
        Ok(o)  => o,
        Err(e) => return port_error_response(e),
    };
    if let Some(resp) = quota::into_response_if_exceeded(outcome) {
        return resp;
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let orgs    = CloudflareOrganizationRepository::new(&ctx.env);

    let org = match create_organization(
        &tenants, &orgs, &tid, &body.slug, &body.display_name, now,
    ).await {
        Ok(o)  => o,
        Err(e) => return port_error_response(e),
    };

    audit::write_owned(
        &ctx.env, EventKind::OrganizationCreated,
        Some(principal.id.clone()), Some(org.id.clone()),
        Some(format!("tenant={tid},slug={}", org.slug)),
    ).await.ok();

    json(201, &org)
}

pub async fn list<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if let Err(r) = require(AdminAction::ViewTenancy, &req, &ctx.env).await? {
        return Ok(r);
    }
    let Some(tid) = ctx.param("tid") else { return not_found(); };
    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    match orgs.list_for_tenant(tid).await {
        Ok(rows) => json(200, &rows),
        Err(e)   => port_error_response(e),
    }
}

pub async fn get<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if let Err(r) = require(AdminAction::ViewTenancy, &req, &ctx.env).await? {
        return Ok(r);
    }
    let Some(oid) = ctx.param("oid") else { return not_found(); };
    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    match orgs.get(oid).await {
        Ok(Some(o)) => {
            // Defense in depth: confirm the org belongs to the
            // tenant in the URL. Without this check, a caller with
            // any tenant access could read an org belonging to
            // another tenant by guessing its id.
            if let Some(tid) = ctx.param("tid") {
                if o.tenant_id.as_str() != tid {
                    return not_found();
                }
            }
            json(200, &o)
        }
        Ok(None) => not_found(),
        Err(e)   => port_error_response(e),
    }
}

#[derive(Deserialize)]
struct UpdateOrgBody { display_name: Option<String> }

pub async fn update<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(oid) = ctx.param("oid").map(|s| s.to_owned()) else { return not_found(); };
    let body: UpdateOrgBody = match req.json().await {
        Ok(b) => b, Err(_) => return bad_request("invalid_json"),
    };

    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if let Some(name) = body.display_name {
        if let Err(e) = orgs.update_display_name(&oid, &name, now).await {
            return port_error_response(e);
        }
    }
    audit::write_owned(
        &ctx.env, EventKind::OrganizationUpdated,
        Some(principal.id.clone()), Some(oid.clone()), None,
    ).await.ok();

    match orgs.get(&oid).await {
        Ok(Some(o)) => json(200, &o),
        Ok(None)    => not_found(),
        Err(e)      => port_error_response(e),
    }
}

#[derive(Deserialize)]
struct StatusBody { status: OrganizationStatus }

pub async fn set_status<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(oid) = ctx.param("oid").map(|s| s.to_owned()) else { return not_found(); };
    let body: StatusBody = match req.json().await {
        Ok(b) => b, Err(_) => return bad_request("invalid_json"),
    };

    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if let Err(e) = orgs.set_status(&oid, body.status, now).await {
        return port_error_response(e);
    }
    audit::write_owned(
        &ctx.env, EventKind::OrganizationStatusChanged,
        Some(principal.id.clone()), Some(oid.clone()),
        Some(format!("{:?}", body.status).to_lowercase()),
    ).await.ok();

    match orgs.get(&oid).await {
        Ok(Some(o)) => json(200, &o),
        Ok(None)    => not_found(),
        Err(e)      => port_error_response(e),
    }
}

// Suppress the unused-import warning when the `conflict` helper isn't
// reached on a specific build (PortError::Conflict from the service
// already maps via port_error_response). It's still useful as
// vocabulary in this file.
#[allow(dead_code)] fn _conflict_alias(s: &str) -> Result<Response> { conflict(s) }
