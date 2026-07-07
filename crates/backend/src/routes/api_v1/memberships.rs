//! Membership route handlers — three relations under one file
//! because the trait surface is unified.
//!
//! - `POST /api/v1/tenants/:tid/memberships`         { user_id, role }
//! - `DELETE /api/v1/tenants/:tid/memberships/:uid`
//! - `POST /api/v1/organizations/:oid/memberships`   { user_id, role }
//! - `DELETE /api/v1/organizations/:oid/memberships/:uid`
//! - `POST /api/v1/groups/:gid/memberships`          { user_id }
//! - `DELETE /api/v1/groups/:gid/memberships/:uid`

use cesauth_cf::tenancy::CloudflareMembershipRepository;
use cesauth_core::admin::types::AdminAction;
use cesauth_core::tenancy::ports::MembershipRepository;
use cesauth_core::tenancy::types::{
    GroupMembership, OrganizationMembership, OrganizationRole,
    TenantMembership, TenantMembershipRole,
};
use serde::Deserialize;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::api_v1::auth::{
    bad_request, json, not_found, port_error_response, require,
};

// -------------------------------------------------------------------------
// Tenant memberships
// -------------------------------------------------------------------------

#[derive(Deserialize)]
struct AddTenantBody { user_id: String, role: TenantMembershipRole }

pub async fn add_tenant<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else { return not_found(); };
    let body: AddTenantBody = match req.json().await {
        Ok(b) => b, Err(_) => return bad_request("invalid_json"),
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let m = TenantMembership {
        tenant_id: tid.clone(), user_id: body.user_id.clone(),
        role: body.role, joined_at: now,
    };
    let repo = CloudflareMembershipRepository::new(&ctx.env);
    if let Err(e) = repo.add_tenant_membership(&m).await {
        return port_error_response(e);
    }
    audit::write_owned(
        &ctx.env, EventKind::MembershipAdded,
        Some(principal.id.clone()), Some(format!("tenant:{tid}/user:{}", body.user_id)),
        Some(format!("role={:?}", body.role).to_lowercase()),
    ).await.ok();
    json(201, &m)
}

pub async fn remove_tenant<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else { return not_found(); };
    let Some(uid) = ctx.param("uid").map(|s| s.to_owned()) else { return not_found(); };

    let repo = CloudflareMembershipRepository::new(&ctx.env);
    if let Err(e) = repo.remove_tenant_membership(&tid, &uid).await {
        return port_error_response(e);
    }
    audit::write_owned(
        &ctx.env, EventKind::MembershipRemoved,
        Some(principal.id.clone()), Some(format!("tenant:{tid}/user:{uid}")), None,
    ).await.ok();
    json(200, &serde_json::json!({ "ok": true }))
}

pub async fn list_tenant<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if let Err(r) = require(AdminAction::ViewTenancy, &req, &ctx.env).await? {
        return Ok(r);
    }
    let Some(tid) = ctx.param("tid") else { return not_found(); };
    let repo = CloudflareMembershipRepository::new(&ctx.env);
    match repo.list_tenant_members(tid).await {
        Ok(rows) => json(200, &rows),
        Err(e)   => port_error_response(e),
    }
}

// -------------------------------------------------------------------------
// Organization memberships
// -------------------------------------------------------------------------

#[derive(Deserialize)]
struct AddOrgBody { user_id: String, role: OrganizationRole }

pub async fn add_org<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(oid) = ctx.param("oid").map(|s| s.to_owned()) else { return not_found(); };
    let body: AddOrgBody = match req.json().await {
        Ok(b) => b, Err(_) => return bad_request("invalid_json"),
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let m = OrganizationMembership {
        organization_id: oid.clone(), user_id: body.user_id.clone(),
        role: body.role, joined_at: now,
    };
    let repo = CloudflareMembershipRepository::new(&ctx.env);
    if let Err(e) = repo.add_organization_membership(&m).await {
        return port_error_response(e);
    }
    audit::write_owned(
        &ctx.env, EventKind::MembershipAdded,
        Some(principal.id.clone()),
        Some(format!("organization:{oid}/user:{}", body.user_id)),
        Some(format!("role={:?}", body.role).to_lowercase()),
    ).await.ok();
    json(201, &m)
}

pub async fn remove_org<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(oid) = ctx.param("oid").map(|s| s.to_owned()) else { return not_found(); };
    let Some(uid) = ctx.param("uid").map(|s| s.to_owned()) else { return not_found(); };
    let repo = CloudflareMembershipRepository::new(&ctx.env);
    if let Err(e) = repo.remove_organization_membership(&oid, &uid).await {
        return port_error_response(e);
    }
    audit::write_owned(
        &ctx.env, EventKind::MembershipRemoved,
        Some(principal.id.clone()),
        Some(format!("organization:{oid}/user:{uid}")), None,
    ).await.ok();
    json(200, &serde_json::json!({ "ok": true }))
}

pub async fn list_org<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if let Err(r) = require(AdminAction::ViewTenancy, &req, &ctx.env).await? {
        return Ok(r);
    }
    let Some(oid) = ctx.param("oid") else { return not_found(); };
    let repo = CloudflareMembershipRepository::new(&ctx.env);
    match repo.list_organization_members(oid).await {
        Ok(rows) => json(200, &rows),
        Err(e)   => port_error_response(e),
    }
}

// -------------------------------------------------------------------------
// Group memberships
// -------------------------------------------------------------------------

#[derive(Deserialize)]
struct AddGroupBody { user_id: String }

pub async fn add_group<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(gid) = ctx.param("gid").map(|s| s.to_owned()) else { return not_found(); };
    let body: AddGroupBody = match req.json().await {
        Ok(b) => b, Err(_) => return bad_request("invalid_json"),
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let m = GroupMembership {
        group_id: gid.clone(), user_id: body.user_id.clone(), joined_at: now,
    };
    let repo = CloudflareMembershipRepository::new(&ctx.env);
    if let Err(e) = repo.add_group_membership(&m).await {
        return port_error_response(e);
    }
    audit::write_owned(
        &ctx.env, EventKind::MembershipAdded,
        Some(principal.id.clone()),
        Some(format!("group:{gid}/user:{}", body.user_id)), None,
    ).await.ok();
    json(201, &m)
}

pub async fn remove_group<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(gid) = ctx.param("gid").map(|s| s.to_owned()) else { return not_found(); };
    let Some(uid) = ctx.param("uid").map(|s| s.to_owned()) else { return not_found(); };
    let repo = CloudflareMembershipRepository::new(&ctx.env);
    if let Err(e) = repo.remove_group_membership(&gid, &uid).await {
        return port_error_response(e);
    }
    audit::write_owned(
        &ctx.env, EventKind::MembershipRemoved,
        Some(principal.id.clone()),
        Some(format!("group:{gid}/user:{uid}")), None,
    ).await.ok();
    json(200, &serde_json::json!({ "ok": true }))
}

pub async fn list_group<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if let Err(r) = require(AdminAction::ViewTenancy, &req, &ctx.env).await? {
        return Ok(r);
    }
    let Some(gid) = ctx.param("gid") else { return not_found(); };
    let repo = CloudflareMembershipRepository::new(&ctx.env);
    match repo.list_group_members(gid).await {
        Ok(rows) => json(200, &rows),
        Err(e)   => port_error_response(e),
    }
}
