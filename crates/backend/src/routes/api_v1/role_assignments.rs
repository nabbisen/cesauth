//! Role-assignment route handlers.
//!
//! - `POST   /api/v1/role_assignments`        { user_id, role_id, scope, expires_at? }
//! - `DELETE /api/v1/role_assignments/:id`
//! - `GET    /api/v1/users/:uid/role_assignments`

use cesauth_cf::authz::CloudflareRoleAssignmentRepository;
use cesauth_core::admin::types::AdminAction;
use cesauth_core::authz::ports::RoleAssignmentRepository;
use cesauth_core::authz::types::{RoleAssignment, Scope};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::api_v1::auth::{
    bad_request, json, not_found, port_error_response, require,
};

#[derive(Deserialize)]
struct CreateBody {
    user_id:    String,
    role_id:    String,
    scope:      Scope,
    expires_at: Option<i64>,
}

pub async fn create<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let body: CreateBody = match req.json().await {
        Ok(b) => b, Err(_) => return bad_request("invalid_json"),
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let assignment = RoleAssignment {
        id:         Uuid::new_v4().to_string(),
        user_id:    body.user_id.clone(),
        role_id:    body.role_id.clone(),
        scope:      body.scope.clone(),
        granted_by: principal.id.clone(),
        granted_at: now,
        expires_at: body.expires_at,
    };

    let repo = CloudflareRoleAssignmentRepository::new(&ctx.env);
    if let Err(e) = repo.create(&assignment).await {
        return port_error_response(e);
    }

    audit::write_owned(
        &ctx.env, EventKind::RoleGranted,
        Some(principal.id.clone()), Some(assignment.id.clone()),
        Some(format!("user={},role={}", body.user_id, body.role_id)),
    ).await.ok();

    json(201, &assignment)
}

pub async fn delete<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(id) = ctx.param("id").map(|s| s.to_owned()) else { return not_found(); };

    let repo = CloudflareRoleAssignmentRepository::new(&ctx.env);
    // delete is idempotent at the port level; we record an audit event
    // in either case.
    if let Err(e) = repo.delete(&id).await {
        return port_error_response(e);
    }
    audit::write_owned(
        &ctx.env, EventKind::RoleRevoked,
        Some(principal.id.clone()), Some(id.clone()), None,
    ).await.ok();
    json(200, &serde_json::json!({ "ok": true, "id": id }))
}

pub async fn list_for_user<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if let Err(r) = require(AdminAction::ViewTenancy, &req, &ctx.env).await? {
        return Ok(r);
    }
    let Some(uid) = ctx.param("uid") else { return not_found(); };
    let repo = CloudflareRoleAssignmentRepository::new(&ctx.env);
    match repo.list_for_user(uid).await {
        Ok(rows) => json(200, &rows),
        Err(e)   => port_error_response(e),
    }
}
