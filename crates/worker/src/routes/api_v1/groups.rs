//! `/api/v1/tenants/:tid/groups/...` route handlers.

use cesauth_cf::tenancy::CloudflareGroupRepository;
use cesauth_core::admin::types::AdminAction;
use cesauth_core::tenancy::ports::{GroupRepository, NewGroupInput};
use cesauth_core::tenancy::service::create_group;
use cesauth_core::tenancy::types::GroupParent;
use serde::Deserialize;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::api_v1::auth::{
    bad_request, json, not_found, port_error_response, require,
};
use crate::routes::api_v1::quota::{self};

#[derive(Deserialize)]
struct CreateGroupBody {
    /// `tenant` for tenant-wide groups; `organization` for org-scoped.
    parent_kind:     String,
    /// Required when `parent_kind == "organization"`; ignored
    /// otherwise.
    organization_id: Option<String>,
    slug:            String,
    display_name:    String,
}

pub async fn create<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else { return not_found(); };
    let body: CreateGroupBody = match req.json().await {
        Ok(b) => b, Err(_) => return bad_request("invalid_json"),
    };

    let parent = match (body.parent_kind.as_str(), body.organization_id.as_deref()) {
        ("tenant",       _)        => GroupParent::Tenant,
        ("organization", Some(o))  => GroupParent::Organization { organization_id: o.to_owned() },
        ("organization", None)     => return bad_request("organization_id required for parent_kind=organization"),
        _                          => return bad_request("invalid parent_kind"),
    };

    // Plan-quota: max_groups, counted across the whole tenant
    // regardless of the group's parent flavor.
    let current = match quota::count_groups(&ctx.env, &tid).await {
        Ok(n)  => n,
        Err(e) => return port_error_response(e),
    };
    let outcome = match quota::check_quota(&ctx.env, &tid, "max_groups", current).await {
        Ok(o)  => o,
        Err(e) => return port_error_response(e),
    };
    if let Some(resp) = quota::into_response_if_exceeded(outcome) {
        return resp;
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let groups = CloudflareGroupRepository::new(&ctx.env);

    let group = match create_group(&groups, &NewGroupInput {
        tenant_id:    &tid,
        parent,
        slug:         &body.slug,
        display_name: &body.display_name,
    }, now).await {
        Ok(g)  => g,
        Err(e) => return port_error_response(e),
    };

    audit::write_owned(
        &ctx.env, EventKind::GroupCreated,
        Some(principal.id.clone()), Some(group.id.clone()),
        Some(format!("tenant={tid},slug={}", group.slug)),
    ).await.ok();

    json(201, &group)
}

pub async fn list<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if let Err(r) = require(AdminAction::ViewTenancy, &req, &ctx.env).await? {
        return Ok(r);
    }
    let Some(tid) = ctx.param("tid") else { return not_found(); };
    let groups = CloudflareGroupRepository::new(&ctx.env);

    // ?organization_id=... narrows to org-scoped groups; otherwise
    // returns the tenant-scoped set. Listing every group regardless
    // of parent is intentionally not exposed (callers either want
    // "tenant-wide groups" or "this org's groups").
    let url = req.url()?;
    let qp = url.query_pairs().find(|(k, _)| k == "organization_id")
        .map(|(_, v)| v.into_owned());

    let result = match qp {
        Some(o) => groups.list_for_organization(&o).await,
        None    => groups.list_tenant_scoped(tid).await,
    };
    match result {
        Ok(rows) => json(200, &rows),
        Err(e)   => port_error_response(e),
    }
}

pub async fn delete<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(gid) = ctx.param("gid").map(|s| s.to_owned()) else { return not_found(); };
    let groups = CloudflareGroupRepository::new(&ctx.env);
    let now = OffsetDateTime::now_utc().unix_timestamp();

    if let Err(e) = groups.delete(&gid, now).await {
        return port_error_response(e);
    }

    audit::write_owned(
        &ctx.env, EventKind::GroupDeleted,
        Some(principal.id.clone()), Some(gid.clone()), None,
    ).await.ok();

    json(200, &serde_json::json!({ "ok": true, "id": gid }))
}
