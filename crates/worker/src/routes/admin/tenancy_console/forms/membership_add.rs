//! Membership add form handlers.
//!
//! Three URL flavors:
//! - `GET/POST /admin/tenancy/tenants/:tid/memberships/new`
//! - `GET/POST /admin/tenancy/organizations/:oid/memberships/new`
//! - `GET/POST /admin/tenancy/groups/:gid/memberships/new`
//!
//! Each delegates to the existing v0.5.0 service layer +
//! `MembershipRepository` adapter from v0.6.0. One-click submit;
//! no preview/confirm step.

use cesauth_cf::tenancy::{
    CloudflareGroupRepository, CloudflareMembershipRepository,
    CloudflareOrganizationRepository, CloudflareTenantRepository,
};
use cesauth_core::ports::PortError;
use cesauth_core::tenancy::ports::{
    GroupRepository, MembershipRepository, OrganizationRepository, TenantRepository,
};
use cesauth_core::tenancy::types::{
    GroupMembership, OrganizationMembership, OrganizationRole,
    TenantMembership, TenantMembershipRole,
};
use cesauth_ui::tenancy_console::forms::membership_add as ui;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::console::render;
use crate::routes::admin::tenancy_console::forms::common::{parse_form, redirect_303, require_manage};

// =====================================================================
// Tenant membership
// =====================================================================

pub async fn form_tenant<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid") else { return Response::error("not found", 404); };
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let tenant = match tenants.get(tid).await {
        Ok(Some(t)) => t, _ => return Response::error("not found", 404),
    };
    render::html_response(ui::for_tenant(&principal, &tenant.id, &tenant.slug, "", "member", None))
}

pub async fn submit_tenant<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let form = parse_form(&mut req).await?;
    let user_id = form.get("user_id").cloned().unwrap_or_default();
    let role_str = form.get("role").cloned().unwrap_or_default();

    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let tenant = match tenants.get(&tid).await {
        Ok(Some(t)) => t, _ => return Response::error("not found", 404),
    };

    let role = match role_str.as_str() {
        "owner"  => TenantMembershipRole::Owner,
        "admin"  => TenantMembershipRole::Admin,
        "member" => TenantMembershipRole::Member,
        _ => return render::html_response(ui::for_tenant(
            &principal, &tenant.id, &tenant.slug, &user_id, &role_str,
            Some("Choose a role"),
        )),
    };
    if user_id.trim().is_empty() {
        return render::html_response(ui::for_tenant(
            &principal, &tenant.id, &tenant.slug, &user_id, &role_str,
            Some("User id is required"),
        ));
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let memberships = CloudflareMembershipRepository::new(&ctx.env);
    let m = TenantMembership {
        tenant_id: tid.clone(), user_id: user_id.clone(),
        role, joined_at: now,
    };
    if let Err(e) = memberships.add_tenant_membership(&m).await {
        let msg = match e {
            PortError::Conflict
                => "User is already a member of this tenant".to_owned(),
            PortError::NotFound
                => "User id not found".to_owned(),
            _ => "Storage error".to_owned(),
        };
        return render::html_response(ui::for_tenant(
            &principal, &tenant.id, &tenant.slug, &user_id, &role_str, Some(&msg),
        ));
    }

    audit::write_owned(
        &ctx.env, EventKind::MembershipAdded,
        Some(principal.id.clone()),
        Some(format!("tenant:{tid}/user:{user_id}")),
        Some(format!("via=tenancy-console,role={role_str}")),
    ).await.ok();

    redirect_303(&format!("/admin/tenancy/tenants/{tid}"))
}

// =====================================================================
// Organization membership
// =====================================================================

pub async fn form_org<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(oid) = ctx.param("oid") else { return Response::error("not found", 404); };
    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let org = match orgs.get(oid).await {
        Ok(Some(o)) => o, _ => return Response::error("not found", 404),
    };
    render::html_response(ui::for_organization(&principal, &org.id, &org.slug, "", "member", None))
}

pub async fn submit_org<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(oid) = ctx.param("oid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let form = parse_form(&mut req).await?;
    let user_id  = form.get("user_id").cloned().unwrap_or_default();
    let role_str = form.get("role").cloned().unwrap_or_default();

    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let org = match orgs.get(&oid).await {
        Ok(Some(o)) => o, _ => return Response::error("not found", 404),
    };

    let role = match role_str.as_str() {
        "admin"  => OrganizationRole::Admin,
        "member" => OrganizationRole::Member,
        _ => return render::html_response(ui::for_organization(
            &principal, &org.id, &org.slug, &user_id, &role_str,
            Some("Choose a role"),
        )),
    };
    if user_id.trim().is_empty() {
        return render::html_response(ui::for_organization(
            &principal, &org.id, &org.slug, &user_id, &role_str,
            Some("User id is required"),
        ));
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let memberships = CloudflareMembershipRepository::new(&ctx.env);
    let m = OrganizationMembership {
        organization_id: oid.clone(), user_id: user_id.clone(),
        role, joined_at: now,
    };
    if let Err(e) = memberships.add_organization_membership(&m).await {
        let msg = match e {
            PortError::Conflict
                => "User is already a member of this organization".to_owned(),
            PortError::NotFound
                => "User id not found".to_owned(),
            _ => "Storage error".to_owned(),
        };
        return render::html_response(ui::for_organization(
            &principal, &org.id, &org.slug, &user_id, &role_str, Some(&msg),
        ));
    }

    audit::write_owned(
        &ctx.env, EventKind::MembershipAdded,
        Some(principal.id.clone()),
        Some(format!("organization:{oid}/user:{user_id}")),
        Some(format!("via=tenancy-console,role={role_str}")),
    ).await.ok();

    redirect_303(&format!("/admin/tenancy/organizations/{oid}"))
}

// =====================================================================
// Group membership
// =====================================================================

pub async fn form_group<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(gid) = ctx.param("gid") else { return Response::error("not found", 404); };
    let groups = CloudflareGroupRepository::new(&ctx.env);
    let group = match groups.get(gid).await {
        Ok(Some(g)) => g, _ => return Response::error("not found", 404),
    };
    render::html_response(ui::for_group(
        &principal, &group.id, &group.slug, &group.tenant_id, "", None,
    ))
}

pub async fn submit_group<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(gid) = ctx.param("gid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let form = parse_form(&mut req).await?;
    let user_id = form.get("user_id").cloned().unwrap_or_default();

    let groups = CloudflareGroupRepository::new(&ctx.env);
    let group = match groups.get(&gid).await {
        Ok(Some(g)) => g, _ => return Response::error("not found", 404),
    };

    if user_id.trim().is_empty() {
        return render::html_response(ui::for_group(
            &principal, &group.id, &group.slug, &group.tenant_id, &user_id,
            Some("User id is required"),
        ));
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let memberships = CloudflareMembershipRepository::new(&ctx.env);
    let m = GroupMembership {
        group_id: gid.clone(), user_id: user_id.clone(),
        joined_at: now,
    };
    if let Err(e) = memberships.add_group_membership(&m).await {
        let msg = match e {
            PortError::Conflict
                => "User is already a member of this group".to_owned(),
            PortError::NotFound
                => "User id not found".to_owned(),
            _ => "Storage error".to_owned(),
        };
        return render::html_response(ui::for_group(
            &principal, &group.id, &group.slug, &group.tenant_id, &user_id, Some(&msg),
        ));
    }

    audit::write_owned(
        &ctx.env, EventKind::MembershipAdded,
        Some(principal.id.clone()),
        Some(format!("group:{gid}/user:{user_id}")),
        Some("via=tenancy-console".to_owned()),
    ).await.ok();

    redirect_303(&format!("/admin/tenancy/tenants/{}", group.tenant_id))
}
