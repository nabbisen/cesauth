//! Membership remove handlers (three variants).
//!
//! GET path renders the confirm page; POST commits if the form
//! carried `confirm=yes`. Otherwise POST re-renders the confirm
//! page (defensive against operators bookmarking the POST URL).

use cesauth_cf::tenancy::{
    CloudflareGroupRepository, CloudflareMembershipRepository,
    CloudflareOrganizationRepository, CloudflareTenantRepository,
};
use cesauth_core::tenancy::ports::{
    GroupRepository, MembershipRepository, OrganizationRepository, TenantRepository,
};
use cesauth_ui::tenancy_console::forms::membership_remove as ui;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::console::render;
use crate::routes::admin::tenancy_console::forms::common::{
    confirmed, parse_form, redirect_303, require_manage,
};

// ----- Tenant membership -----

pub async fn confirm_tenant<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid") else { return Response::error("not found", 404); };
    let Some(uid) = ctx.param("uid") else { return Response::error("not found", 404); };
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let memberships = CloudflareMembershipRepository::new(&ctx.env);
    let tenant = match tenants.get(tid).await {
        Ok(Some(t)) => t, _ => return Response::error("not found", 404),
    };
    let role = memberships.list_tenant_members(tid).await.ok()
        .and_then(|rows| rows.into_iter().find(|m| m.user_id.as_str() == uid))
        .map(|m| match m.role {
            cesauth_core::tenancy::types::TenantMembershipRole::Owner  => "owner",
            cesauth_core::tenancy::types::TenantMembershipRole::Admin  => "admin",
            cesauth_core::tenancy::types::TenantMembershipRole::Member => "member",
        })
        .unwrap_or("(unknown)");
    render::html_response(ui::for_tenant(&principal, &tenant.id, &tenant.slug, uid, role))
}

pub async fn submit_tenant<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let Some(uid) = ctx.param("uid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let form = parse_form(&mut req).await?;

    if !confirmed(&form) {
        // No confirm — bounce back to confirm page.
        let tenants = CloudflareTenantRepository::new(&ctx.env);
        let tenant = match tenants.get(&tid).await {
            Ok(Some(t)) => t, _ => return Response::error("not found", 404),
        };
        return render::html_response(ui::for_tenant(&principal, &tenant.id, &tenant.slug, &uid, "(unknown)"));
    }

    let memberships = CloudflareMembershipRepository::new(&ctx.env);
    if let Err(e) = memberships.remove_tenant_membership(&tid, &uid).await {
        worker::console_error!("tenant membership remove failed: {e:?}");
        return Response::error("storage error", 500);
    }

    audit::write_owned(
        &ctx.env, EventKind::MembershipRemoved,
        Some(principal.id.clone()),
        Some(format!("tenant:{tid}/user:{uid}")),
        Some("via=tenancy-console".to_owned()),
    ).await.ok();

    redirect_303(&format!("/admin/tenancy/tenants/{tid}"))
}

// ----- Organization membership -----

pub async fn confirm_org<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(oid) = ctx.param("oid") else { return Response::error("not found", 404); };
    let Some(uid) = ctx.param("uid") else { return Response::error("not found", 404); };
    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let memberships = CloudflareMembershipRepository::new(&ctx.env);
    let org = match orgs.get(oid).await {
        Ok(Some(o)) => o, _ => return Response::error("not found", 404),
    };
    let role = memberships.list_organization_members(oid).await.ok()
        .and_then(|rows| rows.into_iter().find(|m| m.user_id.as_str() == uid))
        .map(|m| match m.role {
            cesauth_core::tenancy::types::OrganizationRole::Admin  => "admin",
            cesauth_core::tenancy::types::OrganizationRole::Member => "member",
        })
        .unwrap_or("(unknown)");
    render::html_response(ui::for_organization(&principal, &org.id, &org.slug, uid, role))
}

pub async fn submit_org<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(oid) = ctx.param("oid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let Some(uid) = ctx.param("uid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let form = parse_form(&mut req).await?;

    if !confirmed(&form) {
        let orgs = CloudflareOrganizationRepository::new(&ctx.env);
        let org = match orgs.get(&oid).await {
            Ok(Some(o)) => o, _ => return Response::error("not found", 404),
        };
        return render::html_response(ui::for_organization(&principal, &org.id, &org.slug, &uid, "(unknown)"));
    }

    let memberships = CloudflareMembershipRepository::new(&ctx.env);
    if let Err(e) = memberships.remove_organization_membership(&oid, &uid).await {
        worker::console_error!("org membership remove failed: {e:?}");
        return Response::error("storage error", 500);
    }

    audit::write_owned(
        &ctx.env, EventKind::MembershipRemoved,
        Some(principal.id.clone()),
        Some(format!("organization:{oid}/user:{uid}")),
        Some("via=tenancy-console".to_owned()),
    ).await.ok();

    redirect_303(&format!("/admin/tenancy/organizations/{oid}"))
}

// ----- Group membership -----

pub async fn confirm_group<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(gid) = ctx.param("gid") else { return Response::error("not found", 404); };
    let Some(uid) = ctx.param("uid") else { return Response::error("not found", 404); };
    let groups = CloudflareGroupRepository::new(&ctx.env);
    let group = match groups.get(gid).await {
        Ok(Some(g)) => g, _ => return Response::error("not found", 404),
    };
    render::html_response(ui::for_group(&principal, &group.id, &group.slug, &group.tenant_id, uid))
}

pub async fn submit_group<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(gid) = ctx.param("gid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let Some(uid) = ctx.param("uid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let form = parse_form(&mut req).await?;

    let groups = CloudflareGroupRepository::new(&ctx.env);
    let group = match groups.get(&gid).await {
        Ok(Some(g)) => g, _ => return Response::error("not found", 404),
    };

    if !confirmed(&form) {
        return render::html_response(ui::for_group(&principal, &group.id, &group.slug, &group.tenant_id, &uid));
    }

    let memberships = CloudflareMembershipRepository::new(&ctx.env);
    if let Err(e) = memberships.remove_group_membership(&gid, &uid).await {
        worker::console_error!("group membership remove failed: {e:?}");
        return Response::error("storage error", 500);
    }

    audit::write_owned(
        &ctx.env, EventKind::MembershipRemoved,
        Some(principal.id.clone()),
        Some(format!("group:{gid}/user:{uid}")),
        Some("via=tenancy-console".to_owned()),
    ).await.ok();

    redirect_303(&format!("/admin/tenancy/tenants/{}", group.tenant_id))
}
