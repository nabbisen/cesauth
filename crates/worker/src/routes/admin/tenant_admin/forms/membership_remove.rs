//! Tenant-scoped membership remove handlers — three flavors.
//! One-step confirm: the GET renders the confirm page; the POST
//! removes (gated on `confirm=yes` so accidental form submission
//! doesn't go through).

use cesauth_cf::tenancy::{
    CloudflareGroupRepository, CloudflareMembershipRepository,
    CloudflareOrganizationRepository,
};
use cesauth_core::authz::types::{PermissionCatalog, ScopeRef};
use cesauth_core::tenancy::ports::{
    GroupRepository, MembershipRepository, OrganizationRepository,
};
use cesauth_core::tenancy::types::{GroupParent, TenantMembershipRole, OrganizationRole};
use cesauth_ui::tenant_admin::forms::membership_remove as ui;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenancy_console::forms::common::{confirmed, parse_form, redirect_303};
use crate::routes::admin::tenant_admin::gate;

// ---------------------------------------------------------------------
// Tenant membership
// ---------------------------------------------------------------------

pub async fn confirm_tenant<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c) => c, Err(r) => return Ok(r),
    };
    if let Err(r) = gate::check_action(
        &ctx_ta, PermissionCatalog::TENANT_MEMBER_REMOVE,
        ScopeRef::Tenant { tenant_id: &ctx_ta.tenant.id }, &ctx,
    ).await? { return Ok(r); }

    let uid = match ctx.param("uid") {
        Some(s) => s.clone(),
        None    => return Response::error("missing user id", 400),
    };

    let memberships = CloudflareMembershipRepository::new(&ctx.env);
    let role_label = memberships.list_tenant_members(&ctx_ta.tenant.id).await.ok()
        .and_then(|rows| rows.into_iter().find(|m| m.user_id == uid))
        .map(|m| match m.role {
            TenantMembershipRole::Owner  => "owner",
            TenantMembershipRole::Admin  => "admin",
            TenantMembershipRole::Member => "member",
        })
        .unwrap_or("(unknown)");

    render::html_response(ui::for_tenant(
        &ctx_ta.principal, &ctx_ta.tenant, &uid, role_label,
    ))
}

pub async fn submit_tenant<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c) => c, Err(r) => return Ok(r),
    };
    if let Err(r) = gate::check_action(
        &ctx_ta, PermissionCatalog::TENANT_MEMBER_REMOVE,
        ScopeRef::Tenant { tenant_id: &ctx_ta.tenant.id }, &ctx,
    ).await? { return Ok(r); }

    let uid = match ctx.param("uid") {
        Some(s) => s.clone(),
        None    => return Response::error("missing user id", 400),
    };
    let form = parse_form(&mut req).await?;
    if !confirmed(&form) {
        return render::html_response(ui::for_tenant(
            &ctx_ta.principal, &ctx_ta.tenant, &uid, "(unknown)",
        ));
    }

    let memberships = CloudflareMembershipRepository::new(&ctx.env);
    if let Err(e) = memberships.remove_tenant_membership(&ctx_ta.tenant.id, &uid).await {
        worker::console_error!("tenant membership remove failed: {e:?}");
        return Response::error("storage error", 500);
    }

    audit::write_owned(
        &ctx.env, EventKind::MembershipRemoved,
        Some(ctx_ta.principal.id.clone()),
        Some(format!("tenant:{}/user:{}", ctx_ta.tenant.id, uid)),
        Some(format!("via=tenant-admin,tenant={}", ctx_ta.tenant.id)),
    ).await.ok();

    redirect_303(&format!("/admin/t/{}", ctx_ta.tenant.slug))
}

// ---------------------------------------------------------------------
// Organization membership
// ---------------------------------------------------------------------

async fn gate_for_org<D>(
    req: &Request, ctx: &RouteContext<D>,
) -> Result<std::result::Result<(cesauth_core::tenant_admin::TenantAdminContext,
    cesauth_core::tenancy::types::Organization, String), Response>>
{
    let principal = match auth::resolve_or_respond(req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(Err(r)),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, ctx).await? {
        Ok(c) => c, Err(r) => return Ok(Err(r)),
    };
    if let Err(r) = gate::check_action(
        &ctx_ta, PermissionCatalog::ORGANIZATION_MEMBER_REMOVE,
        ScopeRef::Tenant { tenant_id: &ctx_ta.tenant.id }, ctx,
    ).await? { return Ok(Err(r)); }

    let oid = match ctx.param("oid") {
        Some(s) => s.clone(),
        None    => return Ok(Err(Response::error("missing organization id", 400)?)),
    };
    let uid = match ctx.param("uid") {
        Some(s) => s.clone(),
        None    => return Ok(Err(Response::error("missing user id", 400)?)),
    };
    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let org = match orgs.get(&oid).await {
        Ok(Some(o)) => o,
        _ => return Ok(Err(Response::error("organization not found", 404)?)),
    };
    if org.tenant_id != ctx_ta.tenant.id {
        return Ok(Err(Response::error(
            "organization belongs to a different tenant", 403)?));
    }
    Ok(Ok((ctx_ta, org, uid)))
}

pub async fn confirm_org<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, org, uid) = match gate_for_org(&req, &ctx).await? {
        Ok(t) => t, Err(r) => return Ok(r),
    };
    let memberships = CloudflareMembershipRepository::new(&ctx.env);
    let role_label = memberships.list_organization_members(&org.id).await.ok()
        .and_then(|rows| rows.into_iter().find(|m| m.user_id == uid))
        .map(|m| match m.role {
            OrganizationRole::Admin  => "admin",
            OrganizationRole::Member => "member",
        })
        .unwrap_or("(unknown)");
    render::html_response(ui::for_organization(
        &ctx_ta.principal, &ctx_ta.tenant,
        &org.id, &org.slug, &uid, role_label,
    ))
}

pub async fn submit_org<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, org, uid) = match gate_for_org(&req, &ctx).await? {
        Ok(t) => t, Err(r) => return Ok(r),
    };
    let form = parse_form(&mut req).await?;
    if !confirmed(&form) {
        return render::html_response(ui::for_organization(
            &ctx_ta.principal, &ctx_ta.tenant, &org.id, &org.slug, &uid, "(unknown)",
        ));
    }

    let memberships = CloudflareMembershipRepository::new(&ctx.env);
    if let Err(e) = memberships.remove_organization_membership(&org.id, &uid).await {
        worker::console_error!("org membership remove failed: {e:?}");
        return Response::error("storage error", 500);
    }

    audit::write_owned(
        &ctx.env, EventKind::MembershipRemoved,
        Some(ctx_ta.principal.id.clone()),
        Some(format!("organization:{}/user:{}", org.id, uid)),
        Some(format!("via=tenant-admin,tenant={}", ctx_ta.tenant.id)),
    ).await.ok();

    redirect_303(&format!("/admin/t/{}/organizations/{}", ctx_ta.tenant.slug, org.id))
}

// ---------------------------------------------------------------------
// Group membership
// ---------------------------------------------------------------------

async fn gate_for_group<D>(
    req: &Request, ctx: &RouteContext<D>,
) -> Result<std::result::Result<(cesauth_core::tenant_admin::TenantAdminContext,
    cesauth_core::tenancy::types::Group, String, String), Response>>
{
    let principal = match auth::resolve_or_respond(req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(Err(r)),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, ctx).await? {
        Ok(c) => c, Err(r) => return Ok(Err(r)),
    };
    if let Err(r) = gate::check_action(
        &ctx_ta, PermissionCatalog::GROUP_MEMBER_REMOVE,
        ScopeRef::Tenant { tenant_id: &ctx_ta.tenant.id }, ctx,
    ).await? { return Ok(Err(r)); }

    let gid = match ctx.param("gid") {
        Some(s) => s.clone(),
        None    => return Ok(Err(Response::error("missing group id", 400)?)),
    };
    let uid = match ctx.param("uid") {
        Some(s) => s.clone(),
        None    => return Ok(Err(Response::error("missing user id", 400)?)),
    };
    let groups = CloudflareGroupRepository::new(&ctx.env);
    let group = match groups.get(&gid).await {
        Ok(Some(g)) => g,
        _ => return Ok(Err(Response::error("group not found", 404)?)),
    };
    if group.tenant_id != ctx_ta.tenant.id {
        return Ok(Err(Response::error(
            "group belongs to a different tenant", 403)?));
    }
    let org_id = match &group.parent {
        GroupParent::Tenant => String::new(),
        GroupParent::Organization { organization_id } => organization_id.clone(),
    };
    Ok(Ok((ctx_ta, group, org_id, uid)))
}

pub async fn confirm_group<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, group, org_id, uid) = match gate_for_group(&req, &ctx).await? {
        Ok(t) => t, Err(r) => return Ok(r),
    };
    render::html_response(ui::for_group(
        &ctx_ta.principal, &ctx_ta.tenant,
        &group.id, &group.slug, &org_id, &uid,
    ))
}

pub async fn submit_group<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, group, org_id, uid) = match gate_for_group(&req, &ctx).await? {
        Ok(t) => t, Err(r) => return Ok(r),
    };
    let form = parse_form(&mut req).await?;
    if !confirmed(&form) {
        return render::html_response(ui::for_group(
            &ctx_ta.principal, &ctx_ta.tenant,
            &group.id, &group.slug, &org_id, &uid,
        ));
    }

    let memberships = CloudflareMembershipRepository::new(&ctx.env);
    if let Err(e) = memberships.remove_group_membership(&group.id, &uid).await {
        worker::console_error!("group membership remove failed: {e:?}");
        return Response::error("storage error", 500);
    }

    audit::write_owned(
        &ctx.env, EventKind::MembershipRemoved,
        Some(ctx_ta.principal.id.clone()),
        Some(format!("group:{}/user:{}", group.id, uid)),
        Some(format!("via=tenant-admin,tenant={}", ctx_ta.tenant.id)),
    ).await.ok();

    let return_to = if org_id.is_empty() {
        format!("/admin/t/{}/organizations", ctx_ta.tenant.slug)
    } else {
        format!("/admin/t/{}/organizations/{}", ctx_ta.tenant.slug, org_id)
    };
    redirect_303(&return_to)
}
