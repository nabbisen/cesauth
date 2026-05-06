//! Tenant-scoped membership add handlers — three flavors:
//! tenant / organization / group.
//!
//! Each handler runs the same opening sequence (auth → gate →
//! check_action with the relevant `*_MEMBER_ADD` permission) before
//! delegating to `MembershipRepository::add_*`. Defense-in-depth on
//! every child resource the URL points at: organization/group/user
//! must belong to the current tenant.
//!
//! Memberships are additive — `Conflict` from the repository is
//! mapped to a friendly "user is already a member" message rather
//! than a 500.

use cesauth_cf::ports::repo::CloudflareUserRepository;
use cesauth_cf::tenancy::{
    CloudflareGroupRepository, CloudflareMembershipRepository,
    CloudflareOrganizationRepository,
};
use cesauth_core::authz::types::{PermissionCatalog, ScopeRef};
use cesauth_core::ports::PortError;
use cesauth_core::ports::repo::UserRepository;
use cesauth_core::tenancy::ports::{
    GroupRepository, MembershipRepository, OrganizationRepository,
};
use cesauth_core::tenancy::types::{
    GroupMembership, GroupParent, OrganizationMembership, OrganizationRole,
    TenantMembership, TenantMembershipRole,
};
use cesauth_ui::tenant_admin::forms::membership_add as ui;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenancy_console::forms::common::{parse_form, redirect_303};
use crate::routes::admin::tenant_admin::gate;

// ---------------------------------------------------------------------
// Tenant membership
// ---------------------------------------------------------------------

pub async fn form_tenant<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c) => c, Err(r) => return Ok(r),
    };
    if let Err(r) = gate::check_action(
        &ctx_ta, PermissionCatalog::TENANT_MEMBER_ADD,
        ScopeRef::Tenant { tenant_id: &ctx_ta.tenant.id }, &ctx,
    ).await? { return Ok(r); }

    render::html_response(ui::for_tenant(
        &ctx_ta.principal, &ctx_ta.tenant, "", "member", None,
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
        &ctx_ta, PermissionCatalog::TENANT_MEMBER_ADD,
        ScopeRef::Tenant { tenant_id: &ctx_ta.tenant.id }, &ctx,
    ).await? { return Ok(r); }

    let form = parse_form(&mut req).await?;
    let user_id  = form.get("user_id").cloned().unwrap_or_default();
    let role_str = form.get("role").cloned().unwrap_or_default();

    let role = match role_str.as_str() {
        "owner"  => TenantMembershipRole::Owner,
        "admin"  => TenantMembershipRole::Admin,
        "member" => TenantMembershipRole::Member,
        _ => return render::html_response(ui::for_tenant(
            &ctx_ta.principal, &ctx_ta.tenant, &user_id, &role_str,
            Some("Choose a role"),
        )),
    };
    if user_id.trim().is_empty() {
        return render::html_response(ui::for_tenant(
            &ctx_ta.principal, &ctx_ta.tenant, &user_id, &role_str,
            Some("User id is required"),
        ));
    }

    // Defense in depth: the user must belong to this tenant.
    if let Some(resp) = verify_user_in_tenant(&ctx.env, &user_id, &ctx_ta.tenant.id).await? {
        return Ok(resp);
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let memberships = CloudflareMembershipRepository::new(&ctx.env);
    let m = TenantMembership {
        tenant_id: ctx_ta.tenant.id.clone(),
        user_id:   user_id.clone(),
        role, joined_at: now,
    };
    if let Err(e) = memberships.add_tenant_membership(&m).await {
        let msg = match e {
            PortError::Conflict => "User is already a member of this tenant".to_owned(),
            PortError::NotFound => "User id not found".to_owned(),
            _ => "Storage error".to_owned(),
        };
        return render::html_response(ui::for_tenant(
            &ctx_ta.principal, &ctx_ta.tenant, &user_id, &role_str, Some(&msg),
        ));
    }

    audit::write_owned(
        &ctx.env, EventKind::MembershipAdded,
        Some(ctx_ta.principal.id.clone()),
        Some(format!("tenant:{}/user:{}", ctx_ta.tenant.id, user_id)),
        Some(format!("via=tenant-admin,tenant={},role={}",
            ctx_ta.tenant.id, role_str)),
    ).await.ok();

    redirect_303(&format!("/admin/t/{}", ctx_ta.tenant.slug))
}

// ---------------------------------------------------------------------
// Organization membership
// ---------------------------------------------------------------------

async fn gate_for_org<D>(
    req: &Request, ctx: &RouteContext<D>,
) -> Result<std::result::Result<(cesauth_core::tenant_admin::TenantAdminContext,
    cesauth_core::tenancy::types::Organization), Response>>
{
    let principal = match auth::resolve_or_respond(req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(Err(r)),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, ctx).await? {
        Ok(c) => c, Err(r) => return Ok(Err(r)),
    };
    if let Err(r) = gate::check_action(
        &ctx_ta, PermissionCatalog::ORGANIZATION_MEMBER_ADD,
        ScopeRef::Tenant { tenant_id: &ctx_ta.tenant.id }, ctx,
    ).await? { return Ok(Err(r)); }

    let oid = match ctx.param("oid") {
        Some(s) => s.clone(),
        None    => return Ok(Err(Response::error("missing organization id", 400)?)),
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
    Ok(Ok((ctx_ta, org)))
}

pub async fn form_org<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, org) = match gate_for_org(&req, &ctx).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    render::html_response(ui::for_organization(
        &ctx_ta.principal, &ctx_ta.tenant, &org.id, &org.slug,
        "", "member", None,
    ))
}

pub async fn submit_org<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, org) = match gate_for_org(&req, &ctx).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };

    let form = parse_form(&mut req).await?;
    let user_id  = form.get("user_id").cloned().unwrap_or_default();
    let role_str = form.get("role").cloned().unwrap_or_default();

    let role = match role_str.as_str() {
        "admin"  => OrganizationRole::Admin,
        "member" => OrganizationRole::Member,
        _ => return render::html_response(ui::for_organization(
            &ctx_ta.principal, &ctx_ta.tenant, &org.id, &org.slug,
            &user_id, &role_str, Some("Choose a role"),
        )),
    };
    if user_id.trim().is_empty() {
        return render::html_response(ui::for_organization(
            &ctx_ta.principal, &ctx_ta.tenant, &org.id, &org.slug,
            &user_id, &role_str, Some("User id is required"),
        ));
    }

    if let Some(resp) = verify_user_in_tenant(&ctx.env, &user_id, &ctx_ta.tenant.id).await? {
        return Ok(resp);
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let memberships = CloudflareMembershipRepository::new(&ctx.env);
    let m = OrganizationMembership {
        organization_id: org.id.clone(),
        user_id:         user_id.clone(),
        role, joined_at: now,
    };
    if let Err(e) = memberships.add_organization_membership(&m).await {
        let msg = match e {
            PortError::Conflict => "User is already a member of this organization".to_owned(),
            PortError::NotFound => "User id not found".to_owned(),
            _ => "Storage error".to_owned(),
        };
        return render::html_response(ui::for_organization(
            &ctx_ta.principal, &ctx_ta.tenant, &org.id, &org.slug,
            &user_id, &role_str, Some(&msg),
        ));
    }

    audit::write_owned(
        &ctx.env, EventKind::MembershipAdded,
        Some(ctx_ta.principal.id.clone()),
        Some(format!("organization:{}/user:{}", org.id, user_id)),
        Some(format!("via=tenant-admin,tenant={},role={}",
            ctx_ta.tenant.id, role_str)),
    ).await.ok();

    redirect_303(&format!("/admin/t/{}/organizations/{}", ctx_ta.tenant.slug, org.id))
}

// ---------------------------------------------------------------------
// Group membership
// ---------------------------------------------------------------------

async fn gate_for_group<D>(
    req: &Request, ctx: &RouteContext<D>,
) -> Result<std::result::Result<(cesauth_core::tenant_admin::TenantAdminContext,
    cesauth_core::tenancy::types::Group, String), Response>>
{
    let principal = match auth::resolve_or_respond(req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(Err(r)),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, ctx).await? {
        Ok(c) => c, Err(r) => return Ok(Err(r)),
    };
    if let Err(r) = gate::check_action(
        &ctx_ta, PermissionCatalog::GROUP_MEMBER_ADD,
        ScopeRef::Tenant { tenant_id: &ctx_ta.tenant.id }, ctx,
    ).await? { return Ok(Err(r)); }

    let gid = match ctx.param("gid") {
        Some(s) => s.clone(),
        None    => return Ok(Err(Response::error("missing group id", 400)?)),
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
    Ok(Ok((ctx_ta, group, org_id)))
}

pub async fn form_group<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, group, org_id) = match gate_for_group(&req, &ctx).await? {
        Ok(t) => t, Err(r) => return Ok(r),
    };
    render::html_response(ui::for_group(
        &ctx_ta.principal, &ctx_ta.tenant,
        &group.id, &group.slug, &org_id, "", None,
    ))
}

pub async fn submit_group<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, group, org_id) = match gate_for_group(&req, &ctx).await? {
        Ok(t) => t, Err(r) => return Ok(r),
    };

    let form = parse_form(&mut req).await?;
    let user_id = form.get("user_id").cloned().unwrap_or_default();
    if user_id.trim().is_empty() {
        return render::html_response(ui::for_group(
            &ctx_ta.principal, &ctx_ta.tenant,
            &group.id, &group.slug, &org_id, &user_id,
            Some("User id is required"),
        ));
    }

    if let Some(resp) = verify_user_in_tenant(&ctx.env, &user_id, &ctx_ta.tenant.id).await? {
        return Ok(resp);
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let memberships = CloudflareMembershipRepository::new(&ctx.env);
    let m = GroupMembership {
        group_id: group.id.clone(),
        user_id:  user_id.clone(),
        joined_at: now,
    };
    if let Err(e) = memberships.add_group_membership(&m).await {
        let msg = match e {
            PortError::Conflict => "User is already a member of this group".to_owned(),
            PortError::NotFound => "User id not found".to_owned(),
            _ => "Storage error".to_owned(),
        };
        return render::html_response(ui::for_group(
            &ctx_ta.principal, &ctx_ta.tenant,
            &group.id, &group.slug, &org_id, &user_id, Some(&msg),
        ));
    }

    audit::write_owned(
        &ctx.env, EventKind::MembershipAdded,
        Some(ctx_ta.principal.id.clone()),
        Some(format!("group:{}/user:{}", group.id, user_id)),
        Some(format!("via=tenant-admin,tenant={}", ctx_ta.tenant.id)),
    ).await.ok();

    let return_to = if org_id.is_empty() {
        format!("/admin/t/{}/organizations", ctx_ta.tenant.slug)
    } else {
        format!("/admin/t/{}/organizations/{}", ctx_ta.tenant.slug, org_id)
    };
    redirect_303(&return_to)
}

// ---------------------------------------------------------------------
// Shared defense-in-depth: the user_id the operator typed must
// belong to this tenant. The slug gate already verifies the
// principal's user; this re-checks the *target* user.
// ---------------------------------------------------------------------

async fn verify_user_in_tenant(
    env: &worker::Env, user_id: &str, tenant_id: &str,
) -> Result<Option<Response>> {
    let users = CloudflareUserRepository::new(env);
    match users.find_by_id(user_id).await {
        Ok(Some(u)) if u.tenant_id == tenant_id => Ok(None),
        Ok(Some(_)) => Ok(Some(Response::error(
            "target user belongs to a different tenant", 403)?)),
        Ok(None)    => Ok(Some(Response::error("user not found", 404)?)),
        Err(_)      => Ok(Some(Response::error("storage error", 500)?)),
    }
}
