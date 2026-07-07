//! `GET /admin/tenancy/tenants/:tid` — single tenant view.
//!
//! Fans out reads to: tenants, organizations under that tenant,
//! tenant memberships, current subscription, and the subscription's
//! plan. Each is independent; we issue them serially because D1's
//! Workers binding doesn't expose parallel statements yet, but the
//! whole page renders well under a hundred milliseconds at typical
//! sizes.

use cesauth_cf::billing::{CloudflarePlanRepository, CloudflareSubscriptionRepository};
use cesauth_cf::tenancy::{
    CloudflareMembershipRepository, CloudflareOrganizationRepository,
    CloudflareTenantRepository,
};
use cesauth_core::admin::types::AdminAction;
use cesauth_core::billing::ports::{PlanRepository, SubscriptionRepository};
use cesauth_core::tenancy::ports::{
    MembershipRepository, OrganizationRepository, TenantRepository,
};
use cesauth_frontend::tenancy_console::tenant_detail::TenantDetailInput;
use cesauth_frontend::tenancy_console::tenant_detail_page;
use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::auth;
use crate::routes::admin::console::render;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::admin::operator_json_api::shell(&req, &ctx, "テナント詳細 — cesauth").await
}

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let _admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    crate::routes::admin::operator_json_api::csrf_json()
}

// -------------------------------------------------------------------------
// POST /admin/tenancy/tenants/:id/suspend   (Operations+, RFC 068)
// -------------------------------------------------------------------------

pub async fn suspend<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match crate::routes::admin::auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = crate::routes::admin::auth::ensure_role_allows(
        &principal,
        cesauth_core::admin::types::AdminAction::ManageTenancy,
    ) {
        return Ok(r);
    }

    let tenant_id = ctx.param("id")
        .ok_or_else(|| worker::Error::RustError("missing id".into()))?
        .to_owned();

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let tenants = cesauth_cf::tenancy::CloudflareTenantRepository::new(&ctx.env);

    use cesauth_core::tenancy::service::suspend_tenant;
    if let Err(e) = suspend_tenant(&tenants, &tenant_id, now).await {
        return worker::Response::error(format!("suspend failed: {e:?}"), 500);
    }

    crate::audit::write_owned(
        &ctx.env,
        crate::audit::EventKind::TenantStatusChanged,
        Some(principal.id.clone()),
        Some(tenant_id.clone()),
        Some("status:Suspended".to_owned()),
    ).await.ok();

    let mut resp = worker::Response::empty()?.with_status(303);
    let _ = resp.headers_mut().set("location", &format!("/admin/tenancy/tenants/{tenant_id}"));
    Ok(resp)
}

// -------------------------------------------------------------------------
// POST /admin/tenancy/tenants/:id/restore   (Operations+, RFC 068)
// -------------------------------------------------------------------------

pub async fn restore<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match crate::routes::admin::auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = crate::routes::admin::auth::ensure_role_allows(
        &principal,
        cesauth_core::admin::types::AdminAction::ManageTenancy,
    ) {
        return Ok(r);
    }

    let tenant_id = ctx.param("id")
        .ok_or_else(|| worker::Error::RustError("missing id".into()))?
        .to_owned();

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let tenants = cesauth_cf::tenancy::CloudflareTenantRepository::new(&ctx.env);

    use cesauth_core::tenancy::service::restore_tenant;
    if let Err(e) = restore_tenant(&tenants, &tenant_id, now).await {
        return worker::Response::error(format!("restore failed: {e:?}"), 500);
    }

    crate::audit::write_owned(
        &ctx.env,
        crate::audit::EventKind::TenantStatusChanged,
        Some(principal.id.clone()),
        Some(tenant_id.clone()),
        Some("status:Active".to_owned()),
    ).await.ok();

    let mut resp = worker::Response::empty()?.with_status(303);
    let _ = resp.headers_mut().set("location", &format!("/admin/tenancy/tenants/{tenant_id}"));
    Ok(resp)
}
