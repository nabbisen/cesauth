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
use cesauth_ui::tenancy_console::tenant_detail::TenantDetailInput;
use cesauth_ui::tenancy_console::tenant_detail_page;
use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::auth;
use crate::routes::admin::console::render;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)    => p,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = auth::ensure_role_allows(&principal, AdminAction::ViewTenancy) {
        return Ok(resp);
    }
    let Some(tid) = ctx.param("tid") else { return Response::error("not found", 404); };

    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let tenant = match tenants.get(tid).await {
        Ok(Some(t)) => t,
        Ok(None)    => return Response::error("not found", 404),
        Err(_)      => return Response::error("storage error", 500),
    };

    let orgs    = CloudflareOrganizationRepository::new(&ctx.env);
    let members = CloudflareMembershipRepository::new(&ctx.env);
    let subs    = CloudflareSubscriptionRepository::new(&ctx.env);
    let plans   = CloudflarePlanRepository::new(&ctx.env);

    let organizations = orgs.list_for_tenant(&tenant.id).await.unwrap_or_default();
    let members_list  = members.list_tenant_members(&tenant.id).await.unwrap_or_default();
    let subscription  = subs.current_for_tenant(&tenant.id).await.ok().flatten();
    let plan = match &subscription {
        Some(s) => plans.get(&s.plan_id).await.ok().flatten(),
        None    => None,
    };

    render::html_response(tenant_detail_page(&principal, &TenantDetailInput {
        tenant:        &tenant,
        members:       &members_list,
        organizations: &organizations,
        subscription:  subscription.as_ref(),
        plan:          plan.as_ref(),
    }))
}
