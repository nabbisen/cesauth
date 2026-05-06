//! `GET /admin/tenancy/tenants/:tid/subscription/history` — append-only
//! subscription change log for one tenant.

use cesauth_cf::billing::{
    CloudflareSubscriptionHistoryRepository, CloudflareSubscriptionRepository,
};
use cesauth_cf::tenancy::CloudflareTenantRepository;
use cesauth_core::admin::types::AdminAction;
use cesauth_core::billing::ports::{SubscriptionHistoryRepository, SubscriptionRepository};
use cesauth_core::tenancy::ports::TenantRepository;
use cesauth_ui::tenancy_console::subscription_history_page;
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

    // Resolve the tenant (slug for the title) and its current
    // subscription id (the history table is keyed on subscription_id).
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let tenant = match tenants.get(tid).await {
        Ok(Some(t)) => t,
        Ok(None)    => return Response::error("not found", 404),
        Err(_)      => return Response::error("storage error", 500),
    };

    let subs = CloudflareSubscriptionRepository::new(&ctx.env);
    let history = CloudflareSubscriptionHistoryRepository::new(&ctx.env);
    let entries = match subs.current_for_tenant(&tenant.id).await {
        Ok(Some(s)) => history.list_for_subscription(&s.id).await.unwrap_or_default(),
        // No current subscription means there's no history to show
        // either; we still render the page (with the empty state)
        // for symmetry with other empty-list views.
        Ok(None) | Err(_) => Vec::new(),
    };

    render::html_response(subscription_history_page(
        &principal, &tenant.id, &tenant.slug, &entries,
    ))
}
