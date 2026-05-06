//! `GET /admin/t/:slug/subscription` — append-only subscription
//! change log for the current tenant.

use cesauth_cf::billing::{
    CloudflareSubscriptionHistoryRepository, CloudflareSubscriptionRepository,
};
use cesauth_core::billing::ports::{SubscriptionHistoryRepository, SubscriptionRepository};
use cesauth_ui::tenant_admin::subscription_page;
use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenant_admin::gate;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)     => p,
        Err(resp) => return Ok(resp),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c)     => c,
        Err(resp) => return Ok(resp),
    };

    if let Err(resp) = gate::check_read(
        &ctx_ta,
        cesauth_core::authz::types::PermissionCatalog::SUBSCRIPTION_READ,
        &ctx,
    ).await? {
        return Ok(resp);
    }

    // Subscription history is keyed on subscription_id, so we first
    // resolve the current subscription. No current subscription
    // (newly-created tenants) means no history; render the empty
    // state.
    let subs    = CloudflareSubscriptionRepository::new(&ctx.env);
    let history = CloudflareSubscriptionHistoryRepository::new(&ctx.env);
    let entries = match subs.current_for_tenant(&ctx_ta.tenant.id).await {
        Ok(Some(s)) => history.list_for_subscription(&s.id).await.unwrap_or_default(),
        Ok(None) | Err(_) => Vec::new(),
    };

    render::html_response(subscription_page(&ctx_ta.principal, &ctx_ta.tenant, &entries))
}
