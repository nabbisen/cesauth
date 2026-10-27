//! `GET /admin/tenancy/tenants/:tid/subscription/history` — append-only
//! subscription change log for one tenant.

use cesauth_cf::billing::{
    CloudflareSubscriptionHistoryRepository, CloudflareSubscriptionRepository,
};
use cesauth_cf::tenancy::CloudflareTenantRepository;
use cesauth_core::admin::types::AdminAction;
use cesauth_core::billing::ports::{SubscriptionHistoryRepository, SubscriptionRepository};
use cesauth_core::tenancy::ports::TenantRepository;
use cesauth_frontend::tenancy_console::subscription_history_page;
use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::console::render;

/// **RFC 145 cycle 3.** Used to return the Leptos shell with no
/// matching `app.rs` route — HTTP 200 rendering `<NotFound/>`.
/// Read-only: `resolve_admin` only, no `ensure_role_allows`. 404 if the
/// tenant has no current subscription on file, matching the other
/// subscription routes' own behavior (`subscription_set_plan.rs`,
/// `subscription_set_status.rs`) rather than inventing a new policy for
/// the missing case.
pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(r) => return Ok(r),
    };

    let tid = match ctx.param("tid") {
        Some(s) => s.clone(),
        None    => return Response::error("missing tenant id", 400),
    };
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let tenant = match tenants.get(&tid).await {
        Ok(Some(t)) => t,
        Ok(None)    => return Response::error("not found", 404),
        Err(_)      => return Response::error("storage error", 500),
    };

    let subs = CloudflareSubscriptionRepository::new(&ctx.env);
    let current = match subs.current_for_tenant(&tid).await {
        Ok(Some(s)) => s,
        Ok(None)    => return Response::error("no subscription on file", 404),
        Err(_)      => return Response::error("storage error", 500),
    };

    let history_repo = CloudflareSubscriptionHistoryRepository::new(&ctx.env);
    let entries = history_repo.list_for_subscription(&current.id).await.unwrap_or_default();

    render::html_response(|| subscription_history_page(&admin, &tenant.id, &tenant.slug, &entries))
}

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let _admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    crate::routes::admin::operator_json_api::csrf_json()
}
