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

use crate::routes::admin::auth;
use crate::routes::admin::console::render;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::admin::operator_json_api::shell(&req, &ctx, "サブスクリプション — cesauth").await
}

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let _admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    crate::routes::admin::operator_json_api::csrf_json()
}
