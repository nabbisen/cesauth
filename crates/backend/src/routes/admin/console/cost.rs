//! `GET /admin/console/cost` — Cost Dashboard (§4.2).
//!
//! Snapshots every tracked service and renders a per-service trend
//! table. Partial failure is tolerated: if one service's metrics read
//! fails, the others still render with an `error` note in their slot
//! rather than bringing the whole page down (§11).
//!
//! Why snapshot on every view: the dashboard is a low-traffic surface
//! (admin-only), so the cost of sampling D1 `COUNT(*)` + R2 `list()`
//! on each view is trivial compared to running a separate cron. It
//! also gives operators a live number instead of a cached one.
//! `CostSnapshotRepository` dedupes by hour bucket so repeated views
//! do not create repeated rows.

use cesauth_cf::admin::{
    CloudflareCostSnapshotRepository, CloudflareThresholdRepository, CloudflareUsageMetricsSource,
};
use cesauth_core::admin::service::build_cost_dashboard;
use cesauth_core::admin::types::{AdminAction, ServiceId};
use cesauth_frontend as ui;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::admin::operator_json_api::shell(&req, &ctx, "コスト — cesauth").await
}

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let _admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    crate::routes::admin::operator_json_api::csrf_json()
}
