//! `GET /admin/console/alerts` — Alert Center (§4.6).
//!
//! Combines every alert source: bucket safety (stale attestations,
//! public buckets) plus cost-threshold breaches across all services.
//! Newest first.

use cesauth_cf::admin::{
    CloudflareBucketSafetyRepository, CloudflareCostSnapshotRepository,
    CloudflareThresholdRepository, CloudflareUsageMetricsSource,
};
use cesauth_core::admin::service::generate_alerts;
use cesauth_core::admin::types::AdminAction;
use cesauth_frontend as ui;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::admin::operator_json_api::shell(&req, &ctx, "アラート — cesauth").await
}

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let _admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    crate::routes::admin::operator_json_api::csrf_json()
}
