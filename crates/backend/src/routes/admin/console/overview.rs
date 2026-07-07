//! `GET /admin/console` — Overview page (§4.1).
//!
//! Rolls up:
//!   * alert counts
//!   * recent (last 5) safety alerts
//!   * last 10 audit events
//!   * the three most-recently-verified buckets
//!
//! All visible to any authenticated role. Cost alerts are NOT computed
//! here (they'd require a snapshot per service — see the Alert Center
//! for the full cross-service roll-up).

use cesauth_cf::admin::{
    CloudflareAuditQuerySource, CloudflareBucketSafetyRepository, CloudflareThresholdRepository,
};
use cesauth_core::admin::service::build_overview;
use cesauth_core::admin::types::AdminAction;
use cesauth_frontend as ui;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::admin::operator_json_api::shell(&req, &ctx, "cesauth コンソール").await
}

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let _admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    crate::routes::admin::operator_json_api::csrf_json()
}
