//! `GET /admin/console/alerts` — Alert Center (§4.6).
//!
//! Combines every alert source: bucket safety (stale attestations,
//! public buckets) plus cost-threshold breaches across all services.
//! Newest first.

use worker::{Request, Response, Result, RouteContext};


pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::admin::operator_json_api::shell(&req, &ctx, "アラート — cesauth").await
}
