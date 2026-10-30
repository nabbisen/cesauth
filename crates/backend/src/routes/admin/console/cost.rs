//! `GET /admin/console/cost` — Cost Dashboard (§4.2).
//!
//! Serves the Leptos shell only. The per-service snapshot/trend table
//! this doc used to describe was never built into this handler — no
//! `CostSnapshotRepository` read happens here. See RFC 161.

use worker::{Request, Response, Result, RouteContext};


pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::admin::operator_json_api::shell(&req, &ctx, "コスト — cesauth").await
}
