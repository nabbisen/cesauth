//! `GET /admin/console/alerts` — Alert Center (§4.6).
//!
//! Serves the Leptos shell only. The read surface this doc used to
//! describe (combining bucket-safety and cost-threshold alerts) was
//! never built into this handler — see RFC 161.

use worker::{Request, Response, Result, RouteContext};


pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::admin::operator_json_api::shell(&req, &ctx, "アラート — cesauth").await
}
