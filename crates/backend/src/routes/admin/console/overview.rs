//! `GET /admin/console` — Overview page (§4.1).
//!
//! Serves the Leptos shell. `GET /admin/console.json` (`page_json`
//! below) returns only a CSRF token — the rollup this doc used to
//! describe (alert counts, recent safety alerts, recent audit events,
//! recently-verified buckets) was never built into either handler. The
//! frontend component renders a nav menu and a bare "is the JSON
//! endpoint reachable" check, not any of the above. See RFC 161.

use worker::{Request, Response, Result, RouteContext};


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
