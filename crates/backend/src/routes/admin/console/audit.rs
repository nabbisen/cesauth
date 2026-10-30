//! `GET /admin/console/audit` — Audit Log viewer.
//!
//! Serves the Leptos shell only. No query-parameter parsing, filtering,
//! or pagination happens in this handler — a prior version of this doc
//! specified one (`prefix`/`limit`/`kind`/`subject`/`actor`/`event`/
//! `from`/`to`/`cursor`) in detail, describing a search feature that
//! was never built. See RFC 161. For the production audit read path
//! today, see `docs/src/deployment/observability.md`.

use worker::{Request, Response, Result, RouteContext};


pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::admin::operator_json_api::shell(&req, &ctx, "監査ログ — cesauth").await
}
