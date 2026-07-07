//! `GET /admin/console/operations` — cron pass status (RFC 081).

use worker::{Request, Response, Result, RouteContext};

use cesauth_core::admin::types::AdminAction;
use cesauth_frontend::admin::operations::{operations_page, CronPassDisplay};

use crate::require_system_admin;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::admin::operator_json_api::shell(&req, &ctx, "オペレーション — cesauth").await
}

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let _admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    crate::routes::admin::operator_json_api::csrf_json()
}

/// Shape of the JSON stored in KV by each cron pass (RFC 081).
#[derive(serde::Deserialize)]
struct CronRecord {
    finished_at:     String,
    success:         bool,
    processed_count: u64,
    mode:            Option<String>,
    error_message:   Option<String>,
}
