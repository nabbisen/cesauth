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
use cesauth_ui as ui;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::ViewConsole) {
        return Ok(r);
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let audit_src   = CloudflareAuditQuerySource::new(&ctx.env);
    let safety_repo = CloudflareBucketSafetyRepository::new(&ctx.env);
    let thresh_repo = CloudflareThresholdRepository::new(&ctx.env);

    let summary = build_overview(&principal, &audit_src, &safety_repo, &thresh_repo, now)
        .await
        .map_err(|e| worker::Error::RustError(format!("overview: {e}")))?;

    // Audit the view itself - §13 asks that every change operation is
    // recorded, and while a view isn't a change, the spec also asks
    // that "監視失敗自体も監査対象" (§11). We record views to match that.
    audit::write_owned(
        &ctx.env, EventKind::AdminConsoleViewed,
        Some(principal.id.clone()), None, Some("overview".into()),
    ).await.ok();

    if render::prefers_json(&req) {
        render::json_response(&serde_json::to_value(&summary)
            .unwrap_or(serde_json::Value::Null))
    } else {
        render::html_response(ui::admin::overview_page(&summary))
    }
}
