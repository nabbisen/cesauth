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
    let metrics = CloudflareUsageMetricsSource::new(&ctx.env);
    let snaps   = CloudflareCostSnapshotRepository::new(&ctx.env);
    let safety  = CloudflareBucketSafetyRepository::new(&ctx.env);
    let thresh  = CloudflareThresholdRepository::new(&ctx.env);

    let alerts = generate_alerts(&metrics, &snaps, &safety, &thresh, now)
        .await
        .unwrap_or_default();

    audit::write_owned(
        &ctx.env, EventKind::AdminConsoleViewed,
        Some(principal.id.clone()), None, Some("alerts".into()),
    ).await.ok();

    if render::prefers_json(&req) {
        render::json_response(&serde_json::json!({
            "as_of":  now,
            "alerts": alerts,
        }))
    } else {
        render::html_response(ui::admin::alerts_page(now, &alerts))
    }
}
