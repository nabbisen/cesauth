//! `GET /admin/console/cost` — Cost Dashboard (§4.2).
//!
//! Snapshots every tracked service and renders a per-service trend
//! table. Partial failure is tolerated: if one service's metrics read
//! fails, the others still render with an `error` note in their slot
//! rather than bringing the whole page down (§11).
//!
//! Why snapshot on every view: the dashboard is a low-traffic surface
//! (admin-only), so the cost of sampling D1 `COUNT(*)` + R2 `list()`
//! on each view is trivial compared to running a separate cron. It
//! also gives operators a live number instead of a cached one.
//! `CostSnapshotRepository` dedupes by hour bucket so repeated views
//! do not create repeated rows.

use cesauth_cf::admin::{
    CloudflareCostSnapshotRepository, CloudflareThresholdRepository, CloudflareUsageMetricsSource,
};
use cesauth_core::admin::service::build_cost_dashboard;
use cesauth_core::admin::types::{AdminAction, ServiceId};
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
    let thresh  = CloudflareThresholdRepository::new(&ctx.env);

    let results = build_cost_dashboard(&metrics, &snaps, &thresh, now).await;

    audit::write_owned(
        &ctx.env, EventKind::AdminConsoleViewed,
        Some(principal.id.clone()), None, Some("cost".into()),
    ).await.ok();

    if render::prefers_json(&req) {
        // JSON shape: array of { service, ok: true/false, trend? | error? }
        let payload: Vec<serde_json::Value> = results.into_iter().map(|(svc, res)| {
            match res {
                Ok(trend) => serde_json::json!({
                    "service": svc.as_str(),
                    "ok":      true,
                    "trend":   trend,
                }),
                Err(e) => serde_json::json!({
                    "service": svc.as_str(),
                    "ok":      false,
                    "error":   e.to_string(),
                }),
            }
        }).collect();
        render::json_response(&serde_json::json!({
            "as_of":    now,
            "services": payload,
        }))
    } else {
        // For HTML: flatten to the subset the template needs.
        // Errors become placeholder rows with the error text.
        let view: Vec<(ServiceId, std::result::Result<cesauth_core::admin::types::CostTrend, String>)> =
            results.into_iter()
                .map(|(svc, r)| (svc, r.map_err(|e| e.to_string())))
                .collect();
        render::html_response(ui::admin::cost_page(now, &view))
    }
}
