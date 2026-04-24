//! Configuration Review (§4.5).
//!
//! `GET /admin/console/config` renders the attested bucket-safety rows
//! and the current threshold values — the settings every operator
//! should periodically eyeball.
//!
//! `POST /admin/console/config/:bucket/preview` takes a proposed
//! `BucketSafetyChange` as JSON and returns a diff without committing
//! anything. This is the "§7 二段階確認" preview step.
//!
//! `POST /admin/console/config/:bucket/apply` takes the same payload
//! plus a `confirm: true` flag and actually writes. Requires
//! `EditBucketSafety` (Operations+). The handler audits before AND
//! after write so the trail records both attempt and outcome.
//!
//! For v0.3.0 we ship the preview/apply pair as a JSON-script API
//! only — the HTML "confirm screen" UI is priority-8 in the spec and
//! slated for 0.3.1.

use cesauth_cf::admin::{CloudflareBucketSafetyRepository, CloudflareThresholdRepository};
use cesauth_core::admin::service::{
    apply_bucket_safety_change, build_safety_report, preview_bucket_safety_change,
};
use cesauth_core::admin::types::{AdminAction, BucketSafetyChange};
use cesauth_ui as ui;
use serde::Deserialize;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;

// -------------------------------------------------------------------------
// GET /admin/console/config
// -------------------------------------------------------------------------

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::ViewConsole) {
        return Ok(r);
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let safety = CloudflareBucketSafetyRepository::new(&ctx.env);
    let thresh = CloudflareThresholdRepository::new(&ctx.env);

    // Gather in parallel-ish. `build_safety_report` does bucket+thresh
    // already; we call it then fetch the threshold list explicitly for
    // the review section.
    let report = build_safety_report(&safety, &thresh, now)
        .await
        .map_err(|e| worker::Error::RustError(format!("config: {e}")))?;
    let thresholds = cesauth_core::admin::ports::ThresholdRepository::list(&thresh)
        .await
        .unwrap_or_default();

    audit::write_owned(
        &ctx.env, EventKind::AdminConsoleViewed,
        Some(principal.id.clone()), None, Some("config".into()),
    ).await.ok();

    if render::prefers_json(&req) {
        render::json_response(&serde_json::json!({
            "report":     report,
            "thresholds": thresholds,
        }))
    } else {
        render::html_response(ui::admin::config_page(&principal, &report, &thresholds))
    }
}

// -------------------------------------------------------------------------
// POST /admin/console/config/:bucket/preview   (Operations+)
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ChangeBody {
    public:               bool,
    cors_configured:      bool,
    bucket_lock:          bool,
    lifecycle_configured: bool,
    event_notifications:  bool,
    notes:                Option<String>,
}

impl ChangeBody {
    fn into_change(self, bucket: String) -> BucketSafetyChange {
        BucketSafetyChange {
            bucket,
            public:               self.public,
            cors_configured:      self.cors_configured,
            bucket_lock:          self.bucket_lock,
            lifecycle_configured: self.lifecycle_configured,
            event_notifications:  self.event_notifications,
            notes:                self.notes,
        }
    }
}

pub async fn preview<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::EditBucketSafety) {
        return Ok(r);
    }

    let Some(bucket) = ctx.param("bucket") else {
        return Response::error("missing bucket", 400);
    };

    let body: ChangeBody = match req.json().await {
        Ok(b)  => b,
        Err(_) => return Response::error("bad change body", 400),
    };
    let change = body.into_change(bucket.to_owned());

    let safety = CloudflareBucketSafetyRepository::new(&ctx.env);
    match preview_bucket_safety_change(&safety, &change).await {
        Ok(diff) => render::json_response(&serde_json::json!({
            "ok":   true,
            "diff": diff,
        })),
        Err(cesauth_core::ports::PortError::NotFound) => {
            Response::error("unknown bucket", 404)
        }
        Err(e) => Response::error(format!("preview failed: {e}"), 500),
    }
}

// -------------------------------------------------------------------------
// POST /admin/console/config/:bucket/apply   (Operations+)
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ApplyBody {
    #[serde(flatten)]
    change:  ChangeBody,
    /// Must be `true` — the scripted equivalent of a human clicking
    /// "Yes, apply". Missing or false rejects the request so a JSON
    /// client cannot accidentally submit the preview body to the apply
    /// endpoint.
    confirm: bool,
}

pub async fn apply<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::EditBucketSafety) {
        return Ok(r);
    }

    let Some(bucket) = ctx.param("bucket") else {
        return Response::error("missing bucket", 400);
    };

    let body: ApplyBody = match req.json().await {
        Ok(b)  => b,
        Err(_) => return Response::error("bad apply body", 400),
    };
    if !body.confirm {
        return Response::error("confirm: true is required to apply", 400);
    }

    let change = body.change.into_change(bucket.to_owned());

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let safety = CloudflareBucketSafetyRepository::new(&ctx.env);
    let verifier_label = principal.name.clone().unwrap_or_else(|| principal.id.clone());

    // Audit the attempt first, then write. If the write fails we still
    // have the attempt record, which matches §11's "監視失敗自体も監査
    // 対象" expectation.
    audit::write_owned(
        &ctx.env, EventKind::AdminBucketSafetyChanged,
        Some(principal.id.clone()), None, Some(format!("attempt:{bucket}")),
    ).await.ok();

    match apply_bucket_safety_change(&safety, &change, &verifier_label, now).await {
        Ok((before, after)) => {
            audit::write_owned(
                &ctx.env, EventKind::AdminBucketSafetyChanged,
                Some(principal.id.clone()), None, Some(format!("ok:{bucket}")),
            ).await.ok();
            render::json_response(&serde_json::json!({
                "ok":     true,
                "before": before,
                "after":  after,
            }))
        }
        Err(cesauth_core::ports::PortError::NotFound) => {
            Response::error("unknown bucket", 404)
        }
        Err(e) => Response::error(format!("apply failed: {e}"), 500),
    }
}

