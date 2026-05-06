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
//! v0.4.0 adds the HTML-form pair under the same role gate:
//!
//!   * `GET  /admin/console/config/:bucket/edit` — editable form
//!     pre-populated with the current attested state.
//!   * `POST /admin/console/config/:bucket/edit` — two-state handler:
//!     without `confirm=yes` it renders the confirmation page showing
//!     a before/after diff; with `confirm=yes` it applies and
//!     redirects to the review page. All writes go through the same
//!     service functions as the JSON API.

use cesauth_cf::admin::{CloudflareBucketSafetyRepository, CloudflareThresholdRepository};
use cesauth_core::admin::service::{
    apply_bucket_safety_change, build_safety_report, preview_bucket_safety_change,
};
use cesauth_core::admin::types::{AdminAction, BucketSafetyChange};
use cesauth_ui as ui;
use serde::Deserialize;
use std::collections::HashMap;
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

// -------------------------------------------------------------------------
// GET /admin/console/config/:bucket/edit   (Operations+, HTML)
// -------------------------------------------------------------------------

pub async fn edit_form<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
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

    let safety = CloudflareBucketSafetyRepository::new(&ctx.env);
    let state = match cesauth_core::admin::ports::BucketSafetyRepository::get(&safety, bucket).await {
        Ok(Some(s))  => s,
        Ok(None)     => return Response::error("unknown bucket", 404),
        Err(e)       => return Response::error(format!("read failed: {e}"), 500),
    };

    audit::write_owned(
        &ctx.env, EventKind::AdminConsoleViewed,
        Some(principal.id.clone()), None, Some(format!("config_edit:{bucket}")),
    ).await.ok();

    render::html_response(ui::admin::config_edit_form(&principal, &state, None))
}

// -------------------------------------------------------------------------
// POST /admin/console/config/:bucket/edit   (Operations+, HTML form)
// -------------------------------------------------------------------------

/// Parse an application/x-www-form-urlencoded body into a map.
async fn parse_form(req: &mut Request) -> Result<HashMap<String, String>> {
    let body = req.text().await.unwrap_or_default();
    Ok(url::form_urlencoded::parse(body.as_bytes()).into_owned().collect())
}

fn form_bool(form: &HashMap<String, String>, key: &str) -> bool {
    // Checkboxes submit `"1"` when checked, omit the field when not.
    // Hidden fields we emit on the confirm page always send either
    // `"1"` or `"0"`. Either way, the truth test is "present AND value
    // is `1`".
    matches!(form.get(key).map(String::as_str), Some("1") | Some("on") | Some("true") | Some("yes"))
}

pub async fn edit_submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::EditBucketSafety) {
        return Ok(r);
    }

    let bucket = match ctx.param("bucket") {
        Some(b) => b.to_owned(),
        None    => return Response::error("missing bucket", 400),
    };

    let form = parse_form(&mut req).await?;
    let confirmed = matches!(form.get("confirm").map(String::as_str), Some("yes"));

    let change = BucketSafetyChange {
        bucket:               bucket.clone(),
        public:               form_bool(&form, "public"),
        cors_configured:      form_bool(&form, "cors_configured"),
        bucket_lock:          form_bool(&form, "bucket_lock"),
        lifecycle_configured: form_bool(&form, "lifecycle_configured"),
        event_notifications:  form_bool(&form, "event_notifications"),
        notes: match form.get("notes") {
            Some(s) if !s.is_empty() => Some(s.clone()),
            _                        => None,
        },
    };

    let safety = CloudflareBucketSafetyRepository::new(&ctx.env);

    if !confirmed {
        // First POST: render the confirmation page.
        match preview_bucket_safety_change(&safety, &change).await {
            Ok(diff) => render::html_response(
                ui::admin::config_confirm_page(&principal, &diff)
            ),
            Err(cesauth_core::ports::PortError::NotFound) => {
                let state = match cesauth_core::admin::ports::BucketSafetyRepository::get(&safety, &bucket).await {
                    Ok(Some(s)) => s,
                    _           => return Response::error("unknown bucket", 404),
                };
                render::html_response(ui::admin::config_edit_form(
                    &principal, &state, Some("unknown bucket"),
                ))
            }
            Err(e) => Response::error(format!("preview failed: {e}"), 500),
        }
    } else {
        // Second POST: apply.
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let verifier_label = principal.name.clone().unwrap_or_else(|| principal.id.clone());

        audit::write_owned(
            &ctx.env, EventKind::AdminBucketSafetyChanged,
            Some(principal.id.clone()), None, Some(format!("attempt:{bucket}")),
        ).await.ok();

        match apply_bucket_safety_change(&safety, &change, &verifier_label, now).await {
            Ok(_) => {
                audit::write_owned(
                    &ctx.env, EventKind::AdminBucketSafetyChanged,
                    Some(principal.id.clone()), None, Some(format!("ok:{bucket}")),
                ).await.ok();
                // 303 back to the review page. Strictly speaking 303
                // forces GET after POST, which is what we want here -
                // the operator's reload button should not re-submit.
                let mut resp = Response::empty()?.with_status(303);
                let _ = resp.headers_mut().set("location", "/admin/console/config");
                let _ = resp.headers_mut().set("cache-control", "no-store");
                Ok(resp)
            }
            Err(cesauth_core::ports::PortError::NotFound) => {
                Response::error("unknown bucket", 404)
            }
            Err(e) => Response::error(format!("apply failed: {e}"), 500),
        }
    }
}
