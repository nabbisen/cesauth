//! Generic write-side actions for the admin console.
//!
//! `POST /admin/console/thresholds/:name` with JSON body
//! `{ "value": <i64> }` updates an operator-editable threshold.
//! Requires Operations+.
//!
//! Threshold *names* are intentionally free-form TEXT in D1; the well-
//! known set is in
//! [`cesauth_core::admin::types::threshold_names`].

use cesauth_cf::admin::CloudflareThresholdRepository;
use cesauth_core::admin::service::update_threshold;
use cesauth_core::admin::types::AdminAction;
use serde::Deserialize;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;

#[derive(Debug, Deserialize)]
struct ThresholdBody {
    value: i64,
}

pub async fn threshold<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::EditThreshold) {
        return Ok(r);
    }

    let Some(name) = ctx.param("name") else {
        return Response::error("missing threshold name", 400);
    };
    let body: ThresholdBody = match req.json().await {
        Ok(b)  => b,
        Err(_) => return Response::error("bad body", 400),
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let thresh = CloudflareThresholdRepository::new(&ctx.env);

    match update_threshold(&thresh, name, body.value, now).await {
        Ok(t) => {
            audit::write_owned(
                &ctx.env, EventKind::AdminThresholdUpdated,
                Some(principal.id.clone()), None, Some(format!("{name}={}", body.value)),
            ).await.ok();
            render::json_response(&serde_json::json!({
                "ok":        true,
                "threshold": t,
            }))
        }
        Err(cesauth_core::ports::PortError::NotFound) => {
            Response::error("unknown threshold", 404)
        }
        Err(e) => Response::error(format!("update failed: {e}"), 500),
    }
}
