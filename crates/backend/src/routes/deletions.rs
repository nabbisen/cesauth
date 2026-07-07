//! Deletion request worker routes — RFC 047.
//!
//! Routes:
//!
//!   POST /me/security/delete-account
//!       Self-service: authenticated user schedules their own deletion.
//!
//!   GET  /admin/t/:slug/deletion-requests
//!       Tenant admin views pending deletion requests for the tenant.
//!
//!   POST /admin/t/:slug/deletion-requests/:id/cancel
//!       Cancel a pending deletion request.
//!
//!   POST /admin/t/:slug/deletion-requests/:id/execute
//!       Admin-triggered immediate execution (bypasses grace period).

use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::config::Config;
use crate::log::{self, Category, Level};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenant_admin::gate;

// ---------------------------------------------------------------------------
// POST /me/security/delete-account
// ---------------------------------------------------------------------------

pub async fn request_self<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let cfg = Config::from_env(&ctx.env)?;
    let grace_days: i64 = 30;

    // Full implementation pending CloudflareDeletionRequestRepository.
    audit::write_owned(
        &ctx.env, EventKind::DeletionRequested,
        Some(principal.id.clone()), None,
        Some(format!("self-request scheduled in {grace_days}d")),
    ).await.ok();

    log::emit(&cfg.log, Level::Info, Category::Auth,
        "deletion requested (self)",
        Some(&principal.id));

    let mut resp = Response::empty()?.with_status(303);
    let _ = resp.headers_mut().set("location", "/me/security?deletion_requested=1");
    Ok(resp)
}

// ---------------------------------------------------------------------------
// GET /admin/t/:slug/deletion-requests
// ---------------------------------------------------------------------------

pub async fn admin_list<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c)  => c,
        Err(r) => return Ok(r),
    };

    // Full implementation pending CloudflareDeletionRequestRepository.
    let html = format!(
        r#"<!DOCTYPE html><html><head><title>Deletion Requests</title></head>
<body><h1>Pending Deletion Requests — {}</h1>
<p>No pending deletion requests.</p>
</body></html>"#,
        ctx_ta.tenant.slug
    );
    render::html_response(html)
}

// ---------------------------------------------------------------------------
// POST /admin/t/:slug/deletion-requests/:id/cancel
// ---------------------------------------------------------------------------

pub async fn admin_cancel<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c)  => c,
        Err(r) => return Ok(r),
    };

    let request_id = ctx.param("id")
        .ok_or_else(|| worker::Error::RustError("missing id".into()))?
        .to_owned();

    let now = OffsetDateTime::now_utc().unix_timestamp();

    // Full implementation pending CloudflareDeletionRequestRepository.
    audit::write_owned(
        &ctx.env, EventKind::DeletionCancelled,
        Some(ctx_ta.principal.id.clone()), None,
        Some(format!("request:{request_id}")),
    ).await.ok();

    let mut resp = Response::empty()?.with_status(303);
    let _ = resp.headers_mut().set(
        "location",
        &format!("/admin/t/{}/deletion-requests", ctx_ta.tenant.slug),
    );
    Ok(resp)
}

// ---------------------------------------------------------------------------
// POST /admin/t/:slug/deletion-requests/:id/execute
// ---------------------------------------------------------------------------

pub async fn admin_execute<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c)  => c,
        Err(r) => return Ok(r),
    };

    let request_id = ctx.param("id")
        .ok_or_else(|| worker::Error::RustError("missing id".into()))?
        .to_owned();

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let cfg = Config::from_env(&ctx.env)?;

    // Full implementation pending CloudflareDeletionRequestRepository.
    audit::write_owned(
        &ctx.env, EventKind::DeletionExecuted,
        Some(ctx_ta.principal.id.clone()), None,
        Some(format!("request:{request_id} admin-triggered")),
    ).await.ok();

    log::emit(&cfg.log, Level::Warn, Category::Auth,
        &format!("deletion executed admin-triggered: request {request_id}"),
        Some(&ctx_ta.principal.id));

    let mut resp = Response::empty()?.with_status(303);
    let _ = resp.headers_mut().set(
        "location",
        &format!("/admin/t/{}/deletion-requests?executed=1", ctx_ta.tenant.slug),
    );
    Ok(resp)
}
