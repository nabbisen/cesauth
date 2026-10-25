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

use worker::{Request, Response, Result, RouteContext};

use crate::config::Config;
use crate::log::{self, Category, Level};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenant_admin::gate;

// ---------------------------------------------------------------------------
// POST /me/security/delete-account
// ---------------------------------------------------------------------------

/// **RFC 147.** This endpoint used to audit a "scheduled" outcome and
/// redirect with a success flag, without ever creating a row the sweep
/// could find — a user told their deletion was scheduled in 30 days,
/// whose request silently vanished. Nothing here is implemented yet
/// (cycle 2); this cycle's job is only to stop asserting that it is.
/// Auth runs first and unchanged, so an unauthenticated caller learns
/// nothing new (RFC 147 D4).
pub async fn request_self<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };

    let cfg = Config::from_env(&ctx.env)?;

    // Full implementation pending CloudflareDeletionRequestRepository.
    log::emit(&cfg.log, Level::Info, Category::Auth,
        "delete-account called; not implemented (RFC 147)",
        Some(&principal.id));

    Response::error("account deletion is not yet implemented", 501)
}

// ---------------------------------------------------------------------------
// GET /admin/t/:slug/deletion-requests
// ---------------------------------------------------------------------------

pub async fn admin_list<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::leptos_shell::leptos_html_shell(&req, &ctx.env, "Deletion requests — cesauth", "en").await
}

pub async fn admin_list_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::csrf::mint()
        .map_err(|_| worker::Error::RustError("csrf rng failed".into()))
        .and_then(|t| {
            let set_cookie = crate::csrf::set_cookie_header(&t);
            let mut resp = worker::Response::from_json(&serde_json::json!({"csrf_token": t}))?;
            resp.headers_mut().append("set-cookie", &set_cookie).ok();
            resp.headers_mut().set("cache-control", "no-store").ok();
            Ok(resp)
        })
}

// ---------------------------------------------------------------------------
// POST /admin/t/:slug/deletion-requests/:id/cancel
// ---------------------------------------------------------------------------

/// **RFC 147.** Used to audit a cancellation and redirect back to the
/// list, for an `:id` it never looked up — cancelling nothing while saying
/// otherwise. Auth and the tenant-admin gate run first and unchanged (D4);
/// nothing here reads `:id` any more because nothing here acts on it.
pub async fn admin_cancel<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    let _ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c)  => c,
        Err(r) => return Ok(r),
    };

    // Full implementation pending CloudflareDeletionRequestRepository.
    Response::error("deletion-request cancellation is not yet implemented", 501)
}

// ---------------------------------------------------------------------------
// POST /admin/t/:slug/deletion-requests/:id/execute
// ---------------------------------------------------------------------------

/// **RFC 147.** Used to audit an execution — the same audit event kind
/// the real sweep (`sweep.rs`) writes for a deletion that actually ran —
/// for any `:id`, unvalidated, never loaded, never deleting the user it
/// never checked exists. `docs/src/expert/admin-operations.md` called
/// this "physically deletes the user. Irreversible."; it deleted
/// nothing. Auth and the tenant-admin gate run first and unchanged (D4).
pub async fn admin_execute<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c)  => c,
        Err(r) => return Ok(r),
    };

    let cfg = Config::from_env(&ctx.env)?;

    // Full implementation pending CloudflareDeletionRequestRepository.
    log::emit(&cfg.log, Level::Warn, Category::Auth,
        "deletion-request execute endpoint called; not implemented (RFC 147)",
        Some(&ctx_ta.principal.id));

    Response::error("deletion-request execution is not yet implemented", 501)
}
