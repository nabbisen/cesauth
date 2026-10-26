//! Deletion request worker routes — RFC 044 / RFC 147.
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
//!
//! **RFC 147 cycle 2** wires all four handlers to the real
//! `cesauth_core::deletion` services and the `CloudflareDeletionRequestRepository`.
//! Cycle 1 (0.85.1) stopped these endpoints from claiming an outcome that
//! never happened; this cycle makes the outcome real.

use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use cesauth_cf::ports::repo::{CloudflareDeletionRequestRepository, CloudflareUserRepository};
use cesauth_core::deletion::{self, DeletionRequestRepository};
use cesauth_core::ports::repo::UserRepository;

use crate::audit::{self, EventKind};
use crate::config::Config;
use crate::log::{self, Category, Level};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenant_admin::gate;
use crate::routes::me::auth as me_auth;

// ---------------------------------------------------------------------------
// POST /me/security/delete-account
// ---------------------------------------------------------------------------

/// **RFC 147 D1.** Self-service deletion request, authenticated by the
/// user's own session cookie — not the admin bearer this route used before
/// cycle 2 (cycle 1 §4 found that defect: no end user could ever reach this
/// route, so the false-success path it replaced had never fired for a real
/// user).
///
/// **CSRF.** This route takes no form body — it is a bare action trigger —
/// so it cannot carry a double-submit token the way the admin console's
/// forms do. Per `crate::csrf`'s documented threat model (also used by
/// `routes::magic_link::request`), an `application/json` requirement is
/// itself the mitigation: a cross-site HTML form cannot set that
/// Content-Type, and a cross-origin `fetch` with it triggers a CORS
/// preflight this deployment does not answer permissively (no
/// `Access-Control-Allow-Origin` is ever set — see
/// `routes::admin::console::clients`). Anything else is rejected before the
/// session is even resolved, so a forged plain POST never reaches the
/// scheduling logic.
pub async fn request_self<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let content_type = req.headers().get("content-type").ok().flatten();
    let is_json = content_type.as_deref()
        .map(|ct| ct.to_ascii_lowercase().contains("application/json"))
        .unwrap_or(false);
    if !is_json {
        return Response::error("Content-Type: application/json required", 400);
    }

    let session = match me_auth::resolve_or_redirect(&req, &ctx.env).await? {
        Ok(s)  => s,
        Err(r) => return Ok(r),
    };

    let user_repo = CloudflareUserRepository::new(&ctx.env);
    let user = match user_repo.find_by_id(session.user_id.as_str()).await {
        Ok(Some(u)) => u,
        Ok(None)    => return Response::error("account not found", 404),
        Err(_)      => return Response::error("internal error", 500),
    };

    let now      = OffsetDateTime::now_utc().unix_timestamp();
    let del_repo = CloudflareDeletionRequestRepository::new(&ctx.env);

    let scheduled = match deletion::schedule_deletion(
        &del_repo,
        session.user_id.as_str(),
        &user.tenant_id,
        session.user_id.as_str(),
        None,
        deletion::DEFAULT_GRACE_SECS,
        now,
    ).await {
        Ok(r) => r,
        // D7: a rejected request writes no event.
        Err(cesauth_core::CoreError::Conflict) => {
            return Response::error("a deletion request is already pending", 409);
        }
        Err(_) => return Response::error("internal error", 500),
    };

    // D5: subject is the affected user (here, the requester themself).
    audit::write_owned(
        &ctx.env, EventKind::DeletionRequested,
        Some(session.user_id.to_string()),
        None,
        Some(format!("self-request scheduled_at={}", scheduled.scheduled_at)),
    ).await.ok();

    let mut resp = Response::empty()?.with_status(302);
    let _ = resp.headers_mut().set("location", "/me/security");
    Ok(resp)
}

// ---------------------------------------------------------------------------
// GET /admin/t/:slug/deletion-requests
// ---------------------------------------------------------------------------

/// **RFC 147 D9.** Server-rendered (no longer the Leptos shell) with a real
/// CSRF token: `deletion_requests_page`'s hidden `csrf_token` fields used to
/// carry a hardcoded empty string, so the cancel/execute forms below could
/// never pass CSRF. This mints a token, sets its cookie, and threads it
/// into the template — the same mint-then-render order `html_response`
/// callers use elsewhere (RFC 146).
pub async fn admin_list<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c)  => c,
        Err(r) => return Ok(r),
    };
    if let Err(r) = gate::check_read(
        &ctx_ta,
        cesauth_core::authz::types::PermissionCatalog::TENANT_READ,
        &ctx,
    ).await? { return Ok(r); }

    let del_repo = CloudflareDeletionRequestRepository::new(&ctx.env);
    let requests = del_repo.list_pending_by_tenant(&ctx_ta.tenant.id).await.unwrap_or_default();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let csrf_token = crate::csrf::mint()
        .map_err(|_| worker::Error::RustError("csrf rng failed".into()))?;

    let mut resp = render::html_response(|| cesauth_frontend::tenant_admin::deletions::deletion_requests_page(
        &ctx_ta.principal, &ctx_ta.tenant, &requests, now, &csrf_token,
    ))?;
    resp.headers_mut().append("set-cookie", &crate::csrf::set_cookie_header(&csrf_token)).ok();
    Ok(resp)
}

// ---------------------------------------------------------------------------
// POST /admin/t/:slug/deletion-requests/:id/cancel
// ---------------------------------------------------------------------------

/// **RFC 147 D5/D6/D7/D8.** Cancels a pending request through
/// `cesauth_core::deletion::cancel_deletion`. The audit event's `subject` is
/// the affected user (not the cancelling admin — D5); the actor is
/// recorded structurally via the row's own `cancelled_by` column (D6), no
/// new `EventKind`. `:id` is validated against this tenant before anything
/// else: absent or cross-tenant is a 404 with no audit event (D8), so a
/// tenant admin cannot learn that another tenant's request id exists.
pub async fn admin_cancel<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c)  => c,
        Err(r) => return Ok(r),
    };

    let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();
    let form = req.form_data().await?;
    let csrf_form = match form.get("csrf_token") {
        Some(worker::FormEntry::Field(v)) => v,
        _ => String::new(),
    };
    let csrf_cookie = crate::csrf::extract_from_cookie_header(&cookie_header).unwrap_or("");
    if !crate::csrf::verify(&csrf_form, csrf_cookie) {
        return Response::error("Bad Request", 400);
    }

    let request_id = ctx.param("id")
        .ok_or_else(|| worker::Error::RustError("missing id".into()))?
        .to_owned();

    let del_repo = CloudflareDeletionRequestRepository::new(&ctx.env);

    // D8: validate the tenant before anything else.
    let req_row = match del_repo.find_by_id(&request_id).await.ok().flatten() {
        Some(r) if r.tenant_id == ctx_ta.tenant.id => r,
        _ => return Response::error("not found", 404),
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    match deletion::cancel_deletion(&del_repo, &request_id, &ctx_ta.principal.id, now).await {
        Ok(()) => {
            audit::write_owned(
                &ctx.env, EventKind::DeletionCancelled,
                Some(req_row.user_id.clone()),
                None,
                Some(format!("request:{request_id} cancelled_by:{}", ctx_ta.principal.id)),
            ).await.ok();
            let mut resp = Response::empty()?.with_status(303);
            let _ = resp.headers_mut().set(
                "location",
                &format!("/admin/t/{}/deletion-requests", ctx_ta.tenant.slug),
            );
            Ok(resp)
        }
        // D7: a rejected request (not pending any more) writes no event.
        Err(_) => Response::error("deletion request is not pending", 409),
    }
}

// ---------------------------------------------------------------------------
// POST /admin/t/:slug/deletion-requests/:id/execute
// ---------------------------------------------------------------------------

/// **RFC 147 D5/D6/D7/D8.** Admin-triggered immediate execution, bypassing
/// the grace period. Same tenant validation as `admin_cancel` (D8); the
/// audit event's `subject` is the deleted user, and `executed_by` on the
/// row (set by `execute_deletion`) is the acting admin's principal id —
/// the sweep instead passes `"sweep"` (D6), so the two actors are
/// distinguishable from the row alone, with no new `EventKind`.
pub async fn admin_execute<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c)  => c,
        Err(r) => return Ok(r),
    };

    let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();
    let form = req.form_data().await?;
    let csrf_form = match form.get("csrf_token") {
        Some(worker::FormEntry::Field(v)) => v,
        _ => String::new(),
    };
    let csrf_cookie = crate::csrf::extract_from_cookie_header(&cookie_header).unwrap_or("");
    if !crate::csrf::verify(&csrf_form, csrf_cookie) {
        return Response::error("Bad Request", 400);
    }

    let request_id = ctx.param("id")
        .ok_or_else(|| worker::Error::RustError("missing id".into()))?
        .to_owned();

    let del_repo  = CloudflareDeletionRequestRepository::new(&ctx.env);
    let user_repo = CloudflareUserRepository::new(&ctx.env);

    // D8: validate the tenant before anything else.
    let req_row = match del_repo.find_by_id(&request_id).await.ok().flatten() {
        Some(r) if r.tenant_id == ctx_ta.tenant.id => r,
        _ => return Response::error("not found", 404),
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let cfg = Config::from_env(&ctx.env)?;

    match deletion::execute_deletion(&del_repo, &user_repo, &request_id, &ctx_ta.principal.id, now).await {
        Ok(()) => {
            audit::write_owned(
                &ctx.env, EventKind::DeletionExecuted,
                Some(req_row.user_id.clone()),
                None,
                Some(format!("request:{request_id} admin-triggered by:{}", ctx_ta.principal.id)),
            ).await.ok();
            log::emit(&cfg.log, Level::Warn, Category::Auth,
                &format!("deletion-request {request_id} executed by admin"),
                Some(&req_row.user_id));
            let mut resp = Response::empty()?.with_status(303);
            let _ = resp.headers_mut().set(
                "location",
                &format!("/admin/t/{}/deletion-requests", ctx_ta.tenant.slug),
            );
            Ok(resp)
        }
        // D7: a rejected request (not pending any more) writes no event.
        Err(_) => Response::error("deletion request is not pending", 409),
    }
}
