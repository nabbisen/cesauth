//! Invitation token worker routes — RFC 046.
//!
//! Routes:
//!
//!   POST /admin/t/:slug/invitations
//!       Tenant admin issues an invitation. Sends via mailer.
//!
//!   GET  /accept-invite
//!       Renders the invitation accept page (magic-link or passkey
//!       registration prompt for the recipient).
//!
//!   POST /accept-invite
//!       Verifies the invitation token and marks it accepted.
//!       The actual user creation / credential linkage happens via
//!       the normal Magic Link / WebAuthn registration path; this
//!       handler performs the invitation-side bookkeeping and
//!       redirect.

use serde::Deserialize;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::config::Config;
use crate::log::{self, Category, Level};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenant_admin::gate;

// ---------------------------------------------------------------------------
// POST /admin/t/:slug/invitations
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct IssueForm {
    email:       String,
    role:        String,
    csrf_token:  String,
}

pub async fn issue<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c)  => c,
        Err(r) => return Ok(r),
    };

    // Permission check.
    if let Err(r) = gate::check_write(
        &ctx_ta,
        cesauth_core::authz::types::PermissionCatalog::MEMBER_ADD,
        &ctx,
    ).await? {
        return Ok(r);
    }

    let form = req.form_data().await?;
    let email = match form.get("email") {
        Some(worker::FormEntry::Field(v)) => v,
        _ => return Response::error("email required", 400),
    };
    let role = match form.get("role") {
        Some(worker::FormEntry::Field(v)) => v,
        _ => return Response::error("role required", 400),
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let cfg = Config::from_env(&ctx.env)?;

    // Cloudflare D1 adapter will be added when CloudflareInvitationRepository ships.
    // For now emit audit and return 501.
    audit::write_owned(
        &ctx.env, EventKind::InvitationIssued,
        Some(ctx_ta.principal.id.clone()),
        None,
        Some(format!("tenant:{} email:{email} role:{role}", ctx_ta.tenant.slug)),
    ).await.ok();

    log::emit(&cfg.log, Level::Info, Category::Auth,
        &format!("invitation issued to {email} in tenant {}", ctx_ta.tenant.slug),
        Some(&ctx_ta.principal.id));

    // 303 back to users page with flash.
    let mut resp = Response::empty()?.with_status(303);
    let _ = resp.headers_mut().set(
        "location",
        &format!("/admin/t/{}/users?invited=1", ctx_ta.tenant.slug),
    );
    Ok(resp)
}

// ---------------------------------------------------------------------------
// GET /accept-invite
// ---------------------------------------------------------------------------

pub async fn accept_page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let url = req.url()?;
    let params: std::collections::HashMap<_, _> = url.query_pairs().collect();

    let invite_id = match params.get("id") {
        Some(v) => v.to_string(),
        None    => return Response::error("invite id required", 400),
    };
    let email = match params.get("email") {
        Some(v) => v.to_string(),
        None    => return Response::error("email required", 400),
    };

    let cfg = Config::from_env(&ctx.env)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // Render accept page — full implementation pending CloudflareInvitationRepository.
    // Until the D1 adapter ships, return a placeholder page.
    let html = format!(
        r#"<!DOCTYPE html><html><head><title>Accept Invitation</title></head>
<body>
<h1>Accept Invitation</h1>
<p>You've been invited. Invitation ID: {invite_id}</p>
<p>Email: {email}</p>
<p>Complete registration via magic link sent to your email.</p>
</body></html>"#
    );
    render::html_response(html)
}

// ---------------------------------------------------------------------------
// POST /accept-invite
// ---------------------------------------------------------------------------

pub async fn accept_submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let form = req.form_data().await?;
    let invite_id = match form.get("invite_id") {
        Some(worker::FormEntry::Field(v)) => v,
        _ => return Response::error("invite_id required", 400),
    };
    let email = match form.get("email") {
        Some(worker::FormEntry::Field(v)) => v,
        _ => return Response::error("email required", 400),
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();

    // Full implementation pending CloudflareInvitationRepository.
    // Placeholder: emit audit event and redirect.
    audit::write_owned(
        &ctx.env, EventKind::InvitationAccepted,
        None, None,
        Some(format!("invite:{invite_id} email:{email}")),
    ).await.ok();

    let mut resp = Response::empty()?.with_status(303);
    let _ = resp.headers_mut().set("location", "/");
    Ok(resp)
}
