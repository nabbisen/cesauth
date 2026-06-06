//! Invitation token worker routes — RFC 046/049.
//!
//! Routes:
//!   POST /admin/t/:slug/invitations      — admin issues invitation
//!   GET  /accept-invite                  — renders accept page
//!   POST /accept-invite                  — verifies + marks accepted

use serde::Deserialize;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use cesauth_cf::ports::repo::CloudflareInvitationRepository;
use cesauth_core::invitation::{
    self, InvitationRepository, InvitationVerifyOutcome, DEFAULT_INVITE_TTL_SECS,
};

use crate::adapter::mailer;
use crate::audit::{self, EventKind};
use crate::config::Config;
use crate::log::{self, Category, Level};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenant_admin::gate;

// ---------------------------------------------------------------------------
// POST /admin/t/:slug/invitations
// ---------------------------------------------------------------------------

pub async fn issue<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c)  => c,
        Err(r) => return Ok(r),
    };

    if let Err(r) = gate::check_write(
        &ctx_ta,
        cesauth_core::authz::types::PermissionCatalog::MEMBER_ADD,
        &ctx,
    ).await? {
        return Ok(r);
    }

    let form = req.form_data().await?;
    let email = match form.get("email") {
        Some(worker::FormEntry::Field(v)) if !v.is_empty() => v,
        _ => return render::form_error("email required"),
    };
    let role = match form.get("role") {
        Some(worker::FormEntry::Field(v)) if !v.is_empty() => v,
        _ => return render::form_error("role required"),
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let cfg = Config::from_env(&ctx.env)?;

    let inv_repo = CloudflareInvitationRepository::new(&ctx.env);

    let inv = match invitation::issue_invitation(
        &inv_repo,
        &ctx_ta.tenant.id,
        &email,
        &role,
        &ctx_ta.principal.id,
        DEFAULT_INVITE_TTL_SECS,
        now,
    ).await {
        Ok(i) => i,
        Err(cesauth_core::CoreError::Conflict) => {
            log::emit(&cfg.log, Level::Warn, Category::Auth,
                &format!("duplicate invitation for {email} in tenant {}", ctx_ta.tenant.slug),
                Some(&ctx_ta.principal.id));
            return render::html_response("<html><body><p>A pending invitation for this email already exists. Please wait for it to expire or have an admin revoke it.</p></body></html>");
        }
        Err(e) => {
            log::emit(&cfg.log, Level::Error, Category::Storage,
                &format!("issue_invitation failed: {e:?}"),
                Some(&ctx_ta.principal.id));
            return Response::error("internal error", 500);
        }
    };

    // Send invite email via the mailer port.
    let accept_url = format!("{}/accept-invite?id={}&email={}",
        cfg.issuer, inv.id, urlencoding(&inv.email));
    let payload = cesauth_core::magic_link::MagicLinkPayload {
        recipient: &inv.email,
        handle:    &inv.id,
        code:      &accept_url,   // the "code" IS the full accept URL for invitations
        locale:    crate::i18n::locale_str(crate::i18n::Locale::default()),
        reason:    cesauth_core::magic_link::MagicLinkReason::InitialAuth,
    };
    let mailer_inst = mailer::from_env(&ctx.env);
    if let Err(e) = mailer_inst.send(&payload).await {
        log::emit(&cfg.log, Level::Warn, Category::Magic,
            &format!("invitation mailer failed: kind={}", e.audit_kind()),
            Some(&inv.email));
        // Don't fail the request: invitation was created; operator can resend.
    }

    audit::write_owned(
        &ctx.env, EventKind::InvitationIssued,
        Some(ctx_ta.principal.id.clone()),
        None,
        Some(format!("tenant:{} email:{} role:{}", ctx_ta.tenant.slug, inv.email, inv.role)),
    ).await.ok();

    let mut resp = Response::empty()?.with_status(303);
    let _ = resp.headers_mut().set(
        "location",
        &format!("/admin/t/{}/users?invited=1", ctx_ta.tenant.slug),
    );
    Ok(resp)
}

// ---------------------------------------------------------------------------
// GET /accept-invite?id=...&email=...
// ---------------------------------------------------------------------------

pub async fn accept_page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let url = req.url()?;
    let params: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    let invite_id = params.get("id").cloned().unwrap_or_default();
    let email     = params.get("email").cloned().unwrap_or_default();

    if invite_id.is_empty() || email.is_empty() {
        return Response::error("invite id and email are required", 400);
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let inv_repo = CloudflareInvitationRepository::new(&ctx.env);

    let outcome = match invitation::verify_invitation(&inv_repo, &invite_id, &email, now).await {
        Ok(o)  => o,
        Err(_) => return Response::error("internal error", 500),
    };

    let body = match outcome {
        InvitationVerifyOutcome::Valid(inv) => {
            let csrf = crate::csrf::mint().map_err(|_| worker::Error::RustError("csrf".into()))?;
            format!(
                r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Accept Invitation</title></head>
<body>
<h1>You've been invited!</h1>
<p>You have been invited to join <strong>{tenant}</strong>.</p>
<p>To accept this invitation, complete your registration using the magic link
sent to <strong>{email}</strong>.</p>
<form method="POST" action="/accept-invite">
  <input type="hidden" name="invite_id" value="{id}">
  <input type="hidden" name="email" value="{email}">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <button type="submit">Accept invitation</button>
</form>
</body></html>"#,
                tenant = inv.tenant_id,
                email  = inv.email,
                id     = inv.id,
                csrf   = csrf,
            )
        }
        InvitationVerifyOutcome::Expired =>
            "<html><body><p>This invitation has expired. Please request a new one.</p></body></html>".to_owned(),
        InvitationVerifyOutcome::Revoked =>
            "<html><body><p>This invitation was revoked. Please contact your admin.</p></body></html>".to_owned(),
        InvitationVerifyOutcome::AlreadyAccepted =>
            "<html><body><p>This invitation was already accepted. Please sign in.</p></body></html>".to_owned(),
        InvitationVerifyOutcome::NotFound =>
            "<html><body><p>Invitation not found. The link may be invalid.</p></body></html>".to_owned(),
    };

    render::html_response(body)
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
    let inv_repo = CloudflareInvitationRepository::new(&ctx.env);

    let outcome = match invitation::verify_invitation(&inv_repo, &invite_id, &email, now).await {
        Ok(o)  => o,
        Err(_) => return Response::error("internal error", 500),
    };

    let inv = match outcome {
        InvitationVerifyOutcome::Valid(i) => i,
        InvitationVerifyOutcome::Expired =>
            return render::html_response("<html><body>Invitation expired.</body></html>"),
        InvitationVerifyOutcome::Revoked =>
            return render::html_response("<html><body>Invitation revoked.</body></html>"),
        InvitationVerifyOutcome::AlreadyAccepted =>
            return render::html_response("<html><body>Already accepted. Please sign in.</body></html>"),
        InvitationVerifyOutcome::NotFound =>
            return Response::error("invitation not found", 404),
    };

    // Mark invitation accepted. The actual user account creation happens
    // when the user completes the Magic Link or WebAuthn registration flow
    // that we redirect them into.  For now, mark "accepted" optimistically
    // so the invite can't be replayed, and redirect to the magic-link
    // request page pre-filled with the email.
    if let Err(e) = invitation::accept_invitation(&inv_repo, &inv.id, "pending-registration", now).await {
        log::emit(&cfg.log, Level::Error, Category::Auth,
            &format!("accept_invitation mark failed: {e:?}"),
            Some(&inv.email));
        return Response::error("internal error", 500);
    }

    audit::write_owned(
        &ctx.env, EventKind::InvitationAccepted,
        None, None,
        Some(format!("invite:{} email:{} tenant:{}", inv.id, inv.email, inv.tenant_id)),
    ).await.ok();

    // Redirect to magic-link request page with email pre-filled.
    let cfg = Config::from_env(&ctx.env)?;
    let redirect = format!("/magic-link/request?email={}&invite_id={}",
        urlencoding(&inv.email), inv.id);
    let mut resp = Response::empty()?.with_status(303);
    let _ = resp.headers_mut().set("location", &redirect);
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn urlencoding(s: &str) -> String {
    s.chars().flat_map(|c| {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            vec![c]
        } else {
            format!("%{:02X}", c as u32).chars().collect()
        }
    }).collect()
}

// ---------------------------------------------------------------------------
// GET /admin/t/:slug/invitations  (RFC 066)
// ---------------------------------------------------------------------------

pub async fn list<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c)  => c,
        Err(r) => return Ok(r),
    };

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let inv_repo = cesauth_cf::ports::repo::CloudflareInvitationRepository::new(&ctx.env);

    let invitations = match cesauth_core::invitation::InvitationRepository::list_pending_by_tenant(
        &inv_repo, &ctx_ta.tenant.id, now,
    ).await {
        Ok(v)  => v,
        Err(_) => vec![],
    };

    render::html_response(cesauth_ui::tenant_admin::invitations::invitations_page(
        &ctx_ta.principal,
        &ctx_ta.tenant,
        &invitations,
        now,
    ))
}
