//! Invitation token worker routes — RFC 046/049/153.
//!
//! Routes:
//!   POST /admin/t/:slug/invitations           — admin issues invitation
//!   GET  /admin/t/:slug/invitations.json      — list pending + CSRF token
//!   POST /admin/t/:slug/invitations/:id/revoke — admin revokes (RFC 153)
//!   GET  /accept-invite                       — renders accept page
//!   POST /accept-invite                       — verifies, renders the
//!                                                continue-to-sign-in page
//!                                                (RFC 153: does NOT mark
//!                                                accepted — see `accept_submit`)

use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use cesauth_cf::ports::repo::CloudflareInvitationRepository;
use cesauth_core::invitation::{
    self, InvitationRepository, InvitationVerifyOutcome, DEFAULT_INVITE_TTL_SECS,
};
use cesauth_core::magic_link::MagicLinkMailer;

use crate::adapter::mailer;
use crate::audit::{self, EventKind};
use crate::config::Config;
use crate::log::{self, Category, Level};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenant_admin::gate;

/// Return a simple HTML error page for form validation failures.
fn form_error(msg: &str) -> Result<Response> {
    render::html_response(|| format!(
        "<html><head><title>Error</title></head><body><p>{}</p></body></html>",
        msg
    ))
}

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

    if let Err(r) = gate::check_action(
        &ctx_ta,
        cesauth_core::authz::types::PermissionCatalog::GROUP_MEMBER_ADD,
        cesauth_core::authz::types::ScopeRef::Tenant { tenant_id: &ctx_ta.tenant.id },
        &ctx,
    ).await? {
        return Ok(r);
    }

    let form = req.form_data().await?;
    let email = match form.get("email") {
        Some(worker::FormEntry::Field(v)) if !v.is_empty() => v,
        _ => return form_error("email required"),
    };
    let role = match form.get("role") {
        Some(worker::FormEntry::Field(v)) if !v.is_empty() => v,
        _ => return form_error("role required"),
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
            return render::html_response(|| "<html><body><p>A pending invitation for this email already exists. Please wait for it to expire or have an admin revoke it.</p></body></html>".to_owned());
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
        recipient:  &inv.email,
        handle:     &inv.id,
        code:       &accept_url,   // the "code" IS the full accept URL for invitations
        locale:     crate::i18n::locale_str(cesauth_core::i18n::Locale::default()),
        reason:     cesauth_core::magic_link::MagicLinkReason::InitialAuth,
        tenant_id:  Some(&ctx_ta.tenant.id),
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

    // RFC 146 §5 gate 2: `body` is built here, outside the `html_response`
    // closure below, because the `Valid` arm's `crate::csrf::mint()?` uses
    // `?` against this function's own `Result` — a `FnOnce() -> String`
    // closure cannot propagate that. Reported rather than restructured
    // (moving the mint unconditionally earlier would mint a CSRF token,
    // and risk failing closed, on the four outcomes that never needed one
    // before). Dormant, not live: this template never calls
    // `crate::render_nonce()` — no `<style nonce>` here — so today's
    // CSP header's unused nonce token is the only thing this site's
    // pre-fix ordering affects, and it affects nothing a reader can see.
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

    render::html_response(|| body)
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
            return render::html_response(|| "<html><body>Invitation expired.</body></html>".to_owned()),
        InvitationVerifyOutcome::Revoked =>
            return render::html_response(|| "<html><body>Invitation revoked.</body></html>".to_owned()),
        InvitationVerifyOutcome::AlreadyAccepted =>
            return render::html_response(|| "<html><body>Already accepted. Please sign in.</body></html>".to_owned()),
        InvitationVerifyOutcome::NotFound =>
            return Response::error("invitation not found", 404),
    };

    // **RFC 153 §3.** Nothing is accepted here. The invitation stays
    // `pending` — `accept_invitation` now runs only once an account
    // genuinely exists, in `magic_link::verify::complete_invitation` — so
    // a user who verifies this far and then abandons the flow (closes the
    // tab, never checks email) can simply start over: `accept_page` will
    // find the row still pending and still usable, not "already accepted"
    // with no account behind it.
    //
    // **RFC 153 §4.** This used to 303-redirect to
    // `/magic-link/request?email=…&invite_id=…` — a GET URL to a route
    // registered POST-only (`lib.rs`), so the browser's follow-up GET hit
    // the catchall 404. `invite_id` being discarded was never the first
    // problem; the user never reached anywhere that could discard it.
    // Rendering the continuation directly, with a real form, fixes both.
    let csrf = match crate::csrf::mint() {
        Ok(t)  => t,
        Err(_) => return Response::error("service temporarily unavailable", 500),
    };
    let set_cookie = crate::csrf::set_cookie_header(&csrf);
    let body = accept_continue_page(&inv.email, &inv.id, &csrf);
    let mut resp = render::html_response(|| body)?;
    resp.headers_mut().append("set-cookie", &set_cookie).ok();
    Ok(resp)
}

/// Pure render for `accept_submit`'s continuation page — pulled out of the
/// handler so the escaping and the form's three fields are host-testable
/// without a `worker::Env` (RFC 143's `decide_verify_*` / `render_*_page`
/// precedent: separate the string-building from the Env-touching parts).
fn accept_continue_page(email: &str, invite_id: &str, csrf: &str) -> String {
    format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Invitation accepted</title></head>
<body>
<h1>Almost there</h1>
<p>Send a sign-in code to <strong>{email}</strong> to finish setting up your account.</p>
<form method="POST" action="/magic-link/request">
  <input type="hidden" name="email" value="{email}">
  <input type="hidden" name="invite_id" value="{id}">
  <input type="hidden" name="csrf" value="{csrf}">
  <button type="submit">Send sign-in code</button>
</form>
</body></html>"#,
        email = cesauth_frontend::escape(email),
        id    = cesauth_frontend::escape(invite_id),
        csrf  = cesauth_frontend::escape(csrf),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 153 §4's continuation page: all three fields present, and an
    /// email containing HTML-significant characters does not break out of
    /// its `value="..."` attribute. The admin-supplied email is the one
    /// field here that isn't fully under this codebase's control (an
    /// operator types it at issue time), so it's the one worth a
    /// deliberately hostile fixture.
    #[test]
    fn accept_continue_page_escapes_the_email_and_carries_all_three_fields() {
        let html = accept_continue_page(
            r#"a"'><script>alert(1)</script>@example.com"#,
            "inv-123",
            "csrf-abc",
        );
        assert!(!html.contains("<script>"),
            "an email containing markup must not inject into the page: {html}");
        assert!(html.contains(r#"name="invite_id" value="inv-123""#));
        assert!(html.contains(r#"name="csrf" value="csrf-abc""#));
        assert!(html.contains(r#"action="/magic-link/request""#));
    }

    #[test]
    fn accept_continue_page_carries_a_well_formed_email_unescaped_to_the_eye() {
        let html = accept_continue_page("alice@example.com", "inv-1", "tok");
        assert!(html.contains(r#"name="email" value="alice@example.com""#));
    }
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
    crate::routes::leptos_shell::leptos_html_shell(&req, &ctx.env, "Invitations — cesauth", "en").await
}

/// **RFC 153.** Before this, the handler read neither `req` nor `ctx` — no
/// auth, no tenant gate — because it returned nothing but a CSRF token.
/// Now that it also returns the tenant's pending invitations (email
/// addresses, roles), it needs the same gate `issue` already has; reusing
/// `TENANT_READ` rather than `issue`'s `GROUP_MEMBER_ADD` because this is
/// a read, not the action that permission names.
pub async fn list_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
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
    ).await? {
        return Ok(r);
    }

    let now      = OffsetDateTime::now_utc().unix_timestamp();
    let inv_repo = CloudflareInvitationRepository::new(&ctx.env);
    let pending  = inv_repo.list_pending_by_tenant(&ctx_ta.tenant.id, now).await.unwrap_or_default();

    let rows: Vec<serde_json::Value> = pending.iter().map(|i| serde_json::json!({
        "id":         i.id,
        "email":      i.email,
        "role":       i.role,
        "issued_at":  i.issued_at,
        "expires_at": i.expires_at,
    })).collect();

    let csrf_token = match crate::csrf::mint() {
        Ok(t)  => t,
        Err(_) => return Response::error("service temporarily unavailable", 500),
    };
    let set_cookie = crate::csrf::set_cookie_header(&csrf_token);
    let mut resp = Response::from_json(&serde_json::json!({
        "csrf_token":  csrf_token,
        "invitations": rows,
    }))?;
    resp.headers_mut().append("set-cookie", &set_cookie).ok();
    resp.headers_mut().set("cache-control", "no-store").ok();
    Ok(resp)
}

// ---------------------------------------------------------------------------
// POST /admin/t/:slug/invitations/:id/revoke
// ---------------------------------------------------------------------------

/// **RFC 153 §3.** `core::invitation::revoke_invitation` has existed since
/// RFC 046/049 with no route reaching it — `revoked_at`/`revoked_by` have
/// never held a value in production (RFC 153 §2's own finding). Same gate
/// and CSRF shape as `issue`: `SameSite=Strict` is the real control
/// (`route-contracts.md` records `issue`'s row as `N/A (SameSite=Strict)`),
/// so this needs no double-submit token either.
pub async fn revoke<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c)  => c,
        Err(r) => return Ok(r),
    };
    if let Err(r) = gate::check_action(
        &ctx_ta,
        cesauth_core::authz::types::PermissionCatalog::GROUP_MEMBER_ADD,
        cesauth_core::authz::types::ScopeRef::Tenant { tenant_id: &ctx_ta.tenant.id },
        &ctx,
    ).await? {
        return Ok(r);
    }

    let invite_id = match ctx.param("id") {
        Some(s) => s.clone(),
        None    => return Response::error("missing id", 400),
    };

    let inv_repo = CloudflareInvitationRepository::new(&ctx.env);

    // Validate the tenant before anything else — same discipline as
    // deletion-requests' D8 (`admin_cancel`/`admin_execute`): a request
    // naming another tenant's invitation id is a 404, not a 403 that
    // would confirm the id exists.
    let inv = match inv_repo.find_by_id(&invite_id).await.ok().flatten() {
        Some(i) if i.tenant_id == ctx_ta.tenant.id => i,
        _ => return Response::error("not found", 404),
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    if let Err(e) = invitation::revoke_invitation(&inv_repo, &invite_id, &ctx_ta.principal.id, now).await {
        let cfg = Config::from_env(&ctx.env)?;
        log::emit(&cfg.log, Level::Error, Category::Auth,
            &format!("revoke_invitation failed: {e:?}"),
            Some(&ctx_ta.principal.id));
        return Response::error("internal error", 500);
    }

    // Subject = the issuing/revoking admin, matching `InvitationIssued`'s
    // own convention just above in this file — there is no affected-user
    // id to use instead; the invitee never became one.
    audit::write_owned(
        &ctx.env, EventKind::InvitationRevoked,
        Some(ctx_ta.principal.id.clone()),
        None,
        Some(format!("invite:{} email:{} tenant:{}", inv.id, inv.email, ctx_ta.tenant.slug)),
    ).await.ok();

    let mut resp = Response::empty()?.with_status(303);
    let _ = resp.headers_mut().set(
        "location",
        &format!("/admin/t/{}/invitations", ctx_ta.tenant.slug),
    );
    Ok(resp)
}
