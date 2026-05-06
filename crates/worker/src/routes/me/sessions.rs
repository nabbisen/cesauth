//! `/me/security/sessions` — user-facing session list + revoke
//! handlers (v0.35.0, ADR-012).
//!
//! `GET /me/security/sessions` renders all of the signed-in
//! user's active sessions with a revoke button per row. The
//! current session's button is disabled (revoking the session
//! you're currently using is structurally the logout flow's
//! job).
//!
//! `POST /me/security/sessions/:session_id/revoke` revokes a
//! session that BELONGS TO the signed-in user. The user_id
//! check is the primary defense against revoking another
//! user's session via a forged session_id; the page renders
//! only the current user's sessions, so the user_id mismatch
//! case shouldn't arise in practice, but we enforce it
//! defensively.

use cesauth_cf::ports::store::CloudflareActiveSessionStore;
use cesauth_core::ports::store::{ActiveSessionStore, SessionStatus};
use cesauth_ui::templates::{sessions_page, SessionListItem};
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::csrf;
use crate::flash;
use crate::routes::me::auth as me_auth;

/// `GET /me/security/sessions` — list active sessions for the
/// signed-in user.
pub async fn get_handler<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let session = match me_auth::resolve_or_redirect(&req, &ctx.env).await? {
        Ok(s)  => s,
        Err(r) => return Ok(r),
    };

    let store = CloudflareActiveSessionStore::new(&ctx.env);

    // 50 is enough for any plausible user. If a user has more
    // than 50 active sessions something is unusual; the
    // revoke-all flow is a future feature (ADR-012 §"Open
    // questions").
    let rows = store.list_for_user(&session.user_id, false, 50).await
        .map_err(|e| worker::Error::RustError(format!("session list failed: {e:?}")))?;

    let items: Vec<SessionListItem> = rows.into_iter().map(|s| SessionListItem {
        is_current:    s.session_id == session.session_id,
        session_id:    s.session_id,
        auth_method:   match s.auth_method {
            cesauth_core::ports::store::AuthMethod::Passkey   => "passkey",
            cesauth_core::ports::store::AuthMethod::MagicLink => "magic_link",
            cesauth_core::ports::store::AuthMethod::Admin     => "admin",
        }.to_owned(),
        client_id:     s.client_id,
        created_at:    s.created_at,
        last_seen_at:  s.last_seen_at,
    }).collect();

    // CSRF for the per-row POST forms. Reuse cookie token if
    // present; mint a fresh one otherwise.
    let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();
    let existing = csrf::extract_from_cookie_header(&cookie_header).map(str::to_owned);
    let (token, set_cookie) = match existing {
        Some(t) if !t.is_empty() => (t, None),
        _ => {
            let t = csrf::mint();
            let h = csrf::set_cookie_header(&t);
            (t, Some(h))
        }
    };

    // Flash banner support (e.g., post-revoke success).
    let (flash_msg, clear_header) = flash::take_from_request(&ctx.env, &cookie_header);
    let flash_view = flash_msg.map(flash::render_view);
    let flash_html = cesauth_ui::templates::flash_block(flash_view);

    let html = sessions_page(&items, &token, &flash_html);
    let mut resp = Response::from_html(html)?;
    if let Some(h) = set_cookie {
        resp.headers_mut().append("set-cookie", &h).ok();
    }
    resp.headers_mut().append("set-cookie", &clear_header).ok();
    Ok(resp)
}

/// `POST /me/security/sessions/:session_id/revoke` — revoke a
/// specific session belonging to the signed-in user.
pub async fn post_revoke<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let session = match me_auth::resolve_or_redirect(&req, &ctx.env).await? {
        Ok(s)  => s,
        Err(r) => return Ok(r),
    };

    // CSRF.
    let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();
    let form = req.form_data().await?;
    let csrf_form = match form.get("csrf") {
        Some(worker::FormEntry::Field(v)) => v,
        _ => String::new(),
    };
    let csrf_cookie = csrf::extract_from_cookie_header(&cookie_header).unwrap_or("");
    if !csrf::verify(&csrf_form, csrf_cookie) {
        return Response::error("Bad Request", 400);
    }

    // Path param.
    let target_id = match ctx.param("session_id") {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => return Response::error("missing session_id", 400),
    };

    // Refuse to revoke the current session via this endpoint —
    // that's the logout flow's job, and doing it here would
    // surprise the user (they POST and then get redirected
    // through the login screen instead of a clean logout
    // page). The UI's button is disabled for the current row,
    // so this branch is just defensive.
    if target_id == session.session_id {
        return Response::error(
            "use the logout flow to end the current session",
            400,
        );
    }

    let store = CloudflareActiveSessionStore::new(&ctx.env);

    // Ownership check: peek the session, refuse if it belongs
    // to a different user. Without this an attacker who
    // somehow got a session_id from another user could revoke
    // it through this endpoint by submitting a CSRF-valid
    // form. In practice the page only renders THIS user's
    // sessions, so the attacker would have to forge the id
    // (UUIDv4 search is cryptographically unlikely), but
    // defense in depth.
    let target_state = match store.status(&target_id).await {
        Ok(SessionStatus::Active(s))  => s,
        // Already revoked / never started: no-op success
        // (don't leak the existence-check by returning a
        // distinct error).
        Ok(_) => return Ok(redirect_back("revoked").map_err(|e| worker::Error::RustError(format!("redirect: {e:?}")))?),
        Err(e) => return Err(worker::Error::RustError(format!("session lookup: {e:?}"))),
    };
    if target_state.user_id != session.user_id {
        return Response::error("forbidden", 403);
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let _ = store.revoke(&target_id, now).await
        .map_err(|e| worker::Error::RustError(format!("session revoke: {e:?}")))?;

    // Audit. The kind distinguishes user-initiated revocation
    // from admin-initiated, which the v0.35.0 audit split
    // adds. Payload carries who-revoked-whom for forensic
    // surfaces.
    let payload = serde_json::json!({
        "session_id":    target_id,
        "revoked_by":    "user",
        "actor_user_id": session.user_id,
    }).to_string();
    audit::write_owned(
        &ctx.env, EventKind::SessionRevokedByUser,
        Some(target_state.user_id),
        Some(target_state.client_id),
        Some(payload),
    ).await.ok();

    // Set a success flash. The redirect target's GET handler
    // consumes it via take_from_request and clears the cookie.
    let mut resp = Response::empty()?.with_status(302);
    resp.headers_mut().set("location", "/me/security/sessions").ok();
    flash::set_on_response(
        &ctx.env,
        resp.headers_mut(),
        flash::Flash::new(flash::FlashLevel::Success, flash::FlashKey::SessionRevoked),
    )?;
    Ok(resp)
}

fn redirect_back(_outcome: &str) -> std::result::Result<Response, worker::Error> {
    let mut resp = Response::empty()?.with_status(302);
    resp.headers_mut().set("location", "/me/security/sessions").ok();
    Ok(resp)
}
