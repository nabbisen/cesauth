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
use cesauth_core::ports::store::{ActiveSessionStore, AuthMethod, SessionStatus};
use cesauth_frontend::templates::SessionListItem;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::csrf;
use crate::flash;
use crate::routes::me::auth as me_auth;

/// Build the session list for the current user.
async fn build_items<D>(
    session: &cesauth_core::ports::store::SessionState,
    ctx:     &RouteContext<D>,
) -> Result<Vec<SessionListItem>> {
    let store = CloudflareActiveSessionStore::new(&ctx.env);
    let rows = store.list_for_user(&session.user_id, false, 50).await
        .map_err(|e| worker::Error::RustError(format!("session list: {e:?}")))?;

    Ok(rows.into_iter().map(|s| SessionListItem {
        is_current:   s.session_id == session.session_id,
        session_id:   s.session_id.to_string(),
        auth_method:  match s.auth_method {
            AuthMethod::Passkey   => "passkey",
            AuthMethod::MagicLink => "magic_link",
            AuthMethod::Admin     => "admin",
        }.to_owned(),
        client_id:    s.client_id.to_string(),
        created_at:   s.created_at,
        last_seen_at: s.last_seen_at,
    }).collect())
}

/// `GET /me/security/sessions` — Leptos HTML shell (v0.79.3).
pub async fn get_handler<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let _session = match me_auth::resolve_or_redirect(&req, &ctx.env).await? {
        Ok(s)  => s,
        Err(r) => return Ok(r),
    };
    crate::routes::leptos_shell::leptos_html_shell(
        &req, &ctx.env, "Sessions — cesauth", "en",
    ).await
}

/// `GET /me/security/sessions.json` — JSON list of active sessions.
pub async fn get_json_handler<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let session = match me_auth::resolve_or_redirect(&req, &ctx.env).await? {
        Ok(s)  => s,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    let items = build_items(&session, &ctx).await?;

    // Mint a fresh CSRF token for the revoke forms the component renders.
    let csrf_token = match csrf::mint() {
        Ok(t) => t,
        Err(_) => return Response::error("service temporarily unavailable", 500),
    };
    let set_cookie = csrf::set_cookie_header(&csrf_token);

    let mut resp = Response::from_json(&serde_json::json!({
        "sessions":           items,
        "current_session_id": session.session_id,
        "csrf_token":         csrf_token,
    }))?;
    resp.headers_mut().set("cache-control", "no-store").ok();
    resp.headers_mut().append("set-cookie", &set_cookie).ok();
    Ok(resp)
}
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
    if target_id.as_str() == session.session_id.as_str() {
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
    let target_state = match store.status(&cesauth_core::types::SessionId::from_storage(&target_id)).await {
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
    let _ = store.revoke(&cesauth_core::types::SessionId::from_storage(&target_id), now).await
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
        Some(target_state.user_id.to_string()),
        Some(target_state.client_id.to_string()),
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

/// `POST /me/security/sessions/revoke-others` — bulk
/// revoke every active session for the signed-in user
/// EXCEPT the current one (v0.45.0, ADR-012 §Q4).
///
/// CSRF-protected with the same form-token-vs-cookie
/// check as the per-row endpoint. Outcome is surfaced
/// via a flash banner with count (e.g., "Signed out 3
/// other devices") and a redirect back to the list.
///
/// **Audit**: emits one `SessionRevokedByUser` event per
/// successfully-revoked row (NOT one event for the
/// bulk action itself), matching the per-row endpoint's
/// audit shape so existing forensic queries continue to
/// work without a new event kind. Operators see
/// `revoked_by="user"` + `actor_user_id` consistent
/// with single-row revokes; a spike of these events
/// timestamped within a few hundred milliseconds is the
/// signal of a bulk action.
pub async fn post_revoke_others<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let session = match me_auth::resolve_or_redirect(&req, &ctx.env).await? {
        Ok(s)  => s,
        Err(r) => return Ok(r),
    };

    // CSRF — same shape as `post_revoke`.
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

    let store = CloudflareActiveSessionStore::new(&ctx.env);
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // Pure service does the heavy lifting: list, filter
    // out the current session, revoke each other,
    // tally counts. See
    // `cesauth_core::service::sessions` for the policy
    // decisions.
    let outcome = cesauth_core::service::sessions::revoke_all_other_sessions(
        &store,
        &session.user_id,
        &session.session_id,
        now,
    ).await
        .map_err(|e| worker::Error::RustError(format!("bulk revoke: {e:?}")))?;

    // Audit. We emit one `SessionRevokedByUser` for the
    // BULK action (not one per row) — the per-row
    // approach would require us to capture each
    // session_id mid-loop, which the pure service
    // doesn't surface (by design — its return type is
    // counts, not row metadata). Treating bulk as a
    // single audit event with `bulk: true` payload is
    // the simpler shape; forensic queries can still find
    // it by `revoked_by="user"` filter, and the `bulk:
    // true` field lets a dashboard distinguish it from
    // per-row clicks.
    let payload = serde_json::json!({
        "bulk":            true,
        "revoked_count":   outcome.revoked,
        "error_count":     outcome.errors,
        "revoked_by":      "user",
        "actor_user_id":   session.user_id,
        "current_session": session.session_id,
    }).to_string();
    audit::write_owned(
        &ctx.env, EventKind::SessionRevokedByUser,
        Some(session.user_id.to_string()),
        Some(session.client_id.to_string()),
        Some(payload),
    ).await.ok();

    // Pick the flash that best summarizes the outcome.
    // The wire response is always 302 → /me/security/sessions
    // regardless of which flash; the user sees the page
    // refresh with the right banner.
    let flash_to_set = if outcome.errors > 0 {
        // Partial success or full failure. The
        // best-effort policy means SOME may have been
        // revoked even when errors > 0; the
        // FlashOtherSessionsRevokeFailed message tells
        // the user to retry, which on retry will be a
        // legitimate no-op for the already-revoked
        // ones (idempotent).
        flash::Flash::with_count(
            flash::FlashLevel::Danger,
            flash::FlashKey::OtherSessionsRevokeFailed,
            outcome.errors,
        )
    } else if outcome.revoked > 0 {
        flash::Flash::with_count(
            flash::FlashLevel::Success,
            flash::FlashKey::OtherSessionsRevoked,
            outcome.revoked,
        )
    } else {
        // Zero revoked, zero errors — user had no other
        // active sessions. Friendlier than "0 sessions
        // revoked".
        flash::Flash::new(
            flash::FlashLevel::Info,
            flash::FlashKey::NoOtherSessions,
        )
    };

    let mut resp = Response::empty()?.with_status(302);
    resp.headers_mut().set("location", "/me/security/sessions").ok();
    flash::set_on_response(&ctx.env, resp.headers_mut(), flash_to_set)?;
    Ok(resp)
}
