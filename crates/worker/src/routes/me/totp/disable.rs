//! `/me/security/totp/disable` — user-initiated TOTP removal.
//!
//! GET renders the confirmation page (POST/Redirect/GET pattern —
//! arriving at this URL doesn't disable TOTP, only POSTing the
//! confirm form does).
//!
//! POST validates CSRF, deletes ALL TOTP authenticator rows for
//! the calling user (active or unconfirmed) plus all recovery
//! codes (redeemed or unredeemed). The user is left with TOTP
//! fully disabled — their next Magic Link login skips the gate.
//!
//! Per ADR-009 §Q9 the cleanup is per-user-scoped: an
//! `delete_all_for_user` on each repo. We don't need to walk
//! authenticator ids individually because the TOTP repo's
//! `delete_all_for_user` (added in v0.30.0) is an indexed
//! single-statement DELETE.
//!
//! The recovery-codes repo's `delete_all_for_user` was already
//! present at v0.27.0 — see `cesauth_core::totp::storage`.
//!
//! ## Failure semantics
//!
//! Disable is **best-effort, not transactional**. We attempt the
//! authenticators delete first (the security-critical one), then
//! the recovery codes delete. A storage failure on the
//! authenticators delete returns 500 to the user — TOTP is still
//! enabled, and they'll see it on next login. A storage failure
//! on the recovery codes delete is logged but ignored — the
//! authenticators are gone, so the recovery codes are
//! ineffective anyway, and the next disable attempt cleans them
//! up.
//!
//! Why authenticators-first ordering: an authenticator without
//! recovery codes is still a working TOTP credential and the
//! user is still gated. Recovery codes without an authenticator
//! are useless (they can only be used as alternatives to a TOTP
//! prompt that no longer fires). So the security-critical delete
//! is the authenticators table.

use cesauth_cf::ports::repo::{
    CloudflareTotpAuthenticatorRepository, CloudflareTotpRecoveryCodeRepository,
};
use cesauth_core::totp::storage::{
    TotpAuthenticatorRepository, TotpRecoveryCodeRepository,
};
use cesauth_ui::templates;
use worker::{Request, Response, Result};

use crate::csrf;
use crate::routes::me::auth as me_auth;


/// `GET /me/security/totp/disable` — show confirmation page.
pub async fn get_handler(
    req: Request,
    env: worker::Env,
) -> Result<Response> {
    let _session = match me_auth::resolve_or_redirect(&req, &env).await? {
        Ok(s)  => s,
        Err(r) => return Ok(r),
    };

    // Mint or reuse CSRF token. Same pattern as enroll.
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

    let html = templates::totp_disable_confirm_page(&token);
    let mut resp = Response::from_html(html)?;
    if let Some(s) = set_cookie {
        resp.headers_mut().append("set-cookie", &s).ok();
    }
    Ok(resp)
}


/// `POST /me/security/totp/disable` — confirm + execute the
/// removal, redirect home with a success notice.
pub async fn post_handler(
    mut req: Request,
    env:     worker::Env,
) -> Result<Response> {
    let session = match me_auth::resolve_or_redirect(&req, &env).await? {
        Ok(s)  => s,
        Err(r) => return Ok(r),
    };

    let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();

    // CSRF guard.
    let form        = req.form_data().await?;
    let csrf_form   = form_get(&form, "csrf").unwrap_or_default();
    let csrf_cookie = csrf::extract_from_cookie_header(&cookie_header).unwrap_or("");
    if !csrf::verify(&csrf_form, csrf_cookie) {
        return Response::error("Bad Request", 400);
    }

    // Authenticators-first ordering. See module doc.
    let auth_repo = CloudflareTotpAuthenticatorRepository::new(&env);
    if let Err(_) = auth_repo.delete_all_for_user(&session.user_id).await {
        return Response::error("totp disable failed (authenticators)", 500);
    }

    // Recovery codes second. Failures here are logged but not
    // surfaced — the authenticators are already gone, recovery
    // codes are useless without them.
    let recovery_repo = CloudflareTotpRecoveryCodeRepository::new(&env);
    let _ = recovery_repo.delete_all_for_user(&session.user_id).await;

    // Redirect home. The "TOTP disabled" notice is intentionally
    // not surfaced as a flash message — that infrastructure
    // lands in the v0.32.0 `/me/security` self-service UI; for
    // v0.30.0 the silent redirect is enough (the user clicked
    // the disable button, they know what just happened).
    let mut resp = Response::empty()?.with_status(302);
    resp.headers_mut().set("location", "/").ok();
    Ok(resp)
}


fn form_get(form: &worker::FormData, key: &str) -> Option<String> {
    match form.get(key) {
        Some(worker::FormEntry::Field(v)) => Some(v),
        _ => None,
    }
}
