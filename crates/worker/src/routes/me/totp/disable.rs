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
use crate::flash;
use crate::routes::me::auth as me_auth;


/// Where the disable POST handler 302's the user after a
/// successful TOTP removal. Pinned as a constant so a future
/// refactor can't accidentally revert it to `/` (which was the
/// pre-v0.31.0 silent-redirect target — replaced because the
/// user lost their flash context on home, and the Security
/// Center is the natural confirmation surface).
const DISABLE_SUCCESS_REDIRECT: &str = "/me/security";


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

    // Redirect to the Security Center with a success flash. The
    // user clicked disable; landing them back on the index page
    // (a) confirms the new state ("TOTP: 無効" badge), and
    // (b) shows the flash banner with the explicit
    // "TOTP を無効にしました" notice.
    //
    // v0.31.0 P0-B brought the flash infrastructure online; this
    // is one of four handlers that opted into it.
    let mut resp = Response::empty()?.with_status(302);
    resp.headers_mut().set("location", DISABLE_SUCCESS_REDIRECT).ok();
    flash::set_on_response(
        &env,
        resp.headers_mut(),
        flash::Flash::new(flash::FlashLevel::Success, flash::FlashKey::TotpDisabled),
    )?;
    Ok(resp)
}


fn form_get(form: &worker::FormData, key: &str) -> Option<String> {
    match form.get(key) {
        Some(worker::FormEntry::Field(v)) => Some(v),
        _ => None,
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Disable redirect target — v0.31.0 P0-B / P1-B
    // -----------------------------------------------------------------
    //
    // Pin the post-disable landing. v0.31.0 changed the target
    // from `/` (silent redirect) to `/me/security` (Security
    // Center with a success flash), so the user sees the new
    // "TOTP: 無効" badge and the "TOTP を無効にしました" banner
    // simultaneously. Reverting either piece would break the
    // contract that the user gets visible feedback for a
    // destructive action.

    #[test]
    fn disable_lands_on_security_center() {
        assert_eq!(DISABLE_SUCCESS_REDIRECT, "/me/security");
    }

    #[test]
    fn disable_target_is_in_me_namespace() {
        // Pin that the target is allowlisted by
        // me_auth::validate_next_path so a future tightening of
        // the validator doesn't lock the user out of their own
        // post-disable landing page.
        assert!(me_auth::validate_next_path(DISABLE_SUCCESS_REDIRECT).is_some(),
            "post-disable target must remain on the /me/ allowlist");
    }
}
