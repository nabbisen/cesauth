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


/// Outcome of the `decide_disable_post` pure decision.
///
/// Designed to be totally independent of `worker::Env`,
/// `worker::Response`, and the request body — the decision
/// captures **what should happen** in domain terms; the
/// handler maps each variant to a concrete HTTP response.
///
/// Extracted in v0.31.1 to make the handler's branching
/// behavior testable without standing up a `worker::Env` mock.
/// Tests construct in-memory `TotpAuthenticatorRepository` and
/// `TotpRecoveryCodeRepository` adapters and exercise
/// `decide_disable_post` directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisableDecision {
    /// The submitted CSRF token didn't match the cookie. Handler
    /// returns 400. We do not distinguish "no token" from "wrong
    /// token" — both are equally invalid at this layer.
    CsrfFailure,

    /// Authenticators-table delete failed. TOTP is still active
    /// for the user — the next Magic Link login will still gate
    /// on TOTP. Handler returns 500 so the user knows their
    /// disable didn't take and can retry.
    AuthDeleteError,

    /// All deletes successful (or recovery-codes-delete failed
    /// best-effort). TOTP is fully off for this user. Handler
    /// 302's to `/me/security` with a `success.totp_disabled`
    /// flash.
    Success,
}

/// Pure decision logic for `POST /me/security/totp/disable`.
///
/// Inputs:
/// - `user_id`: authenticated session subject.
/// - `csrf_form` / `csrf_cookie`: the two halves of the
///   double-submit CSRF check; `csrf::verify` compares them
///   constant-time.
/// - `auth_repo` / `recovery_repo`: storage adapters. Tests pass
///   in `InMemoryTotpAuthenticatorRepository` /
///   `InMemoryTotpRecoveryCodeRepository`; production uses the
///   D1-backed Cloudflare versions. Both impl the same
///   `cesauth_core::totp::storage` traits.
///
/// Behavior:
/// 1. CSRF guard. Failure → `CsrfFailure` (handler returns 400).
/// 2. Authenticators-first delete. Failure → `AuthDeleteError`
///    (handler returns 500). Why authenticators-first: an
///    authenticator without recovery codes is still a working
///    credential and the user is still gated; recovery codes
///    without an authenticator are useless. So the
///    security-critical delete goes first.
/// 3. Recovery-codes delete (best-effort). Errors here are
///    silently swallowed: the authenticators are already gone,
///    so the recovery codes are now ineffective regardless.
///    The next disable attempt would clean them up anyway.
/// 4. Return `Success`.
pub async fn decide_disable_post<A, R>(
    user_id:       &str,
    csrf_form:     &str,
    csrf_cookie:   &str,
    auth_repo:     &A,
    recovery_repo: &R,
) -> DisableDecision
where
    A: TotpAuthenticatorRepository + ?Sized,
    R: TotpRecoveryCodeRepository  + ?Sized,
{
    if !csrf::verify(csrf_form, csrf_cookie) {
        return DisableDecision::CsrfFailure;
    }
    if auth_repo.delete_all_for_user(user_id).await.is_err() {
        return DisableDecision::AuthDeleteError;
    }
    // Best-effort. See module doc and DisableDecision::Success.
    let _ = recovery_repo.delete_all_for_user(user_id).await;
    DisableDecision::Success
}


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
            let t = match csrf::mint() {
            Ok(tok) => tok,
            Err(_) => {
                crate::audit::write_owned(
                    &ctx.env, crate::audit::EventKind::CsrfRngFailure,
                    None, None, Some("route=/me/security/totp/disable".to_owned()),
                ).await.ok();
                return Response::error("service temporarily unavailable", 500);
            }
        };
            let h = csrf::set_cookie_header(&t);
            (t, Some(h))
        }
    };

    // **v0.47.0** — negotiate locale for the page render.
    let locale = crate::i18n::resolve_locale(&req);

    // **v0.52.0 (RFC 006)** — generate per-request CSP nonce and register
    // it with the UI render layer before calling any template function.
    let csp_nonce = match cesauth_core::security_headers::CspNonce::generate() {
        Ok(n) => n,
        Err(_) => {
            crate::audit::write_owned(
                &ctx.env, crate::audit::EventKind::CsrfRngFailure,
                None, None, Some("csp_nonce_failure".to_owned()),
            ).await.ok();
            return Response::error("service temporarily unavailable", 500);
        }
    };
    cesauth_ui::set_render_nonce(csp_nonce.as_str());
    let html = templates::totp_disable_confirm_page_for(&token, locale);
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

    let form        = req.form_data().await?;
    let csrf_form   = form_get(&form, "csrf").unwrap_or_default();
    let csrf_cookie = csrf::extract_from_cookie_header(&cookie_header).unwrap_or("");

    let auth_repo     = CloudflareTotpAuthenticatorRepository::new(&env);
    let recovery_repo = CloudflareTotpRecoveryCodeRepository::new(&env);

    let decision = decide_disable_post(
        &session.user_id,
        &csrf_form,
        csrf_cookie,
        &auth_repo,
        &recovery_repo,
    ).await;

    match decision {
        DisableDecision::CsrfFailure     => Response::error("Bad Request", 400),
        DisableDecision::AuthDeleteError => Response::error("totp disable failed (authenticators)", 500),
        DisableDecision::Success => {
            // Redirect to the Security Center with a success
            // flash. The user clicked disable; landing them on
            // the index page (a) confirms the new state ("TOTP:
            // 無効" badge), and (b) shows the flash banner with
            // the "TOTP を無効にしました" notice.
            //
            // v0.31.0 P0-B brought the flash infrastructure
            // online; this is one of four handlers that opted
            // into it.
            let mut resp = Response::empty()?.with_status(302);
            resp.headers_mut().set("location", DISABLE_SUCCESS_REDIRECT).ok();
            flash::set_on_response(
                &env,
                resp.headers_mut(),
                flash::Flash::new(flash::FlashLevel::Success, flash::FlashKey::TotpDisabled),
            )?;
            Ok(resp)
        }
    }
}


fn form_get(form: &worker::FormData, key: &str) -> Option<String> {
    match form.get(key) {
        Some(worker::FormEntry::Field(v)) => Some(v),
        _ => None,
    }
}


#[cfg(test)]
mod tests;
