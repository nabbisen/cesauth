//! `/me/security` — Security Center index page (v0.31.0 P0-A).
//!
//! Read-only summary of the user's authentication state:
//!
//! - Primary auth method (Passkey / MagicLink / Anonymous)
//! - TOTP enabled/disabled
//! - Recovery code remaining count (when TOTP is enabled)
//!
//! The page itself contains no destructive actions — only links
//! to dedicated forms (`/me/security/totp/enroll`,
//! `/me/security/totp/disable`). This is the "single task per
//! page" rule from plan v2 §3.1 P0-A.
//!
//! ## Why this page exists
//!
//! Before v0.31.0 the user had no entry point to discover their
//! own TOTP state. Disabling required typing
//! `/me/security/totp/disable` directly, and there was no place
//! to see "you have N recovery codes left". The Security Center
//! gives this surface a name and an address.
//!
//! ## Authentication
//!
//! Cookie-authenticated like the rest of `/me/*`. Unauthenticated
//! requests get a 302 to `/login` (and, in a later PR, a `next`
//! param so the user lands back here).
//!
//! ## Flash integration
//!
//! Reads any pending flash from the `__Host-cesauth_flash` cookie
//! and renders it at the top of `<main>`. The cookie is cleared
//! on the response regardless of whether a flash was actually
//! consumed — a malformed cookie shouldn't linger.

use cesauth_cf::ports::repo::{
    CloudflareTotpAuthenticatorRepository, CloudflareTotpRecoveryCodeRepository,
    CloudflareUserRepository,
};
use cesauth_core::ports::repo::UserRepository;
use cesauth_core::ports::store::AuthMethod;
use cesauth_core::tenancy::AccountType;
use cesauth_core::totp::storage::{
    TotpAuthenticatorRepository, TotpRecoveryCodeRepository,
};
use cesauth_frontend::templates::{PrimaryAuthMethod, SecurityCenterState};
use worker::{Request, Response, Result};

use crate::routes::me::auth as me_auth;

/// `GET /me/security` — render the Security Center (Leptos CSR shell).
///
/// v0.79.2: this route now returns the Leptos HTML shell.  The
/// Leptos component (`pages::security_center`) fetches the actual
/// state from `GET /me/security.json` after the bundle loads.
///
/// Session verification still happens here so unauthenticated
/// requests are redirected to `/` before the shell is served.
pub async fn get_handler(req: Request, env: worker::Env) -> Result<Response> {
    // Verify session first — unauthenticated → 302 /
    let _session = match me_auth::resolve_or_redirect(&req, &env).await? {
        Ok(s)  => s,
        Err(r) => return Ok(r),
    };

    // Return the Leptos HTML shell.  The component fetches state via
    // /me/security.json below.
    crate::routes::leptos_shell::leptos_html_shell(
        &req, &env, "Security — cesauth", "en",
    ).await
}

/// `GET /me/security.json` — JSON API for the Security Center state.
///
/// Called by the Leptos component after it mounts.  Returns
/// `SecurityCenterState` as JSON.  401 if no valid session.
pub async fn get_json_handler(req: Request, env: worker::Env) -> Result<Response> {
    let session = match me_auth::resolve_or_redirect(&req, &env).await? {
        Ok(s)  => s,
        Err(_) => return Response::error("Unauthorized", 401),
    };

    let state = build_state(&env, &session).await?;

    let mut resp = Response::from_json(&state)?;
    resp.headers_mut().set("cache-control", "no-store").ok();
    Ok(resp)
}

/// Build the `SecurityCenterState` for the given session.
/// Shared by both the HTML and JSON handlers.
async fn build_state(
    env:     &worker::Env,
    session: &cesauth_core::ports::store::SessionState,
) -> Result<SecurityCenterState> {
    let user_repo = CloudflareUserRepository::new(env);
    let account_type = user_repo.find_by_id(session.user_id.as_str()).await
        .ok()
        .flatten()
        .map(|u| u.account_type);

    let primary_method = primary_method_for(account_type, session.auth_method.clone());

    let totp_repo = CloudflareTotpAuthenticatorRepository::new(env);
    let totp_enabled = totp_repo.find_active_for_user(session.user_id.as_str()).await
        .ok()
        .flatten()
        .is_some();

    let recovery_count = if totp_enabled {
        let r_repo = CloudflareTotpRecoveryCodeRepository::new(env);
        r_repo.count_remaining(session.user_id.as_str()).await.unwrap_or(0) as u32
    } else {
        0
    };

    Ok(SecurityCenterState {
        primary_method,
        totp_enabled,
        recovery_codes_remaining: recovery_count,
        active_sessions_count: None,
    })
}

/// Map the session's auth method (and the user's account type)
/// to the display-layer enum the template expects.
///
/// `AuthMethod::Admin` shouldn't normally arrive at `/me/*`
/// (admin auth is bearer-token, separate from the user session
/// cookie), but if it does we render it as MagicLink — the page
/// won't lie because admins-as-users are rare and the label is
/// only display copy.
fn primary_method_for(
    account_type: Option<AccountType>,
    auth_method:  AuthMethod,
) -> PrimaryAuthMethod {
    if matches!(account_type, Some(AccountType::Anonymous)) {
        return PrimaryAuthMethod::Anonymous;
    }
    match auth_method {
        AuthMethod::Passkey   => PrimaryAuthMethod::Passkey,
        AuthMethod::MagicLink => PrimaryAuthMethod::MagicLink,
        AuthMethod::Admin     => PrimaryAuthMethod::MagicLink,
    }
}
