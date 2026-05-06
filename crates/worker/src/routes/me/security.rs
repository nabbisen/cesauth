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
use cesauth_ui::templates::{
    self, FlashView, PrimaryAuthMethod, SecurityCenterState,
};
use worker::{Request, Response, Result};

use crate::flash;
use crate::routes::me::auth as me_auth;


/// `GET /me/security` — render the Security Center index.
pub async fn get_handler(req: Request, env: worker::Env) -> Result<Response> {
    let session = match me_auth::resolve_or_redirect(&req, &env).await? {
        Ok(s)  => s,
        Err(r) => return Ok(r),
    };

    // Resolve account type. Anonymous principals get the
    // suppressed-TOTP variant of the page; we don't want to
    // imply they can enroll when the underlying flow rejects
    // anonymous users.
    //
    // If the user lookup fails (race: user was deleted while
    // their session was still active), fall through with the
    // session's auth_method and let the renderer fail-safe
    // by showing the non-anonymous variant. The session
    // resolver already 302'd revoked sessions, so this is rare.
    let user_repo = CloudflareUserRepository::new(&env);
    let account_type = user_repo.find_by_id(&session.user_id).await
        .ok()
        .flatten()
        .map(|u| u.account_type);

    let primary_method = primary_method_for(account_type, session.auth_method);

    // TOTP state. We look up the active confirmed authenticator,
    // not just any row — unconfirmed enrollments don't count as
    // "TOTP is on". (find_active_for_user filters on
    // confirmed_at IS NOT NULL.)
    let totp_repo = CloudflareTotpAuthenticatorRepository::new(&env);
    let totp_enabled = match totp_repo.find_active_for_user(&session.user_id).await {
        Ok(Some(_)) => true,
        Ok(None)    => false,
        Err(_)      => {
            // Storage error → render as if TOTP were off, but
            // log. The index page is read-only; failing closed
            // here would just mean the user can't see their own
            // state, and the more security-critical paths
            // (enroll, verify) re-query the repo themselves.
            false
        }
    };

    // Recovery count is only meaningful when TOTP is enabled.
    // For disabled state the page suppresses the recovery row
    // anyway (see `security_center_page` rendering rules), so
    // skip the query.
    let recovery_count = if totp_enabled {
        let r_repo = CloudflareTotpRecoveryCodeRepository::new(&env);
        r_repo.count_remaining(&session.user_id).await.unwrap_or(0) as u32
    } else {
        0
    };

    let state = SecurityCenterState {
        primary_method,
        totp_enabled,
        recovery_codes_remaining: recovery_count,
    };

    // v0.39.0: negotiate locale once for the page.
    let locale = crate::i18n::resolve_locale(&req);

    // Pull flash + always emit the clear cookie. take_from_request
    // expires the cookie regardless of validity, so a tampered or
    // expired flash doesn't keep redelivering on every request.
    let cookie_header = req.headers().get("cookie")?.unwrap_or_default();
    let (flash_msg, clear_header) = flash::take_from_request(&env, &cookie_header);
    let flash_view = flash_msg.map(|f| FlashView {
        aria_live:    f.level.aria_live(),
        css_modifier: f.level.css_modifier(),
        icon:         f.level.icon(),
        text:         f.key.display_text_for(locale),
    });
    let flash_html = templates::flash_block(flash_view);

    let html = templates::security_center_page_for(&state, &flash_html, locale);

    let mut resp = Response::from_html(html)?;
    resp.headers_mut().append("set-cookie", &clear_header).ok();
    Ok(resp)
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
