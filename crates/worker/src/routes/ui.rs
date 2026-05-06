//! UI routes.
//!
//! Exactly one endpoint right now: `GET /` and `GET /login`, which both
//! render the login page. Kept in its own module so that adding more
//! pages later (error, post-verify landing, admin console) is a matter
//! of dropping a new handler here rather than touching route plumbing.
//!
//! ## `next` handling (v0.31.0 P1-A)
//!
//! When a `/me/*` page redirects an unauthenticated user here, it
//! attaches `?next=<base64url(target)>`. We validate (reusing
//! `me::auth::decode_and_validate_next`) and on success stash the
//! encoded value in `__Host-cesauth_login_next`. After the user
//! signs in, `complete_auth_post_gate` reads the cookie and lands
//! them at the validated target.

use worker::{Request, Response, Result, RouteContext};

use crate::config::Config;
use crate::csrf;
use crate::log::{self, Category, Level};
use crate::routes::me::auth as me_auth;

pub async fn login<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let cfg  = Config::from_env(&ctx.env)?;
    let csrf_token = match csrf::mint() {
        Ok(t) => t,
        Err(_) => {
            crate::audit::write_owned(
                &ctx.env, crate::audit::EventKind::CsrfRngFailure,
                None, None, Some("route=/login".to_owned()),
            ).await.ok();
            return Response::error("service temporarily unavailable", 500);
        }
    };
    let sitekey = Some(cfg.turnstile_sitekey.as_str()).filter(|s| !s.is_empty());
    // v0.39.0: negotiate locale from Accept-Language.
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
    let html = cesauth_ui::templates::login_page_for(&csrf_token, None, sitekey, locale);

    // Read ?next= and decide whether to set the login_next cookie.
    // We validate the decoded path (rejects open-redirect tricks
    // like //evil.com or absolute URLs); only valid targets get
    // stored. Invalid or absent → no cookie set, post-login lands
    // at `/` as usual.
    let next_cookie_header = req.url().ok()
        .and_then(|u| u.query_pairs()
            .find(|(k, _)| k == "next")
            .map(|(_, v)| v.into_owned()))
        .and_then(|encoded| {
            // Validate by decoding; if it round-trips, we trust the
            // ENCODED form to set as the cookie value (small + same
            // string we'd otherwise re-encode).
            me_auth::decode_and_validate_next(&encoded).map(|_| encoded)
        })
        .map(|encoded| me_auth::set_login_next_cookie_header(&encoded));

    let mut resp = Response::from_html(html)?;

    // Set a tight CSP. The login page inlines its script + style, and
    // optionally loads Cloudflare Turnstile from challenges.cloudflare.com
    // - both script and iframe. When Turnstile isn't configured, we
    //   keep the narrower policy so the cross-origin allowances aren't
    //   handed out for free.
    let csp_n = csp_nonce.as_str();
    let csp = if sitekey.is_some() {
        format!("default-src 'self';          script-src 'self' 'nonce-{n}' https://challenges.cloudflare.com;          frame-src https://challenges.cloudflare.com;          connect-src 'self';          style-src 'self' 'nonce-{n}';          base-uri 'none';          frame-ancestors 'none';          form-action 'self'", n = csp_n)
    } else {
        format!("default-src 'self';          script-src 'self' 'nonce-{n}';          style-src 'self' 'nonce-{n}';          base-uri 'none';          frame-ancestors 'none';          form-action 'self'", n = csp_n)
    };
    let h = resp.headers_mut();
    let _ = h.set("content-security-policy", &csp);
    // CSRF token cookie, scoped to the login form.
    let _ = h.set("set-cookie", &csrf::set_cookie_header(&csrf_token));
    if let Some(c) = next_cookie_header {
        // append (not set) so we don't clobber the CSRF cookie above.
        let _ = h.append("set-cookie", &c);
    }

    log::emit(&cfg.log, Level::Debug, Category::Http, "login page rendered", None);
    Ok(resp)
}
