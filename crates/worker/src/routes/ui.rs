//! UI routes.
//!
//! Exactly one endpoint right now: `GET /` and `GET /login`, which both
//! render the login page. Kept in its own module so that adding more
//! pages later (error, post-verify landing, admin console) is a matter
//! of dropping a new handler here rather than touching route plumbing.

use worker::{Request, Response, Result, RouteContext};

use crate::config::Config;
use crate::csrf;
use crate::log::{self, Category, Level};

pub async fn login<D>(_req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let cfg  = Config::from_env(&ctx.env)?;
    let csrf_token = csrf::mint();
    let sitekey = Some(cfg.turnstile_sitekey.as_str()).filter(|s| !s.is_empty());
    let html = cesauth_ui::templates::login_page(&csrf_token, None, sitekey);

    let mut resp = Response::from_html(html)?;

    // Set a tight CSP. The login page inlines its script + style, and
    // optionally loads Cloudflare Turnstile from challenges.cloudflare.com
    // - both script and iframe. When Turnstile isn't configured, we
    //   keep the narrower policy so the cross-origin allowances aren't
    //   handed out for free.
    let csp = if sitekey.is_some() {
        "default-src 'self'; \
         script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; \
         frame-src https://challenges.cloudflare.com; \
         connect-src 'self'; \
         style-src 'self' 'unsafe-inline'; \
         base-uri 'none'; \
         frame-ancestors 'none'; \
         form-action 'self'"
    } else {
        "default-src 'self'; \
         script-src 'self' 'unsafe-inline'; \
         style-src 'self' 'unsafe-inline'; \
         base-uri 'none'; \
         frame-ancestors 'none'; \
         form-action 'self'"
    };
    let _ = resp.headers_mut().set("content-security-policy", csp);
    // CSRF token cookie, scoped to the login form.
    let _ = resp.headers_mut().set("set-cookie", &csrf::set_cookie_header(&csrf_token));

    log::emit(&cfg.log, Level::Debug, Category::Http, "login page rendered", None);
    Ok(resp)
}
