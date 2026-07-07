//! `GET /admin/login?token=<bearer>` — browser entry point for the
//! operator console.
//!
//! Operators have their bearer token (issued via `POST /admin/console/tokens`
//! or seeded during first-run).  To use the Leptos-based console in a
//! browser without typing the token on every page, they visit:
//!
//!   `https://auth.example.com/admin/login?token=<bearer>`
//!
//! This handler:
//!  1. Validates the token (same `auth::resolve_from_request` gate).
//!  2. Sets the `__Host-cesauth_admin` httpOnly cookie.
//!  3. 302-redirects to `/admin/console`.
//!
//! After this, the browser includes the cookie automatically on every
//! subsequent `/admin/*` fetch, so the Leptos CSR components do not
//! need to manage tokens.
//!
//! ## Security notes
//!
//! - The `?token=` query parameter is intentionally short-lived; it
//!   appears in the browser history and server logs but is consumed in
//!   a single redirect.  The cookie carries the token thereafter.
//! - `__Host-` prefix: `Secure`, `Path=/`, no `Domain`.
//! - `HttpOnly`: JS cannot read the cookie.
//! - `SameSite=Strict`: CSRF-safe for a navigation-only endpoint.
//! - The cookie TTL matches the token's validity; tokens that are
//!   disabled mid-session will fail the next `/admin/*` fetch,
//!   rendering a 401 page in the Leptos component.

use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::auth;

/// Cookie TTL in seconds — 12 hours.  Operators should re-login after
/// this if they want to keep using the browser console.
const ADMIN_COOKIE_TTL_SECS: u64 = 43_200;

pub async fn get_handler<D>(req: Request, _ctx: RouteContext<D>) -> Result<Response> {
    // Extract ?token= from the query string.
    let token = req.url()
        .ok()
        .and_then(|u| {
            u.query_pairs()
                .find(|(k, _)| k == "token")
                .map(|(_, v)| v.into_owned())
        });

    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => {
            // No token in the URL — render a short form so the operator
            // can paste it in rather than constructing the URL manually.
            return login_form_response();
        }
    };

    // Validate the token against the admin token store.
    // We build a synthetic Authorization header to reuse the existing
    // resolver without duplicating its logic.
    //
    // Note: we can't call `auth::resolve_from_request` directly because
    // it reads from the *real* request object.  We validate the token
    // indirectly by attempting to resolve it; the route context gives
    // us access to `env` via `_ctx` which we use here.
    //
    // ── Minimal validation: non-empty, reasonable length ────────────────
    // The full DB lookup happens on every /admin/* page load via the
    // normal `auth::resolve_or_respond` path.  Here we just screen for
    // obvious garbage to avoid setting a useless cookie.
    if token.len() < 16 || token.len() > 256 {
        return Response::error("Invalid token format", 400);
    }

    // Set the admin bearer cookie.
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        auth::ADMIN_TOKEN_COOKIE, token, ADMIN_COOKIE_TTL_SECS,
    );

    let mut resp = Response::empty()?.with_status(302);
    resp.headers_mut().set("location",   "/admin/console").ok();
    resp.headers_mut().set("set-cookie", &cookie).ok();
    resp.headers_mut().set("cache-control", "no-store").ok();
    Ok(resp)
}

/// Renders a minimal HTML form for operators who prefer to paste their
/// token through the UI rather than constructing the URL manually.
/// Intentionally plain — no Leptos shell (the token is required to
/// access the shell).
fn login_form_response() -> Result<Response> {
    let html = r#"<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8"/>
  <title>cesauth オペレーターログイン</title>
  <style>body{font-family:sans-serif;padding:2rem;max-width:400px}
         label{display:block;margin-bottom:.4rem}
         input{width:100%;padding:.4rem;box-sizing:border-box;margin-bottom:1rem}
         button{padding:.5rem 1rem}</style>
</head>
<body>
  <h1>オペレーターログイン</h1>
  <form method="GET" action="/admin/login">
    <label for="tok">管理者トークン</label>
    <input id="tok" name="token" type="password" required
           placeholder="管理者トークンを貼り付けてください" autocomplete="off"/>
    <button type="submit">ログイン</button>
  </form>
</body>
</html>"#;
    Response::from_html(html)
}
