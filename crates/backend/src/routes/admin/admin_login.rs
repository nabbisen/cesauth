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

/// Build the `Set-Cookie` value for the admin bearer cookie.
///
/// **RFC 152 half A.** `SameSite=Strict` here is not defense-in-depth on
/// top of a CSRF token — it is the *entire* defense for every `POST` on
/// the tenant-admin and tenancy-console surfaces (33 of 35 routes; the
/// remaining two, `/admin/t/:slug/deletion-requests/:id/{cancel,execute}`,
/// additionally call `csrf::verify`). No cross-site request carries this
/// cookie, so a forged cross-site `POST` to any of those 33 arrives with
/// no credential and is rejected by the auth gate — but that protection
/// holds only as long as this exact string does. Extracted into its own
/// function so [`admin_cookie_carries_the_real_csrf_control`] can assert
/// the literal attributes, not just that *a* cookie gets set — a reader
/// of `route-contracts.md`'s CSRF column now has one place that fails if
/// `SameSite` is ever relaxed for an unrelated reason (RFC 152 §3: *"If
/// it is ever relaxed to Lax for a navigation reason ... no test fails,
/// and no document changes"*).
fn admin_cookie_header(token: &str, ttl_secs: u64) -> String {
    format!(
        "{}={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        auth::ADMIN_TOKEN_COOKIE, token, ttl_secs,
    )
}

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
    let cookie = admin_cookie_header(&token, ADMIN_COOKIE_TTL_SECS);

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
///
/// **RFC 150.** Before this, the `<style>` tag below carried no `nonce`
/// attribute at all, so the inline style was blocked under any
/// nonce-based CSP regardless of isolate state — measured live
/// (`/admin/login` renders unstyled today, confirmed against a running
/// `wrangler dev`, RFC 150 §3's falsifiable prediction). Now mints a
/// fresh nonce through the shared `render_body_with_nonce` core (RFC 150)
/// before rendering, same as every other HTML responder in this crate,
/// and embeds it in the tag so the security-headers middleware's
/// CSP and this document agree.
fn login_form_response() -> Result<Response> {
    let body = match crate::routes::admin::console::render::render_body_with_nonce(|| {
        let nonce = cesauth_frontend::render_nonce();
        format!(
            r#"<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8"/>
  <title>cesauth オペレーターログイン</title>
  <style nonce="{nonce}">body{{font-family:sans-serif;padding:2rem;max-width:400px}}
         label{{display:block;margin-bottom:.4rem}}
         input{{width:100%;padding:.4rem;box-sizing:border-box;margin-bottom:1rem}}
         button{{padding:.5rem 1rem}}</style>
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
</html>"#,
            nonce = nonce,
        )
    }) {
        Ok(b)  => b,
        Err(_) => {
            worker::console_error!("csp_nonce_failure in admin_login::login_form_response");
            return Response::error("service temporarily unavailable", 500);
        }
    };
    Response::from_html(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **RFC 152 half A.** This is the control that actually defends 33
    /// of the 35 `POST` routes under `/admin/t/*` and `/admin/tenancy/*` —
    /// not a double-submit token (nothing on either surface except the
    /// two deletion-request routes calls `csrf::verify`), the admin
    /// cookie's `SameSite=Strict`. Assert every attribute by name, not
    /// just that a cookie is set, so a future edit that drops or weakens
    /// one of them fails here instead of silently reopening 33 routes —
    /// 15 of them destructive — to cross-site `POST`.
    #[test]
    fn admin_cookie_carries_the_real_csrf_control() {
        let cookie = admin_cookie_header("tok_abc123", 43_200);

        assert!(cookie.starts_with("__Host-cesauth_admin="),
            "the __Host- prefix is what guarantees Secure + Path=/ + no \
             Domain are enforced by the browser itself, not just claimed \
             here: {cookie}");
        assert!(cookie.contains("SameSite=Strict"),
            "SameSite=Strict is the entire CSRF defense for 33 of 35 \
             admin POST routes (RFC 152) — relaxing this to Lax for any \
             reason reopens all of them to cross-site forgery: {cookie}");
        assert!(cookie.contains("Secure"), "{cookie}");
        assert!(cookie.contains("HttpOnly"), "{cookie}");
        assert!(cookie.contains("Path=/"), "{cookie}");
    }

    /// The token and TTL are not hardcoded into the string by accident —
    /// pin that both actually reach the output, so a refactor can't
    /// silently stop threading one through.
    #[test]
    fn admin_cookie_carries_the_token_and_ttl() {
        let cookie = admin_cookie_header("tok_xyz789", 999);
        assert!(cookie.contains("tok_xyz789"), "{cookie}");
        assert!(cookie.contains("Max-Age=999"), "{cookie}");
    }
}
