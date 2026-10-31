//! `GET /admin/login?token=<bearer>` + `POST /admin/login` — browser
//! entry point for the operator console.
//!
//! Operators have their bearer token (issued via `POST /admin/console/tokens`
//! or seeded during first-run). To use the Leptos-based console in a
//! browser without typing the token on every page, they visit:
//!
//!   `https://auth.example.com/admin/login?token=<bearer>`
//!
//! **RFC 152 half B stage 2.** This used to validate the token's *length*
//! only and set the session cookie directly from an unvalidated `GET` — a
//! crafted link could set an arbitrary `__Host-cesauth_admin` cookie in
//! whoever followed it (login CSRF / cookie fixation: a victim who follows
//! a link carrying an attacker's *valid* token thereafter operates the
//! console as the attacker's principal, and every action they take is
//! attributed to the attacker in the audit chain — RFC 152 §6.2). Now:
//!
//!  1. `GET ?token=<bearer>` **validates the token for real** — the same
//!     resolver `auth::resolve_from_request` uses, called directly with the
//!     bearer string (it takes `&str`; the constraint that blocked this
//!     before was in `resolve_from_request`'s request-shaped wrapper, not in
//!     the resolver itself). An unknown/disabled token gets the same
//!     treatment any other `/admin/*` request gets, including the
//!     `AdminLoginFailed` audit event. On success it renders a
//!     **confirmation page** — not a redirect — naming the identity the
//!     operator is about to assume (the token's name and role) and carrying
//!     a freshly minted CSRF token.
//!  2. **`POST /admin/login`** verifies that CSRF token, re-validates the
//!     bearer, and only then sets `__Host-cesauth_admin` and `303`s to
//!     `/admin/console`.
//!
//! This closes both consequences RFC 152 §6.2 named: nothing is set before
//! validation (the denial-of-access case — a garbage token can no longer
//! overwrite a working operator's cookie), and `SameSite=Strict` means no
//! cross-site page can submit the confirmation form, so setting the cookie
//! now requires the operator's own deliberate click on a page that told them
//! whose identity they were about to take (the login-CSRF case — RFC 152
//! §6.4: validating the token alone does not fix this, because an attacker's
//! token being *valid* is the premise of the attack; requiring intent does).
//!
//! **What this does not fix:** the bearer token still travels in the `?token=`
//! query string, in browser history and in server logs between `GET` and
//! `POST`. That exposure is unchanged from before this stage and is already
//! accepted in writing (RFC 152 §6.3's option 2 — a one-time server-issued
//! handle instead of the bearer itself — would close it, and is recorded as
//! the end state for its own RFC rather than riding on this fix).
//!
//! ## Security notes
//!
//! - `__Host-` prefix: `Secure`, `Path=/`, no `Domain`.
//! - `HttpOnly`: JS cannot read the cookie.
//! - `SameSite=Strict`: stops the cookie being *sent* on cross-site
//!   requests, AND — now that the cookie is only ever set by a `POST` the
//!   `SameSite=Strict` CSRF cookie itself gates — stops the cookie being
//!   *set* by an induced navigation too (RFC 152 §6.4).
//! - The cookie TTL matches the token's validity; tokens that are
//!   disabled mid-session will fail the next `/admin/*` fetch, rendering a
//!   401 page in the Leptos component.

use worker::{FormEntry, Request, Response, Result, RouteContext};

use cesauth_cf::admin::CloudflareAdminPrincipalResolver;
use cesauth_core::admin::ports::{AdminPrincipalResolver, AuthFailure};
use cesauth_core::admin::types::Role;
use time::OffsetDateTime;

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;

/// Cookie TTL in seconds — 12 hours. Operators should re-login after
/// this if they want to keep using the browser console.
const ADMIN_COOKIE_TTL_SECS: u64 = 43_200;

/// Build the `Set-Cookie` value for the admin bearer cookie.
///
/// **RFC 152 half A.** `SameSite=Strict` here is **defence in depth**
/// (stage 2 closed the login-CSRF gap that made it the *entire* defence
/// for this cookie's own issuance) on top of the double-submit `csrf::verify`
/// now standing in front of every route that mutates state on the
/// tenant-admin and tenancy-console surfaces (34 of 36 routes — RFC 152 half
/// B stage 1). No cross-site request carries this cookie, so a forged
/// cross-site `POST` to any of those routes arrives with no credential and
/// is rejected by the auth gate — but that protection holds only as long as
/// this exact string does. Extracted into its own function so
/// [`admin_cookie_carries_the_real_csrf_control`] can assert the literal
/// attributes, not just that *a* cookie gets set — a reader of
/// `route-contracts.md`'s CSRF column now has one place that fails if
/// `SameSite` is ever relaxed for an unrelated reason (RFC 152 §3: *"If
/// it is ever relaxed to Lax for a navigation reason ... no test fails,
/// and no document changes"*).
fn admin_cookie_header(token: &str, ttl_secs: u64) -> String {
    format!(
        "{}={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        auth::ADMIN_TOKEN_COOKIE, token, ttl_secs,
    )
}

/// `routes::admin::auth::AuthFailure` reason string for the
/// `AdminLoginFailed` audit event — the same mapping
/// `auth::resolve_from_request` uses, duplicated here because this
/// handler calls the resolver directly rather than going through that
/// request-shaped wrapper (it has no `Authorization`/cookie bearer to
/// read yet; the bearer is the `?token=`/form value it is validating).
fn login_failure_reason(f: AuthFailure) -> &'static str {
    match f {
        AuthFailure::MissingBearer    => "missing_bearer",
        AuthFailure::UnknownToken     => "unknown_token",
        AuthFailure::DisabledToken    => "disabled_token",
        AuthFailure::InsufficientRole => "insufficient_role",
    }
}

pub async fn get_handler<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
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

    // Validate the token for real. Nothing is set before this succeeds —
    // the denial-of-access consequence (a garbage token overwriting a
    // working operator's cookie) is gone at this line.
    let resolver = CloudflareAdminPrincipalResolver::new(&ctx.env);
    let principal = match resolver.resolve(&token).await {
        Ok(p)  => p,
        Err(e) => {
            let f: AuthFailure = e.into();
            audit::write_owned(
                &ctx.env, EventKind::AdminLoginFailed, None, None,
                Some(login_failure_reason(f).into()),
            ).await.ok();
            return Ok(auth::forbidden_response(f));
        }
    };

    // Deliberately NOT touching `last_used_at` here — viewing the
    // confirmation page is not "using" the token; the `POST` below,
    // which actually sets the session cookie, is the real login event.
    let csrf_token = match crate::csrf::mint() {
        Ok(t)  => t,
        Err(_) => return Response::error("service temporarily unavailable", 500),
    };
    let set_cookie = crate::csrf::set_cookie_header(&csrf_token);

    let body = match crate::routes::admin::console::render::render_body_with_nonce(|| {
        confirm_page(principal.name.as_deref(), principal.role, &token, &csrf_token)
    }) {
        Ok(b)  => b,
        Err(_) => {
            worker::console_error!("csp_nonce_failure in admin_login::get_handler");
            return Response::error("service temporarily unavailable", 500);
        }
    };
    let mut resp = Response::from_html(body)?;
    resp.headers_mut().set("cache-control", "no-store").ok();
    resp.headers_mut().append("set-cookie", &set_cookie).ok();
    Ok(resp)
}

pub async fn post_handler<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();
    let form = req.form_data().await?;

    let csrf_submitted = match form.get("csrf") {
        Some(FormEntry::Field(v)) => v,
        _ => String::new(),
    };
    let from_cookie = crate::csrf::extract_from_cookie_header(&cookie_header).unwrap_or("");
    if !crate::csrf::verify(&csrf_submitted, from_cookie) {
        return Response::error("Bad Request", 400);
    }

    let token = match form.get("token") {
        Some(FormEntry::Field(v)) if !v.is_empty() => v,
        _ => return Response::error("missing token", 400),
    };

    // Re-validate: the confirmation page may be minutes old, and the
    // token the operator is confirming must still be live.
    let resolver = CloudflareAdminPrincipalResolver::new(&ctx.env);
    let principal = match resolver.resolve(&token).await {
        Ok(p)  => p,
        Err(e) => {
            let f: AuthFailure = e.into();
            audit::write_owned(
                &ctx.env, EventKind::AdminLoginFailed, None, None,
                Some(login_failure_reason(f).into()),
            ).await.ok();
            return Ok(auth::forbidden_response(f));
        }
    };

    // This IS the login event — touch last_used_at now, not on the GET.
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let _ = resolver.touch_last_used(&principal.id, now).await;

    let cookie = admin_cookie_header(&token, ADMIN_COOKIE_TTL_SECS);
    let mut resp = Response::empty()?.with_status(303);
    resp.headers_mut().set("location",     "/admin/console").ok();
    resp.headers_mut().set("set-cookie",   &cookie).ok();
    resp.headers_mut().set("cache-control", "no-store").ok();
    Ok(resp)
}

/// Pure render for the confirmation page — host-testable without a
/// `worker::Env`. All four interpolated values are escaped per the RFC 108
/// escape contract: `name` is operator-supplied at token-creation time
/// (`POST /admin/console/tokens`'s `name` field) and `token` is the bearer
/// itself, neither of which this function controls.
fn confirm_page(name: Option<&str>, role: Role, token: &str, csrf: &str) -> String {
    let nonce = cesauth_frontend::render_nonce();
    let who = name.unwrap_or("(no label)");
    format!(
        r#"<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8"/>
  <title>サインインの確認 — cesauth</title>
  <style nonce="{nonce}">body{{font-family:sans-serif;padding:2rem;max-width:480px}}
         p.identity{{font-size:1.1rem;padding:.75rem;border:1px solid #ccc;border-radius:.3rem}}
         button{{padding:.5rem 1rem;margin-top:1rem}}</style>
</head>
<body>
  <h1>オペレーターコンソールへのサインイン</h1>
  <p class="identity">
    次の権限でサインインしようとしています — <strong>{who}</strong>
    （ロール: <strong>{role}</strong>）。
  </p>
  <p>このリンクを自分で開いた場合のみ、続行してください。</p>
  <form method="POST" action="/admin/login">
    <input type="hidden" name="token" value="{token}">
    <input type="hidden" name="csrf" value="{csrf}">
    <button type="submit">このアカウントでサインインする</button>
  </form>
</body>
</html>"#,
        nonce = nonce,
        who   = cesauth_frontend::escape(who),
        role  = cesauth_frontend::escape(role.label()),
        token = cesauth_frontend::escape(token),
        csrf  = cesauth_frontend::escape(csrf),
    )
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

    /// **RFC 152 half A/half B.** This is defence in depth on top of the
    /// double-submit `csrf::verify` now standing in front of 34 of 36
    /// `POST` routes under `/admin/t/*` and `/admin/tenancy/*` (half B
    /// stage 1) — not the entire defence any more. Assert every attribute
    /// by name, not just that a cookie is set, so a future edit that drops
    /// or weakens one of them fails here instead of silently reopening
    /// every one of those routes to cross-site forgery alongside whatever
    /// else it broke.
    #[test]
    fn admin_cookie_carries_the_real_csrf_control() {
        let cookie = admin_cookie_header("tok_abc123", 43_200);

        assert!(cookie.starts_with("__Host-cesauth_admin="),
            "the __Host- prefix is what guarantees Secure + Path=/ + no \
             Domain are enforced by the browser itself, not just claimed \
             here: {cookie}");
        assert!(cookie.contains("SameSite=Strict"),
            "SameSite=Strict is defence in depth for every admin POST \
             route (RFC 152) on top of the double-submit csrf::verify \
             check -- relaxing this to Lax for any reason still reopens \
             that layer to cross-site forgery: {cookie}");
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

    /// RFC 152 half B stage 2's whole point: a page that sets a cookie
    /// without naming whose it is would pass a CSRF test and fail the
    /// point. The operator's name AND role must be visible, not just
    /// present somewhere in a hidden field.
    #[test]
    fn confirm_page_names_the_identity_being_assumed() {
        let html = confirm_page(Some("ops-rotation"), Role::Operations, "tok-1", "csrf-1");
        assert!(html.contains("ops-rotation"),
            "the token's label must be visible to the operator: {html}");
        assert!(html.contains("Operations admin"),
            "the role must be visible to the operator: {html}");
    }

    #[test]
    fn confirm_page_falls_back_when_the_token_has_no_label() {
        let html = confirm_page(None, Role::Super, "tok-1", "csrf-1");
        assert!(html.contains("(no label)"));
        assert!(html.contains("Super admin"));
    }

    /// The hidden `token` and `csrf` fields are what `POST /admin/login`
    /// reads. Pin both are actually present, not just that the page
    /// mentions the values somewhere.
    #[test]
    fn confirm_page_carries_the_bearer_and_csrf_as_hidden_fields() {
        let html = confirm_page(Some("x"), Role::ReadOnly, "the-bearer-token", "the-csrf-token");
        assert!(html.contains(r#"name="token" value="the-bearer-token""#));
        assert!(html.contains(r#"name="csrf" value="the-csrf-token""#));
        assert!(html.contains(r#"action="/admin/login""#));
        assert!(html.contains(r#"method="POST""#));
    }

    /// RFC 108 escape contract — all four interpolated values. `name` is
    /// operator-supplied (the token's label) and `token` is the bearer
    /// itself; neither is under this function's control.
    #[test]
    fn confirm_page_escapes_the_operator_supplied_label() {
        let html = confirm_page(
            Some(r#"evil" onmouseover="alert(1)"#), Role::Operations, "tok-1", "csrf-1",
        );
        assert!(!html.contains(r#"evil" onmouseover"#),
            "the raw quote must not survive into the attribute or text: {html}");
        assert!(html.contains("&quot;"));
    }

    #[test]
    fn confirm_page_escapes_the_token_and_csrf_fields() {
        let html = confirm_page(
            Some("x"), Role::ReadOnly,
            r#"tok"><script>alert(1)</script>"#,
            r#"csrf"><script>alert(2)</script>"#,
        );
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;script&gt;"));
    }
}
