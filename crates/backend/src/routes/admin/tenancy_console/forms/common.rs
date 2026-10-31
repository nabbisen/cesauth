//! Shared helpers for tenancy mutation form handlers.

use std::collections::HashMap;

use cesauth_core::admin::types::{AdminAction, AdminPrincipal};
use worker::{Request, Response, Result};

use crate::routes::admin::auth;

/// Resolve the bearer + gate on `ManageTenancy`. Returns the
/// principal on success, or a `Response` to short-circuit.
///
/// Identical pattern to the 0.3.x admin console handlers; lifted
/// here to keep each form handler ≤ 30 lines.
pub async fn require_manage(
    req: &Request,
    env: &worker::Env,
) -> Result<std::result::Result<AdminPrincipal, Response>> {
    let principal = match auth::resolve_or_respond(req, env).await? {
        Ok(p)    => p,
        Err(resp) => return Ok(Err(resp)),
    };
    if let Err(resp) = auth::ensure_role_allows(&principal, AdminAction::ManageTenancy) {
        return Ok(Err(resp));
    }
    Ok(Ok(principal))
}

/// Parse `application/x-www-form-urlencoded` into a flat map.
pub async fn parse_form(req: &mut Request) -> Result<HashMap<String, String>> {
    let body = req.text().await.unwrap_or_default();
    Ok(url::form_urlencoded::parse(body.as_bytes()).into_owned().collect())
}

/// Inspect the `confirm` form field (or hidden) — present and
/// equal to `"yes"` triggers the apply path; everything else is a
/// preview render. We accept `"1"` / `"true"` as synonyms in case
/// an operator writes them by hand.
pub fn confirmed(form: &HashMap<String, String>) -> bool {
    matches!(
        form.get("confirm").map(String::as_str),
        Some("yes") | Some("1") | Some("true")
    )
}

/// 303 See Other to `loc` — POST/Redirect/GET pattern. Browsers
/// follow GET on 303, dropping the form body, so refreshing the
/// landing page won't re-submit.
pub fn redirect_303(loc: &str) -> Result<Response> {
    let mut resp = Response::ok("")?;
    resp.headers_mut().set("location", loc)?;
    Ok(resp.with_status(303))
}

/// RFC 152 half B. Mint a CSRF token and the `set-cookie` header value
/// that must be attached to whatever response renders the form that
/// carries it — `attach_csrf_cookie` does that attaching. Same
/// mint/error-mapping as `deletions.rs::admin_list`, lifted here so the
/// 23 form-handler files below it share one copy rather than 23.
pub fn mint_csrf() -> Result<(String, String)> {
    let token = crate::csrf::mint()
        .map_err(|_| worker::Error::RustError("csrf rng failed".into()))?;
    let cookie = crate::csrf::set_cookie_header(&token);
    Ok((token, cookie))
}

/// Attach a `set-cookie` header (from `mint_csrf`) to a response that
/// renders a form carrying the matching token. Every GET/preview/
/// error-re-render path that renders a form must call this with a
/// freshly minted cookie — a stale or missing cookie here is what makes
/// a corrected resubmission fail for a reason the page never explains.
pub fn attach_csrf_cookie(resp: &mut Response, cookie: &str) {
    resp.headers_mut().append("set-cookie", cookie).ok();
}

/// Verify a submitted `csrf` form field against the request's CSRF
/// cookie. `cookie_header` is the raw `cookie` request header value,
/// read by the caller before the form body is consumed.
pub fn verify_csrf(form: &HashMap<String, String>, cookie_header: &str) -> bool {
    let submitted = form.get("csrf").map(String::as_str).unwrap_or("");
    let from_cookie = crate::csrf::extract_from_cookie_header(cookie_header).unwrap_or("");
    crate::csrf::verify(submitted, from_cookie)
}

/// RFC 152 half B stage 1. `verify_csrf`/`mint_csrf`/`attach_csrf_cookie`
/// are the exact decision boundary all 32 SSR form handlers on both the
/// `tenancy_console` and `tenant_admin` surfaces delegate to (the two
/// routes resolving elsewhere -- `deletions.rs`'s pair and
/// `routes/invitations.rs`'s pair -- call `crate::csrf::verify` the same
/// way, inline). None of it touches `worker::Env`, so it is tested here,
/// directly, rather than through a `RouteContext<D>` handler -- a full
/// handler needs a live `worker::Env` (session lookup, D1 reads) that no
/// host test can construct; that boundary is exercised against `wrangler
/// dev`, not here. This module standing in for "a representative
/// handler on each surface" is not a shortcut: both surfaces' handlers
/// run this exact code, unmodified, so a defect here is a defect on
/// both.
#[cfg(test)]
mod tests {
    use super::*;

    fn form_with(csrf: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("csrf".to_owned(), csrf.to_owned());
        m
    }

    #[test]
    fn no_token_in_form_is_rejected() {
        let (_, cookie) = mint_csrf().expect("getrandom must succeed in tests");
        assert!(!verify_csrf(&HashMap::new(), &cookie),
            "a form with no csrf field at all must not verify");
    }

    #[test]
    fn wrong_token_is_rejected() {
        let (_, cookie) = mint_csrf().expect("getrandom must succeed in tests");
        let form = form_with("attacker-supplied-value");
        assert!(!verify_csrf(&form, &cookie),
            "a submitted token that does not match the cookie must not verify");
    }

    #[test]
    fn matching_token_proceeds() {
        let (token, cookie) = mint_csrf().expect("getrandom must succeed in tests");
        let form = form_with(&token);
        assert!(verify_csrf(&form, &cookie),
            "a submitted token matching the cookie must verify");
    }

    #[test]
    fn empty_cookie_header_is_rejected_even_with_a_submitted_token() {
        // A request with no Cookie header at all (first-ever visit, or
        // a cookie-stripping proxy) -- `extract_from_cookie_header`
        // returns None, and the empty fallback must not compare equal
        // to an empty submitted field either.
        let form = form_with("");
        assert!(!verify_csrf(&form, ""));
    }

    /// RFC 152 half B §3's trap: every re-render that carries a form
    /// must mint a FRESH token, not reuse the one that was just spent.
    /// `worker::Response`/`Headers` are wasm-bindgen imports and panic
    /// on a non-wasm host target (`cannot call wasm-bindgen imported
    /// functions on non-wasm targets` — confirmed by running this test
    /// against a real `Response::ok()` first), same constraint
    /// `me/totp/verify`'s own cookie tests already work around — so
    /// this asserts on the raw `set-cookie` STRING `mint_csrf` hands to
    /// `attach_csrf_cookie`, not on a constructed `Response`.
    #[test]
    fn rerender_mints_a_fresh_token_and_a_distinct_set_cookie_string() {
        let (token_a, cookie_a) = mint_csrf().expect("getrandom must succeed in tests");
        let (token_b, cookie_b) = mint_csrf().expect("getrandom must succeed in tests");
        assert_ne!(token_a, token_b,
            "two mints in a row must not produce the same token");
        assert_ne!(cookie_a, cookie_b);
        assert!(cookie_b.contains(&token_b),
            "the set-cookie string attach_csrf_cookie would append must carry the freshly minted token");
    }
}
