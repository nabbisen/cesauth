//! Shared response-shaping helpers for the admin console.
//!
//! * [`prefers_json`] inspects `Accept` to decide whether the caller
//!   wants an HTML page (browser default) or a JSON body (scripts).
//! * [`html_response`] and [`json_response`] set the baseline security
//!   headers every console response carries: strict CSP (no scripts
//!   allowed, inline style only), `no-store`, frame-deny.
//!
//! The console never loads external JS, never loads external fonts,
//! never loads external images; so the CSP can be uncompromising
//! without hurting rendering.

use worker::{Request, Response, Result};

/// Returns `true` iff the caller sent `Accept: application/json`.
///
/// We match "prefers JSON over HTML" cheaply: look for
/// `application/json` in the `Accept` header. An exact comparison is
/// too strict (browsers send `*/*`), so we accept any Accept that
/// contains `application/json` and does NOT strongly prefer `text/html`
/// over it. This mirrors the `curl --header 'Accept: application/json'`
/// / `curl -H 'Accept:'` split that operators use.
pub fn prefers_json(req: &Request) -> bool {
    let Ok(Some(accept)) = req.headers().get("accept") else {
        return false;
    };
    let lower = accept.to_ascii_lowercase();
    if !lower.contains("application/json") {
        return false;
    }
    // If both text/html and application/json appear, we go with whichever
    // shows up first. That matches browsers (text/html,...) sending HTML,
    // and `curl -H 'Accept: application/json,*/*'` sending JSON.
    match (lower.find("application/json"), lower.find("text/html")) {
        (Some(j), Some(h)) => j <= h,
        (Some(_), None)    => true,
        _                  => false,
    }
}

/// The `Content-Security-Policy` value for a given nonce. Pulled out so
/// [`render_with_nonce`] can be tested against this exact string, not a
/// hand-copied approximation of it.
fn csp_header_for(nonce: &str) -> String {
    format!(
        "default-src 'self'; \
         script-src 'none'; \
         style-src 'self' 'nonce-{nonce}'; \
         img-src 'self' data:; \
         form-action 'self'; \
         frame-ancestors 'none'; \
         base-uri 'none'",
    )
}

/// **RFC 150.** The reusable core, shared by every HTML responder in this
/// crate, console or not: mint a nonce, publish it to the render-context
/// global, then run the caller's `render` closure — in that order, inside
/// one function, so nothing can call `render` before the nonce exists
/// (RFC 146 D1's reasoning). Callers outside the admin console don't build
/// their own CSP string; they rely on the generic security-headers
/// middleware (`lib.rs`) to read [`cesauth_frontend::render_nonce`] back
/// after this returns and put it in the header itself. Before RFC 150, each
/// of seven responders either called `set_render_nonce` on some paths and
/// not others, or never called it at all — the fix is one shared entry
/// point, not seven more copies of the same two lines.
pub(crate) fn render_body_with_nonce(
    render: impl FnOnce() -> String,
) -> std::result::Result<String, getrandom::Error> {
    let csp_nonce = cesauth_core::security_headers::CspNonce::generate()?;
    cesauth_frontend::set_render_nonce(csp_nonce.as_str());
    Ok(render())
}

/// **RFC 146.** The admin-console-specific wrapper: run
/// [`render_body_with_nonce`], then build the console's own strict CSP
/// string from the same nonce it just minted (re-read via
/// [`cesauth_frontend::render_nonce`] — nothing touches the global in
/// between, so this is the identical value `render` saw). No
/// `worker::Response` / `Headers` here — both are `web_sys` types that panic
/// unconditionally on a non-wasm32 target (measured: constructing either
/// in a host `cargo test` panics at `web-sys's gen_Headers.rs`,
/// "cannot call wasm-bindgen imported functions on non-wasm targets" —
/// RFC 146 §2's own deliverable test cannot call the real
/// `html_response`/`Response` for this reason, on any Rust version, fixed
/// or not). Separating this core is what makes the nonce invariant
/// host-testable at all.
fn render_with_nonce(
    render: impl FnOnce() -> String,
) -> std::result::Result<(String, String), getrandom::Error> {
    let body = render_body_with_nonce(render)?;
    let csp_header = csp_header_for(&cesauth_frontend::render_nonce());
    Ok((body, csp_header))
}

/// Return an HTML response with the strict admin-surface CSP.
///
/// **RFC 146 D1** — `render` is a closure, not a pre-built `String`: the
/// body cannot exist before this function mints the nonce and publishes it
/// to the render-context global, because nothing can call `render` before
/// that happens. The previous `html_response(body: String)` shape let a
/// caller build `body` (which reads the global via `crate::render_nonce()`
/// inside a template) as the argument expression — evaluated, per Rust's
/// argument-evaluation order, *before* this function's own body runs — so
/// every caller embedded whatever nonce the global held from the *previous*
/// render in this isolate, never the one this response's header goes on to
/// state. Measured live against a running Worker, not just reasoned from
/// the code (see the RFC's own evidence): two frames, two distinct wrong
/// pairings, including one request's body nonce landing on the *previous*
/// request's header nonce.
///
/// Sets:
///   * `content-type: text/html; charset=utf-8`
///   * `cache-control: no-store` (admin pages are never cached by
///     proxies or the browser; session bearer in every request)
///   * a CSP that forbids `script-src` entirely and pins `style-src`
///     to self + inline
pub fn html_response(render: impl FnOnce() -> String) -> Result<Response> {
    let (body, csp_header) = match render_with_nonce(render) {
        Ok(v)  => v,
        Err(_) => {
            // ctx is not available in this helper fn; log via console instead.
            worker::console_error!("csp_nonce_failure: getrandom error in html_response");
            return Response::error("service temporarily unavailable", 500);
        }
    };
    let mut resp = Response::from_html(body)?;
    let h = resp.headers_mut();
    let _ = h.set("cache-control", "no-store");
    let _ = h.set("content-security-policy", &csp_header);
    let _ = h.set("x-content-type-options", "nosniff");
    let _ = h.set("x-frame-options",        "DENY");
    let _ = h.set("referrer-policy",        "no-referrer");
    Ok(resp)
}

/// Return a JSON response with the same no-cache / no-frame headers.
pub fn json_response(value: &serde_json::Value) -> Result<Response> {
    let mut resp = Response::from_json(value)?;
    let h = resp.headers_mut();
    let _ = h.set("cache-control", "no-store");
    let _ = h.set("x-content-type-options", "nosniff");
    let _ = h.set("x-frame-options",        "DENY");
    let _ = h.set("referrer-policy",        "no-referrer");
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 146 §2's deliverable, in the only form that can run on this
    /// target (see `render_with_nonce`'s doc: `Response`/`Headers` panic
    /// off wasm32). Calls the exact composition `html_response` uses —
    /// mint, publish, render, build the header — and asserts the nonce in
    /// the rendered body equals the one in the CSP header string, by
    /// parsing each independently rather than checking "both mention a
    /// nonce".
    fn nonce_from_style_tag(html: &str) -> &str {
        let needle = r#"<style nonce=""#;
        let start = html.find(needle).expect("rendered admin page must have a <style nonce> tag") + needle.len();
        let rest = &html[start..];
        let end = rest.find('"').expect("style tag's nonce attribute must close");
        &rest[..end]
    }

    fn nonce_from_csp(csp: &str) -> &str {
        let needle = "'nonce-";
        let start = csp.find(needle).expect("CSP header must carry a 'nonce-…' token") + needle.len();
        let rest = &csp[start..];
        let end = rest.find('\'').expect("CSP nonce token must close with a quote");
        &rest[..end]
    }

    /// One assertion per distinct admin frame (RFC 146 §8.3) — the
    /// operator console frame and the tenancy console frame — so a second
    /// frame with the same defect cannot hide behind the first one's test.
    /// Each renders by calling the frame the way its real route does,
    /// through the closure, exactly as `html_response`'s real caller would.
    #[test]
    fn admin_frame_render_nonce_matches_its_own_csp_header() {
        let (html, csp) = render_with_nonce(|| {
            cesauth_frontend::admin::token_new_form(
                &cesauth_core::admin::types::AdminPrincipal {
                    id: "tok_test".to_owned(), role: cesauth_core::admin::types::Role::Super, name: None, user_id: None,
                },
                Some("role is required"),
            )
        }).unwrap();
        assert_eq!(nonce_from_style_tag(&html), nonce_from_csp(&csp));
    }

    #[test]
    fn tenancy_console_frame_render_nonce_matches_its_own_csp_header() {
        let (html, csp) = render_with_nonce(|| {
            cesauth_frontend::tenancy_console::forms::group_create::for_tenant(
                &cesauth_core::admin::types::AdminPrincipal {
                    id: "tok_test".to_owned(), role: cesauth_core::admin::types::Role::Super, name: None, user_id: None,
                },
                "t-1", "test-tenant", "", "",
                Some("Slug and display name are required"),
            )
        }).unwrap();
        assert_eq!(nonce_from_style_tag(&html), nonce_from_csp(&csp));
    }

    /// RFC 146 §2 — the regression this whole RFC is about: two renders in
    /// the same process must not let the first's nonce leak into the
    /// second's body (the exact "stale global" shape measured live,
    /// pre-fix, in `evidence-146/pre-fix-*`).
    #[test]
    fn two_renders_in_one_process_do_not_cross_contaminate() {
        let (html_a, csp_a) = render_with_nonce(|| "<style nonce=\"{}\">".replace(
            "{}", &cesauth_frontend::render_nonce(),
        )).unwrap();
        assert_eq!(nonce_from_style_tag(&html_a), nonce_from_csp(&csp_a));

        let (html_b, csp_b) = render_with_nonce(|| "<style nonce=\"{}\">".replace(
            "{}", &cesauth_frontend::render_nonce(),
        )).unwrap();
        assert_eq!(nonce_from_style_tag(&html_b), nonce_from_csp(&csp_b));
        assert_ne!(csp_a, csp_b, "two renders must not mint the same nonce");
    }
}
