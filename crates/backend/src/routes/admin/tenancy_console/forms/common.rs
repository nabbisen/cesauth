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
