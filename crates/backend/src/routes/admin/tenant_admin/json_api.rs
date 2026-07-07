//! Shared utilities for tenant-admin JSON API endpoints.
//!
//! Every tenant-admin GET route now has two variants:
//!  - The HTML shell variant (returns the Leptos shell)
//!  - The `.json` variant (returns the page data as JSON)
//!
//! Both share the same gate logic (session + tenant-admin role).
//! This module provides helpers to reduce boilerplate.

use worker::{Request, Response, Result, RouteContext};

use crate::csrf;
use crate::routes::admin::{auth, tenant_admin::gate};

/// Resolve session → principal → tenant-admin context.
/// Returns `Err(Response)` for redirect/error responses (caller returns those).
pub async fn resolve_ctx<D>(
    req: &Request,
    ctx: &RouteContext<D>,
) -> Result<std::result::Result<cesauth_core::tenant_admin::TenantAdminContext, Response>> {
    let principal = match auth::resolve_or_respond(req, &ctx.env).await? {
        Ok(p)     => p,
        Err(resp) => return Ok(Err(resp)),
    };
    match gate::resolve_or_respond(principal, ctx).await? {
        Ok(c)     => Ok(Ok(c)),
        Err(resp) => Ok(Err(resp)),
    }
}

/// Return `{ csrf_token }` JSON — the minimum payload for form pages.
pub fn csrf_json() -> Result<Response> {
    let token = csrf::mint()
        .map_err(|_| worker::Error::RustError("csrf rng failed".into()))?;
    let set_cookie = csrf::set_cookie_header(&token);
    let mut resp = Response::from_json(&serde_json::json!({ "csrf_token": token }))?;
    resp.headers_mut().append("set-cookie", &set_cookie).ok();
    resp.headers_mut().set("cache-control", "no-store").ok();
    Ok(resp)
}

/// Build and return the Leptos HTML shell for a tenant-admin page.
pub async fn shell<D>(
    req: &Request,
    ctx: &RouteContext<D>,
    title: &str,
) -> Result<Response> {
    crate::routes::leptos_shell::leptos_html_shell(req, &ctx.env, title, "en").await
}
