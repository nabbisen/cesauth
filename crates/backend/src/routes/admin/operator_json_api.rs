//! Shared utilities for operator console JSON API endpoints.
//!
//! All `/admin/tenancy/*` and `/admin/console/*` GET routes follow the
//! same pattern:
//!   1. Resolve the admin bearer (header or `__Host-cesauth_admin` cookie).
//!   2. Return the Leptos HTML shell (for the browser GET).
//!   3. Return JSON data (for the browser's in-component `.json` fetch).
//!
//! This module provides helpers that remove the per-route boilerplate.

use worker::{Request, Response, Result, RouteContext};

use crate::csrf;
use crate::routes::admin::auth;

/// Resolve an `AdminPrincipal` from the request.
/// Returns `Err(Response)` for 401/403 responses the caller should return.
pub async fn resolve_admin<D>(
    req:  &Request,
    ctx:  &RouteContext<D>,
) -> Result<std::result::Result<cesauth_core::admin::types::AdminPrincipal, Response>> {
    match auth::resolve_or_respond(req, &ctx.env).await? {
        Ok(p)     => Ok(Ok(p)),
        Err(resp) => Ok(Err(resp)),
    }
}

/// Return the Leptos HTML shell after admin auth check.
pub async fn shell<D>(
    req:   &Request,
    ctx:   &RouteContext<D>,
    title: &str,
) -> Result<Response> {
    let _admin = match resolve_admin(req, ctx).await? {
        Ok(a)  => a,
        Err(r) => return Ok(r),
    };
    crate::routes::leptos_shell::leptos_html_shell(req, &ctx.env, title, "ja").await
}

/// Return `{ csrf_token }` JSON after admin auth check.
pub fn csrf_json() -> Result<Response> {
    let token = csrf::mint()
        .map_err(|_| worker::Error::RustError("csrf rng failed".into()))?;
    let set_cookie = csrf::set_cookie_header(&token);
    let mut resp = Response::from_json(&serde_json::json!({ "csrf_token": token }))?;
    resp.headers_mut().append("set-cookie", &set_cookie).ok();
    resp.headers_mut().set("cache-control", "no-store").ok();
    Ok(resp)
}

/// Return `{ csrf_token }` JSON — no auth check (used by form pages where
/// auth already verified the shell request).
pub fn csrf_json_unauthed() -> Result<Response> {
    csrf_json()
}
