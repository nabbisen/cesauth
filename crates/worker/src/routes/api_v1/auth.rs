//! Auth + JSON helpers shared across the v0.7.0 API handlers.
//!
//! Route handlers funnel through `require(action, req, env)` which
//! resolves the admin bearer, gates on the requested capability, and
//! returns either the principal (allowed) or a `Response` to short-
//! circuit the request (forbidden / unauthorized). The shape mirrors
//! the existing admin/console handlers' `auth::resolve_or_respond`
//! plus `auth::ensure_role_allows`, but folds them into one call so
//! API handlers stay small.

use cesauth_core::admin::types::{AdminAction, AdminPrincipal};
use serde::Serialize;
use worker::{Request, Response, Result};

use crate::routes::admin::auth as admin_auth;

/// Resolve the bearer and gate on `action`. Returns either the
/// principal (continue) or a fully-formed error `Response` (return).
pub async fn require(
    action: AdminAction,
    req:    &Request,
    env:    &worker::Env,
) -> Result<std::result::Result<AdminPrincipal, Response>> {
    let principal = match admin_auth::resolve_or_respond(req, env).await? {
        Ok(p)    => p,
        Err(resp) => return Ok(Err(resp)),
    };
    if let Err(resp) = admin_auth::ensure_role_allows(&principal, action) {
        return Ok(Err(resp));
    }
    Ok(Ok(principal))
}

/// Build a JSON response with the given status and body. Use over
/// `Response::from_json` because the latter is HTTP 200-only and we
/// also want a stable `Content-Type: application/json; charset=utf-8`.
pub fn json<T: Serialize>(status: u16, body: &T) -> Result<Response> {
    let s = serde_json::to_string(body).unwrap_or_else(|_| "{}".to_owned());
    let mut resp = Response::ok(s)?
        .with_status(status);
    resp.headers_mut().set("content-type", "application/json; charset=utf-8")?;
    Ok(resp)
}

/// 400 Bad Request with a stable `{ "error": "<reason>" }` body.
pub fn bad_request(reason: &str) -> Result<Response> {
    json(400, &ErrorBody { error: reason.to_owned() })
}

/// 404 Not Found with a stable `{ "error": "not_found" }` body.
pub fn not_found() -> Result<Response> {
    json(404, &ErrorBody { error: "not_found".to_owned() })
}

/// 409 Conflict.
pub fn conflict(reason: &str) -> Result<Response> {
    json(409, &ErrorBody { error: reason.to_owned() })
}

/// 500 with a generic error. Internal-storage errors map here so the
/// caller doesn't see a `"storage unavailable"` message that exposes
/// nothing actionable to them.
pub fn server_error() -> Result<Response> {
    json(500, &ErrorBody { error: "internal".to_owned() })
}

/// Map a `PortError` to a `Response`. Conflict / NotFound surface as
/// 409 / 404 respectively; everything else collapses to 500 (with a
/// `console_error!` line in the worker log so operators can trace).
pub fn port_error_response(e: cesauth_core::ports::PortError) -> Result<Response> {
    use cesauth_core::ports::PortError;
    match e {
        PortError::NotFound                  => not_found(),
        PortError::Conflict                  => conflict("conflict"),
        PortError::PreconditionFailed(msg)   => bad_request(msg),
        PortError::Unavailable               => {
            worker::console_error!("api_v1: storage unavailable");
            server_error()
        }
        PortError::Serialization             => {
            worker::console_error!("api_v1: serialization");
            server_error()
        }
    }
}

#[derive(Serialize)]
struct ErrorBody { error: String }
