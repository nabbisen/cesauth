//! Admin principal resolution + role-check helpers.
//!
//! This module is the single place every admin handler goes through to
//! turn an `Authorization: Bearer ...` header into an
//! [`AdminPrincipal`]. The role-gate function
//! [`ensure_role_allows`] turns a missing capability into a 403 in one
//! line.
//!
//! Why a wrapper here and not directly in each handler: the legacy
//! `create_user` / `revoke_session` handlers (pre-0.3) spelled the
//! bearer-compare inline with `ADMIN_API_KEY`. In v0.3 we centralize so
//! that adding a role means editing one file, not nineteen.
//!
//! The resolver itself is [`CloudflareAdminPrincipalResolver`] from the
//! CF adapter crate. It knows the `ADMIN_API_KEY` bootstrap path (fresh
//! deploy without rows in `admin_tokens`) and falls back to the SHA-256
//! lookup.

use cesauth_cf::admin::CloudflareAdminPrincipalResolver;
use cesauth_core::admin::policy::role_allows;
use cesauth_core::admin::ports::{AdminPrincipalResolver, AuthFailure};
use cesauth_core::admin::types::{AdminAction, AdminPrincipal};
use time::OffsetDateTime;
use worker::{Env, Request, Response, Result};

use crate::audit::{self, EventKind};

/// Extract the bearer token from `Authorization: Bearer ...`.
///
/// Returns `None` when the header is missing, empty, or the scheme is
/// anything other than `Bearer`.
fn bearer(req: &Request) -> Option<String> {
    let header = req.headers().get("authorization").ok().flatten()?;
    let stripped = header.strip_prefix("Bearer ")?;
    if stripped.is_empty() { None } else { Some(stripped.to_owned()) }
}

/// Try to resolve the request's bearer to an [`AdminPrincipal`].
///
/// Logs a `AdminLoginFailed` audit event on any non-success path so
/// operators can spot bearer-guessing from the audit log (§13).
pub async fn resolve_from_request(
    req: &Request,
    env: &Env,
) -> std::result::Result<AdminPrincipal, AuthFailure> {
    let Some(tok) = bearer(req) else {
        audit::write_owned(
            env, EventKind::AdminLoginFailed, None, None,
            Some("missing_bearer".into()),
        ).await.ok();
        return Err(AuthFailure::MissingBearer);
    };

    let resolver = CloudflareAdminPrincipalResolver::new(env);
    match resolver.resolve(&tok).await {
        Ok(p) => {
            // Touch `last_used_at`. Best-effort - a touch failure must
            // not block the request.
            let now = OffsetDateTime::now_utc().unix_timestamp();
            let _ = resolver.touch_last_used(&p.id, now).await;
            Ok(p)
        }
        Err(e) => {
            let f: AuthFailure = e.into();
            audit::write_owned(
                env, EventKind::AdminLoginFailed, None, None,
                Some(match f {
                    AuthFailure::MissingBearer    => "missing_bearer",
                    AuthFailure::UnknownToken     => "unknown_token",
                    AuthFailure::DisabledToken    => "disabled_token",
                    AuthFailure::InsufficientRole => "insufficient_role",
                }.into()),
            ).await.ok();
            Err(f)
        }
    }
}

/// Returns `Ok(())` iff `principal` may perform `action`. Emits a
/// `forbidden` [`Response`] otherwise; the caller should `return` that
/// response directly.
pub fn ensure_role_allows(
    principal: &AdminPrincipal,
    action:    AdminAction,
) -> std::result::Result<(), Response> {
    if role_allows(principal.role, action) {
        Ok(())
    } else {
        Err(forbidden_response(AuthFailure::InsufficientRole))
    }
}

/// Render the canonical 401/403 response for an [`AuthFailure`].
///
/// Missing / disabled / unknown bearer -> 401 (with
/// `WWW-Authenticate: Bearer` so browser clients present a login
/// prompt). Insufficient role -> 403.
pub fn forbidden_response(f: AuthFailure) -> Response {
    let status = match f {
        AuthFailure::InsufficientRole => 403,
        _                             => 401,
    };
    let mut resp = Response::error(f.message(), status)
        .unwrap_or_else(|_| Response::empty().unwrap().with_status(status));
    let h = resp.headers_mut();
    let _ = h.set("cache-control", "no-store");
    if status == 401 {
        let _ = h.set("www-authenticate", "Bearer realm=\"cesauth-admin\"");
    }
    resp
}

/// Convenience: caller pattern is "resolve or return the error response".
pub async fn resolve_or_respond(req: &Request, env: &Env) -> Result<std::result::Result<AdminPrincipal, Response>> {
    match resolve_from_request(req, env).await {
        Ok(p)  => Ok(Ok(p)),
        Err(f) => Ok(Err(forbidden_response(f))),
    }
}
