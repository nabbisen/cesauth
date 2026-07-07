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

/// Name of the httpOnly cookie that carries the admin bearer token for
/// browser sessions.  The Leptos CSR shell sets this cookie when the
/// operator visits `GET /admin/login?token=<bearer>`.  Once set, the
/// browser includes it automatically on every `/admin/*` request, so
/// the Leptos components do not need to manage tokens explicitly.
pub const ADMIN_TOKEN_COOKIE: &str = "__Host-cesauth_admin";

/// Extract the bearer token from either:
///   1. `Authorization: Bearer ...` header (API clients / curl)
///   2. `__Host-cesauth_admin` httpOnly cookie (browser Leptos session)
///
/// The cookie path is restricted to `/admin/*`; the `__Host-` prefix
/// requires `Secure`, `Path=/`, no `Domain`.  httpOnly prevents JS
/// from reading it.
fn bearer(req: &Request) -> Option<String> {
    // 1. Try the Authorization header first (API callers).
    if let Ok(Some(header)) = req.headers().get("authorization") {
        if let Some(stripped) = header.strip_prefix("Bearer ") {
            if !stripped.is_empty() {
                return Some(stripped.to_owned());
            }
        }
    }
    // 2. Fall back to the admin cookie (browser Leptos clients).
    let cookie_header = req.headers().get("cookie").ok().flatten()?;
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix(ADMIN_TOKEN_COOKIE) {
            if let Some(val) = val.strip_prefix('=') {
                if !val.is_empty() {
                    return Some(val.to_owned());
                }
            }
        }
    }
    None
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

// ─── RFC 100: Auth boilerplate macros ────────────────────────────────────

/// Resolve the system-admin principal and enforce a required `AdminAction`.
///
/// Expands to two statements that early-return on failure:
/// 1. Bearer-token resolution via `auth::resolve_or_respond`
/// 2. Role-level gate via `auth::ensure_role_allows`
///
/// On success, binds the resolved `AdminPrincipal` to `$principal`.
///
/// # Example
/// ```ignore
/// pub async fn list_tokens<D>(req: Request, ctx: RouteContext<D>) -> worker::Result<Response> {
///     require_system_admin!(req, ctx, principal, AdminAction::ViewConsole);
///     // use `principal` here
/// }
/// ```
#[macro_export]
macro_rules! require_system_admin {
    ($req:expr, $ctx:expr, $principal:ident, $action:expr) => {
        let $principal = match $crate::routes::admin::auth::resolve_or_respond(&$req, &$ctx.env).await? {
            Ok(p)  => p,
            Err(r) => return Ok(r),
        };
        if let Err(r) = $crate::routes::admin::auth::ensure_role_allows(&$principal, $action) {
            return Ok(r);
        }
    };
}

/// Resolve a tenant-admin context and enforce a read permission.
///
/// Expands to three statements that early-return on failure:
/// 1. Bearer-token resolution
/// 2. Tenant-gate resolution (`resolve_tenant_admin`)
/// 3. Permission check (`check_read`)
///
/// On success, binds the `TenantAdminContext` to `$ctx_ta`.
///
/// # Example
/// ```ignore
/// pub async fn overview<D>(req: Request, ctx: RouteContext<D>) -> worker::Result<Response> {
///     require_tenant_admin_read!(req, ctx, ctx_ta, PermissionCatalog::TENANT_READ);
///     // use `ctx_ta` here
/// }
/// ```
#[macro_export]
macro_rules! require_tenant_admin_read {
    ($req:expr, $ctx:expr, $ctx_ta:ident, $permission:expr) => {
        let _principal_ta = match $crate::routes::admin::auth::resolve_or_respond(&$req, &$ctx.env).await? {
            Ok(p)  => p,
            Err(r) => return Ok(r),
        };
        let $ctx_ta = match $crate::routes::admin::tenant_admin::gate::resolve_or_respond(_principal_ta, &$ctx).await? {
            Ok(c)  => c,
            Err(r) => return Ok(r),
        };
        if let Err(r) = $crate::routes::admin::tenant_admin::gate::check_read(&$ctx_ta, $permission, &$ctx).await? {
            return Ok(r);
        }
    };
}
