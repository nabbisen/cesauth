//! Legacy admin API (pre-0.3.0).
//!
//! These handlers predate the Cost & Data Safety Admin Console. They
//! still live here because the URL surface is documented in the
//! operator playbook (and embedded in downstream scripts), and the
//! write-side ceremony - audit logging, role check, response shape -
//! is the same shape the console uses.
//!
//! What changed in 0.3.0:
//!
//! * Bearer auth flows through [`super::auth::resolve_from_request`]
//!   instead of a direct `ADMIN_API_KEY` comparison. The
//!   `ADMIN_API_KEY` bootstrap still works (resolves to a Super
//!   principal); additional principals can be minted into
//!   `admin_tokens` for finer-grained access.
//! * Each handler names the [`AdminAction`] it is about to perform and
//!   lets the role matrix decide whether to proceed. `CreateUser`
//!   requires Operations+; `RevokeSession` requires Security+.
//!
//! Endpoints:
//!
//! * `POST   /admin/users`          - create a user
//! * `DELETE /admin/sessions/:id`   - revoke one session immediately
//!
//! Both write to the audit log regardless of outcome.

use cesauth_cf::ports::{
    repo::CloudflareUserRepository,
    store::CloudflareActiveSessionStore,
};
use cesauth_core::admin::types::AdminAction;
use cesauth_core::ports::repo::UserRepository;
use cesauth_core::ports::store::ActiveSessionStore;
use cesauth_core::types::{User, UserStatus};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use super::auth;

// -------------------------------------------------------------------------
// POST /admin/users
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct CreateUserBody {
    email:        Option<String>,
    display_name: Option<String>,
}

pub async fn create_user<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::CreateUser) {
        return Ok(r);
    }

    let body: CreateUserBody = req.json().await.unwrap_or_default();
    let now  = OffsetDateTime::now_utc().unix_timestamp();
    let user = User {
        id:             Uuid::new_v4().to_string(),
        email:          body.email.clone(),
        email_verified: false,
        display_name:   body.display_name,
        status:         UserStatus::Active,
        created_at:     now,
        updated_at:     now,
    };

    let repo = CloudflareUserRepository::new(&ctx.env);
    match repo.create(&user).await {
        Ok(()) => {
            audit::write_owned(
                &ctx.env, EventKind::AdminUserCreated,
                Some(user.id.clone()), None, Some(principal.id.clone()),
            ).await.ok();
            Response::from_json(&serde_json::json!({
                "id":    user.id,
                "email": user.email,
            })).map(|mut r| {
                let _ = r.headers_mut().set("cache-control", "no-store");
                r
            })
        }
        Err(cesauth_core::ports::PortError::Conflict) => {
            Response::error("email already in use", 409)
        }
        Err(_) => Response::error("storage error", 500),
    }
}

// -------------------------------------------------------------------------
// DELETE /admin/sessions/:id
// -------------------------------------------------------------------------

pub async fn revoke_session<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::RevokeSession) {
        return Ok(r);
    }

    let Some(session_id) = ctx.param("id") else {
        return Response::error("missing session id", 400);
    };

    let now   = OffsetDateTime::now_utc().unix_timestamp();
    let store = CloudflareActiveSessionStore::new(&ctx.env);
    match store.revoke(session_id, now).await {
        Ok(_) => {
            audit::write_owned(
                &ctx.env, EventKind::AdminSessionRevoked,
                Some(session_id.to_owned()), None, Some(principal.id.clone()),
            ).await.ok();
            // 204 No Content - revoke is idempotent and has no body.
            Response::empty().map(|r| r.with_status(204))
        }
        Err(_) => Response::error("storage error", 500),
    }
}
