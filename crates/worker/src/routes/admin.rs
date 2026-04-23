//! Admin API.
//!
//! The endpoints are auth'd with a static bearer token (`ADMIN_API_KEY`
//! secret). For this initial cut we keep the API small enough that a
//! real authorization scheme (roles, scopes, per-caller keys) isn't
//! necessary. Scale up to proper OIDC-authenticated admin once the
//! main product surface is solid.
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
use cesauth_core::ports::repo::UserRepository;
use cesauth_core::ports::store::ActiveSessionStore;
use cesauth_core::types::{User, UserStatus};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};

/// Check the bearer token.
///
/// Returns `true` if the caller is authorized. The expected secret is
/// `ADMIN_API_KEY`; if the secret is missing from the environment the
/// entire admin surface is disabled (every request returns 403). That
/// is a deliberate fail-closed stance.
fn authorized<D>(req: &Request, ctx: &RouteContext<D>) -> bool {
    let Ok(secret) = ctx.env.secret("ADMIN_API_KEY") else {
        return false;
    };
    let expected = secret.to_string();
    if expected.is_empty() {
        return false;
    }

    let Ok(Some(header)) = req.headers().get("authorization") else {
        return false;
    };

    // Expect `Bearer <token>`. Constant-time compare on the token bytes.
    let presented = header.strip_prefix("Bearer ").unwrap_or("");
    constant_time_eq(presented.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn forbidden() -> Result<Response> {
    Response::error("forbidden", 403)
}

// -------------------------------------------------------------------------
// POST /admin/users
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct CreateUserBody {
    email:        Option<String>,
    display_name: Option<String>,
}

pub async fn create_user<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if !authorized(&req, &ctx) {
        return forbidden();
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
                Some(user.id.clone()), None, None,
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
    if !authorized(&req, &ctx) {
        return forbidden();
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
                Some(session_id.to_owned()), None, None,
            ).await.ok();
            // 204 No Content - revoke is idempotent and has no body.
            Response::empty().map(|r| r.with_status(204))
        }
        Err(_) => Response::error("storage error", 500),
    }
}
