//! Admin-token management routes (v0.3.1, Super-only).
//!
//! Handlers:
//!
//! | Route                                    | What it does                                       |
//! |------------------------------------------|----------------------------------------------------|
//! | `GET  /admin/console/tokens`             | HTML list of non-disabled rows in `admin_tokens`.  |
//! | `GET  /admin/console/tokens/new`         | HTML form for creating a new token.                |
//! | `POST /admin/console/tokens`             | Mint plaintext, hash, insert, show plaintext once. |
//! | `POST /admin/console/tokens/:id/disable` | Flip `disabled_at` on a row.                       |
//!
//! Every handler is gated on `AdminAction::ManageAdminTokens`, which the
//! role matrix permits only for `Role::Super`.
//!
//! **Plaintext generation.** `mint_plaintext` produces two
//! concatenated `Uuid::new_v4()` strings — 32 hex chars × 2 = 256
//! bits of randomness from getrandom(2). Plenty for a bearer; no
//! extra crypto dependency required.
//!
//! **Plaintext handling.** The server holds the plaintext only long
//! enough to (a) hash it for storage and (b) render it exactly once
//! on the "created" page. The list endpoint never returns plaintext;
//! the resolver only ever compares hashes. If the operator closes the
//! tab without copying, they disable the token and create a new one.

use cesauth_cf::admin::CloudflareAdminTokenRepository;
use cesauth_core::admin::ports::AdminTokenRepository;
use cesauth_core::admin::types::{AdminAction, Role};
use cesauth_ui as ui;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

/// Mint a fresh plaintext bearer. 256 bits of getrandom-sourced
/// entropy via two UUIDv4s concatenated as hex.
fn mint_plaintext() -> String {
    let a = Uuid::new_v4().as_simple().to_string();
    let b = Uuid::new_v4().as_simple().to_string();
    format!("{a}{b}")
}

/// SHA-256(plaintext) as lower hex. Matches the shape stored in the
/// `admin_tokens.token_hash` column and what the principal resolver
/// compares against.
fn hash_hex(plaintext: &str) -> String {
    let digest = Sha256::digest(plaintext.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

async fn parse_form(req: &mut Request) -> Result<HashMap<String, String>> {
    let body = req.text().await.unwrap_or_default();
    Ok(url::form_urlencoded::parse(body.as_bytes()).into_owned().collect())
}

// -------------------------------------------------------------------------
// GET /admin/console/tokens
// -------------------------------------------------------------------------

pub async fn list<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::ManageAdminTokens) {
        return Ok(r);
    }

    let repo = CloudflareAdminTokenRepository::new(&ctx.env);
    let tokens = repo.list().await
        .map_err(|e| worker::Error::RustError(format!("token list: {e}")))?;

    audit::write_owned(
        &ctx.env, EventKind::AdminConsoleViewed,
        Some(principal.id.clone()), None, Some("tokens".into()),
    ).await.ok();

    if render::prefers_json(&req) {
        render::json_response(&serde_json::json!({
            "tokens": tokens,
        }))
    } else {
        render::html_response(ui::admin::tokens_list_page(&principal, &tokens))
    }
}

// -------------------------------------------------------------------------
// GET /admin/console/tokens/new
// -------------------------------------------------------------------------

pub async fn new_form<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::ManageAdminTokens) {
        return Ok(r);
    }
    render::html_response(ui::admin::token_new_form(&principal, None))
}

// -------------------------------------------------------------------------
// POST /admin/console/tokens
// -------------------------------------------------------------------------

pub async fn create<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::ManageAdminTokens) {
        return Ok(r);
    }

    let form = parse_form(&mut req).await?;

    let role_str = match form.get("role").map(String::as_str) {
        Some(s) => s,
        None    => {
            return render::html_response(ui::admin::token_new_form(&principal, Some("role is required")));
        }
    };
    let role = match Role::from_str(role_str) {
        Some(r) => r,
        None    => {
            return render::html_response(ui::admin::token_new_form(
                &principal, Some("role must be one of: read_only, security, operations, super"),
            ));
        }
    };

    let name = form.get("name")
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    if let Some(n) = name.as_deref() {
        if n.len() > 128 {
            return render::html_response(ui::admin::token_new_form(
                &principal, Some("label too long (max 128 chars)"),
            ));
        }
    }

    let plaintext = mint_plaintext();
    let hash      = hash_hex(&plaintext);
    let now       = OffsetDateTime::now_utc().unix_timestamp();

    let repo = CloudflareAdminTokenRepository::new(&ctx.env);
    let minted = match repo.create(&hash, role, name.as_deref(), now).await {
        Ok(p)  => p,
        Err(cesauth_core::ports::PortError::Conflict) => {
            // Astronomically unlikely with 256-bit plaintext, but
            // handle it cleanly rather than panic.
            return render::html_response(ui::admin::token_new_form(
                &principal, Some("token hash collision — please try again"),
            ));
        }
        Err(e) => {
            return Response::error(format!("create failed: {e}"), 500);
        }
    };

    // Audit the creation. Subject is the NEW principal id (the token
    // being created); reason carries the role string so a grep through
    // the audit log tells the full story without needing the D1
    // snapshot at the same moment.
    audit::write_owned(
        &ctx.env, EventKind::AdminTokenCreated,
        Some(minted.id.clone()), None, Some(format!("role={} by={}", role.as_str(), principal.id)),
    ).await.ok();

    render::html_response(ui::admin::token_created_page(&principal, &minted, &plaintext))
}

// -------------------------------------------------------------------------
// POST /admin/console/tokens/:id/disable
// -------------------------------------------------------------------------

pub async fn disable<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::ManageAdminTokens) {
        return Ok(r);
    }

    let Some(id) = ctx.param("id") else {
        return Response::error("missing token id", 400);
    };

    // Guard: don't let a Super disable their own token. It's not a
    // security issue (they're already authenticated to do it), but
    // the resulting lockout - "I can no longer manage tokens because
    // I just disabled the one I'm holding" - is unpleasant enough to
    // catch here. `super-bootstrap` never lives in the table so we
    // don't need to worry about that path.
    if id == &principal.id {
        return Response::error(
            "refusing to disable your own token; sign in with another token first",
            400,
        );
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let repo = CloudflareAdminTokenRepository::new(&ctx.env);
    match repo.disable(id, now).await {
        Ok(()) => {
            audit::write_owned(
                &ctx.env, EventKind::AdminTokenDisabled,
                Some(id.to_owned()), None, Some(format!("by={}", principal.id)),
            ).await.ok();

            if render::prefers_json(&req) {
                render::json_response(&serde_json::json!({"ok": true}))
            } else {
                let mut resp = Response::empty()?.with_status(303);
                let _ = resp.headers_mut().set("location", "/admin/console/tokens");
                let _ = resp.headers_mut().set("cache-control", "no-store");
                Ok(resp)
            }
        }
        Err(cesauth_core::ports::PortError::NotFound) => {
            Response::error("unknown token", 404)
        }
        Err(e) => Response::error(format!("disable failed: {e}"), 500),
    }
}
