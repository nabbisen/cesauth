//! `/admin/console/clients` — **RFC 141**: register, list, update, rotate
//! the secret of, and delete OIDC clients, without hand-written SQL.
//!
//! | Route | What it does |
//! |---|---|
//! | `GET  /admin/console/clients` | the Leptos shell (console screen: cycle 2) |
//! | `GET  /admin/console/clients.json` | `{"clients": [...]}` — every registered client, never a secret |
//! | `POST /admin/console/clients` | create. Mints a secret for a confidential client, returned exactly once |
//! | `POST /admin/console/clients/:id` | update the mutable fields (`name`, `redirect_uris`, `allowed_scopes`, `audience`) |
//! | `POST /admin/console/clients/:id/rotate-secret` | mint a new secret, returned exactly once |
//! | `POST /admin/console/clients/:id/delete` | hard delete (RFC 141 §4) |
//!
//! Every handler is gated on `AdminAction::ViewClients` (read) or
//! `AdminAction::ManageClients` (write) — the same tier as
//! `ViewTenancy`/`ManageTenancy`.
//!
//! **CSRF.** These are JSON-body endpoints, not form posts. Per
//! `crate::csrf`'s own documented model, only
//! `application/x-www-form-urlencoded` submissions need the double-submit
//! token: a cross-origin page cannot silently issue a cross-origin
//! `application/json` POST — the browser's CORS preflight blocks it, and
//! this deployment sets no `Access-Control-Allow-Origin` that would permit
//! one. CLI/API callers are JSON callers already, by design (RFC 141 §4.1:
//! "through the API"). This is the same reasoning the webauthn and
//! `/api/v1/anonymous/*` routes rely on (see `route-contracts.md`, their
//! `CSRF` column: `N/A (JSON)`), not a new exemption invented for this
//! route.
//!
//! **The secret appears in exactly one field, in exactly two responses**
//! (`create`'s and `rotate_secret`'s), via `RawSecret::expose()`. No other
//! handler here reads it; the list/update/delete responses serialize
//! `OidcClient` directly, which has no secret-bearing field at all.

use cesauth_cf::ports::repo::CloudflareClientRepository;
use cesauth_core::admin::types::AdminAction;
use cesauth_core::ports::repo::ClientRepository;
use cesauth_core::service::clients::{self, ClientOpError, ClientUpdate, NewClient};
use cesauth_core::types::{ClientId, ClientType, TokenAuthMethod};
use serde::Deserialize;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;

fn client_type_str(t: ClientType) -> &'static str {
    match t {
        ClientType::Public       => "public",
        ClientType::Confidential => "confidential",
    }
}

/// Map a `ClientOpError` to the response the route returns. `Validation`
/// and `NotConfidential` are the caller's fault (400); the rest are the
/// usual storage-outcome mapping used elsewhere in this crate.
fn op_error_response(e: ClientOpError) -> Result<Response> {
    match e {
        ClientOpError::Validation(v) => {
            let mut r = Response::from_json(&serde_json::json!({ "error": v.to_string() }))?;
            let _ = r.headers_mut().set("cache-control", "no-store");
            Ok(r.with_status(400))
        }
        ClientOpError::NotConfidential => {
            let mut r = Response::from_json(&serde_json::json!({
                "error": "client is public; it has no secret to rotate",
            }))?;
            let _ = r.headers_mut().set("cache-control", "no-store");
            Ok(r.with_status(400))
        }
        ClientOpError::NotFound => Response::error("unknown client", 404),
        ClientOpError::Conflict => Response::error("a client with that id already exists", 409),
        ClientOpError::Internal => Response::error("storage error", 500),
    }
}

// -------------------------------------------------------------------------
// GET /admin/console/clients
// -------------------------------------------------------------------------

pub async fn list<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::admin::operator_json_api::shell(&req, &ctx, "OIDC クライアント — cesauth").await
}

// -------------------------------------------------------------------------
// GET /admin/console/clients.json
// -------------------------------------------------------------------------

pub async fn list_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&admin, AdminAction::ViewClients) {
        return Ok(r);
    }

    let repo = CloudflareClientRepository::new(&ctx.env);
    let list = match clients::list_clients(&repo).await {
        Ok(l)  => l,
        Err(e) => return op_error_response(e),
    };
    let mut resp = Response::from_json(&serde_json::json!({ "clients": list }))?;
    let _ = resp.headers_mut().set("cache-control", "no-store");
    Ok(resp)
}

// -------------------------------------------------------------------------
// POST /admin/console/clients
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct CreateClientBody {
    id:                 Option<String>,
    name:               Option<String>,
    client_type:        Option<String>,
    redirect_uris:      Option<Vec<String>>,
    allowed_scopes:     Option<Vec<String>>,
    token_auth_method:  Option<String>,
    audience:           Option<String>,
}

fn parse_client_type(s: Option<&str>) -> std::result::Result<ClientType, &'static str> {
    match s {
        Some("public")       => Ok(ClientType::Public),
        Some("confidential") => Ok(ClientType::Confidential),
        _ => Err("client_type must be 'public' or 'confidential'"),
    }
}

fn parse_token_auth_method(s: Option<&str>) -> std::result::Result<TokenAuthMethod, &'static str> {
    match s {
        Some("none")                => Ok(TokenAuthMethod::None),
        Some("client_secret_basic") => Ok(TokenAuthMethod::ClientSecretBasic),
        Some("client_secret_post")  => Ok(TokenAuthMethod::ClientSecretPost),
        _ => Err("token_auth_method must be 'none', 'client_secret_basic', or 'client_secret_post'"),
    }
}

pub async fn create<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::ManageClients) {
        return Ok(r);
    }

    let body: CreateClientBody = match req.json().await {
        Ok(b)  => b,
        Err(_) => return Response::error("invalid JSON body", 400),
    };

    let Some(raw_id) = body.id.as_deref().filter(|s| !s.is_empty()) else {
        return Response::error("id is required", 400);
    };
    // RFC 116: shape-validate the operator-supplied id at the boundary,
    // same rule as every other attacker/operator-controlled identifier.
    // `OidcClient.id` itself is still the plain `Id` (`String`) — RFC 116
    // has not migrated that field — so only the parse, not the type, is
    // adopted here.
    let id = match ClientId::parse(raw_id) {
        Ok(id) => id,
        Err(e) => return Response::error(format!("id: {e}"), 400),
    };
    let client_type = match parse_client_type(body.client_type.as_deref()) {
        Ok(t)  => t,
        Err(e) => return Response::error(e, 400),
    };
    let token_auth_method = match parse_token_auth_method(body.token_auth_method.as_deref()) {
        Ok(m)  => m,
        Err(e) => return Response::error(e, 400),
    };

    let new = NewClient {
        id:                id.as_str().to_owned(),
        name:              body.name.unwrap_or_default(),
        client_type,
        redirect_uris:     body.redirect_uris.unwrap_or_default(),
        allowed_scopes:    body.allowed_scopes.unwrap_or_default(),
        token_auth_method,
        audience:          body.audience.filter(|s| !s.is_empty()),
    };

    let repo = CloudflareClientRepository::new(&ctx.env);
    match clients::register_client(&repo, new).await {
        Ok(registered) => {
            audit::write_owned(
                &ctx.env, EventKind::AdminClientCreated,
                Some(principal.id.clone()), Some(registered.client.id.clone()),
                Some(format!("client_type={}", client_type_str(registered.client.client_type))),
            ).await.ok();

            let mut body = serde_json::json!({ "client": registered.client });
            // RFC 141 §4.2/§6.1: the one place the plaintext is ever read.
            if let Some(secret) = &registered.secret {
                body["client_secret"] = serde_json::Value::String(secret.expose().to_owned());
            }
            let mut resp = Response::from_json(&body)?;
            let _ = resp.headers_mut().set("cache-control", "no-store");
            Ok(resp.with_status(201))
        }
        Err(e) => op_error_response(e),
    }
}

// -------------------------------------------------------------------------
// POST /admin/console/clients/:id
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct UpdateClientBody {
    name:           Option<String>,
    redirect_uris:  Option<Vec<String>>,
    allowed_scopes: Option<Vec<String>>,
    audience:       Option<String>,
}

pub async fn update<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::ManageClients) {
        return Ok(r);
    }
    let Some(id) = ctx.param("id").cloned() else {
        return Response::error("missing client id", 400);
    };

    let body: UpdateClientBody = match req.json().await {
        Ok(b)  => b,
        Err(_) => return Response::error("invalid JSON body", 400),
    };

    let repo = CloudflareClientRepository::new(&ctx.env);

    // RFC 141 §10.2 — read the previous audience first, so the audit event
    // this route gives `OidcClientAudienceChanged` its first writer for
    // can record before/after, as its doc specifies.
    let before_audience = match repo.find(&id).await {
        Ok(Some(c)) => c.audience,
        Ok(None)    => return Response::error("unknown client", 404),
        Err(_)      => return Response::error("storage error", 500),
    };
    let after_audience = body.audience.clone().filter(|s| !s.is_empty());

    let update = ClientUpdate {
        name:           body.name.unwrap_or_default(),
        redirect_uris:  body.redirect_uris.unwrap_or_default(),
        allowed_scopes: body.allowed_scopes.unwrap_or_default(),
        audience:       after_audience.clone(),
    };

    match clients::update_client(&repo, &id, update).await {
        Ok(client) => {
            audit::write_owned(
                &ctx.env, EventKind::AdminClientUpdated,
                Some(principal.id.clone()), Some(client.id.clone()), None,
            ).await.ok();
            if before_audience != after_audience {
                audit::write_owned(
                    &ctx.env, EventKind::OidcClientAudienceChanged,
                    Some(principal.id.clone()), Some(client.id.clone()),
                    Some(format!(
                        "before={},after={}",
                        before_audience.as_deref().unwrap_or("null"),
                        after_audience.as_deref().unwrap_or("null"),
                    )),
                ).await.ok();
            }
            let mut resp = Response::from_json(&serde_json::json!({ "client": client }))?;
            let _ = resp.headers_mut().set("cache-control", "no-store");
            Ok(resp)
        }
        Err(e) => op_error_response(e),
    }
}

// -------------------------------------------------------------------------
// POST /admin/console/clients/:id/rotate-secret
// -------------------------------------------------------------------------

pub async fn rotate_secret<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::ManageClients) {
        return Ok(r);
    }
    let Some(id) = ctx.param("id").cloned() else {
        return Response::error("missing client id", 400);
    };

    let repo = CloudflareClientRepository::new(&ctx.env);
    match clients::rotate_secret(&repo, &id).await {
        Ok(secret) => {
            // RFC 141 §6.1: the event records THAT a secret was minted,
            // never the secret.
            audit::write_owned(
                &ctx.env, EventKind::AdminClientSecretRotated,
                Some(principal.id.clone()), Some(id.clone()), None,
            ).await.ok();
            let mut resp = Response::from_json(&serde_json::json!({
                "client_secret": secret.expose(),
            }))?;
            let _ = resp.headers_mut().set("cache-control", "no-store");
            Ok(resp)
        }
        Err(e) => op_error_response(e),
    }
}

// -------------------------------------------------------------------------
// POST /admin/console/clients/:id/delete
// -------------------------------------------------------------------------

pub async fn delete<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::ManageClients) {
        return Ok(r);
    }
    let Some(id) = ctx.param("id").cloned() else {
        return Response::error("missing client id", 400);
    };

    let repo = CloudflareClientRepository::new(&ctx.env);
    match clients::delete_client(&repo, &id).await {
        Ok(()) => {
            audit::write_owned(
                &ctx.env, EventKind::AdminClientDeleted,
                Some(principal.id.clone()), Some(id.clone()), None,
            ).await.ok();
            Response::from_json(&serde_json::json!({ "ok": true })).map(|mut r| {
                let _ = r.headers_mut().set("cache-control", "no-store");
                r
            })
        }
        Err(e) => op_error_response(e),
    }
}
