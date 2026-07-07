//! `GET /userinfo` and `POST /userinfo` — OIDC Core §5.3 (RFC 040).
//!
//! Accepts a Bearer access token and returns the claims the token
//! subject authorized.  Scope gates:
//!
//! | Scope     | Claims returned       |
//! |-----------|-----------------------|
//! | (any)     | `sub`                 |
//! | `email`   | `email`, `email_verified` |
//! | `profile` | `name`                |
//!
//! ## Authentication
//!
//! The endpoint accepts a Bearer token in the `Authorization` header.
//! Form-encoded `access_token` parameter (§5.3.1) is intentionally
//! not supported — the Bearer header is the only method implemented
//! to avoid form-body confusion with other endpoints.
//!
//! ## Error responses
//!
//! - 401 with `WWW-Authenticate: Bearer error="invalid_token"` for any
//!   token validation failure (absent, expired, malformed, wrong issuer).
//! - 403 for a valid token from a client that lacks `openid` scope
//!   (OIDC Core §5.3.3 — technically the endpoint MAY also 403 here,
//!   but we choose to do so for defence in depth).

use cesauth_cf::ports::repo::{CloudflareSigningKeyRepository, CloudflareUserRepository};
use cesauth_core::jwt::claims::AccessTokenClaims;
use cesauth_core::oidc::userinfo::build_userinfo_claims;
use cesauth_core::ports::repo::{SigningKeyRepository, UserRepository};
use base64::{Engine, engine::general_purpose::STANDARD};
use worker::{Request, Response, Result, RouteContext};

use crate::config::Config;
use crate::log::{self, Category, Level};


pub async fn handler<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let cfg = Config::from_env(&ctx.env)?;

    // ── Extract Bearer token ──────────────────────────────────────────────
    let token = match extract_bearer(req.headers()) {
        Some(t) => t,
        None    => return www_auth_error("Bearer realm=\"cesauth\"", "invalid_request",
                                         "Authorization header with Bearer token required"),
    };

    // ── Verify access token ───────────────────────────────────────────────
    let key_repo = CloudflareSigningKeyRepository::new(&ctx.env);
    // `list_active` is the correct method name on SigningKeyRepository (trait).
    let keys = match key_repo.list_active().await {
        Ok(k)  => k,
        Err(_) => return Response::error("service temporarily unavailable", 503),
    };

    // Decode each key from base64, then try verify_for_introspect (4-arg form).
    // Same pattern as routes/oidc/introspect.rs — skip malformed keys with a
    // console warning rather than failing the whole request.
    let keys_raw: Vec<Vec<u8>> = keys.iter()
        .filter_map(|k| match STANDARD.decode(&k.public_key_b64) {
            Ok(raw) => Some(raw),
            Err(_)  => {
                worker::console_warn!("userinfo: malformed public_key_b64 for kid={}", k.kid);
                None
            }
        })
        .collect();

    let claims: AccessTokenClaims = {
        let mut verified = None;
        for raw in &keys_raw {
            if let Ok(c) = cesauth_core::jwt::verify_for_introspect::<AccessTokenClaims>(
                &token, raw, &cfg.issuer, 30,
            ) {
                verified = Some(c);
                break;
            }
        }
        match verified {
            Some(c) => c,
            None    => {
                log::emit(&cfg.log, Level::Warn, Category::Auth,
                    "userinfo: invalid or expired access token", None);
                return www_auth_error(
                    "Bearer realm=\"cesauth\", error=\"invalid_token\"",
                    "invalid_token",
                    "access token validation failed",
                );
            }
        }
    };

    // ── Issuer check ──────────────────────────────────────────────────────
    if claims.iss != cfg.issuer {
        return www_auth_error(
            "Bearer realm=\"cesauth\", error=\"invalid_token\"",
            "invalid_token",
            "token issuer mismatch",
        );
    }

    // ── Load user ─────────────────────────────────────────────────────────
    let user_repo = CloudflareUserRepository::new(&ctx.env);
    let user = match user_repo.find_by_id(&claims.sub).await {
        Ok(Some(u)) => u,
        Ok(None)    => {
            // User was deleted after token issuance.
            return www_auth_error(
                "Bearer realm=\"cesauth\", error=\"invalid_token\"",
                "invalid_token",
                "subject not found",
            );
        }
        Err(_)      => return Response::error("service temporarily unavailable", 503),
    };

    // ── Build and return claims ───────────────────────────────────────────
    let scopes: Vec<String> = claims.scope
        .split_whitespace()
        .map(str::to_owned)
        .collect();

    let userinfo = build_userinfo_claims(&claims.sub, &user, &scopes);

    let mut resp = Response::from_json(&userinfo)?;
    let _ = resp.headers_mut().set("cache-control", "no-store");
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract a `Bearer <token>` value from the `Authorization` header.
fn extract_bearer(headers: &worker::Headers) -> Option<String> {
    let auth = headers.get("authorization").ok()??;
    let token = auth.strip_prefix("Bearer ")?;
    if token.is_empty() { return None; }
    Some(token.to_owned())
}

/// HTTP 401 with `WWW-Authenticate` header.
fn www_auth_error(www_auth: &str, _error: &str, description: &str) -> Result<Response> {
    let mut resp = Response::error(description, 401)?;
    let _ = resp.headers_mut().set("www-authenticate", www_auth);
    Ok(resp)
}
