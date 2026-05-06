//! `POST /introspect` — RFC 7662 Token Introspection (v0.38.0,
//! ADR-014).
//!
//! Allows a registered confidential client (typically a resource
//! server) to ask cesauth whether a presented token is currently
//! active and to retrieve its claims. The endpoint is necessary
//! because:
//!
//! - Refresh tokens are opaque to bearers; only the issuer can
//!   tell whether a presented refresh token is current vs
//!   retired vs from a revoked family.
//! - Access tokens are signed JWTs that the resource server
//!   could verify locally, but they may have been revoked since
//!   issuance (a future revocation cascade); only the issuer
//!   knows that.
//!
//! ## Privacy invariant — RFC 7662 §2.2
//!
//! When the endpoint returns `active = false`, the response
//! body MUST NOT include any other claims. This is enforced at
//! the type level by [`cesauth_core::oidc::introspect::IntrospectionResponse`]
//! — the only constructor that produces an inactive response
//! takes no claim arguments. The handler can't accidentally
//! leak.
//!
//! ## Authentication — RFC 7662 §2.1
//!
//! Client authentication is REQUIRED. cesauth accepts:
//!
//! - `client_secret_basic` (HTTP `Authorization: Basic
//!   <b64(id:secret)>`).
//! - `client_secret_post` (form-body `client_id` +
//!   `client_secret`) as a fallback when no Authorization
//!   header is present.
//!
//! Auth failure returns 401 with `WWW-Authenticate: Basic
//! realm="cesauth"`.
//!
//! Inactive vs unauthenticated: a successful authentication
//! followed by a token that's-not-active is HTTP 200 with
//! `{"active": false}`. A failed authentication is 401 with no
//! body claims at all. This split is also the spec
//! (introspection responses never come from unauthenticated
//! callers).

use cesauth_cf::ports::repo::{CloudflareClientRepository, CloudflareSigningKeyRepository};
use cesauth_cf::ports::store::CloudflareRefreshTokenFamilyStore;
use cesauth_core::oidc::introspect::{IntrospectInput, TokenTypeHint};
use cesauth_core::ports::repo::SigningKeyRepository;
use cesauth_core::service::client_auth;
use cesauth_core::service::introspect::introspect_token;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::client_auth as client_auth_extract;
use crate::config::Config;
use crate::log::{self, Category, Level};


pub async fn handler<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let cfg = Config::from_env(&ctx.env)?;

    // RFC 7662 §2.1: the request body is form-encoded.
    let form = req.form_data().await?;
    let token = match form.get("token") {
        Some(worker::FormEntry::Field(v)) if !v.is_empty() => v,
        _ => {
            return error_response("invalid_request", 400, None);
        }
    };
    let hint = form.get("token_type_hint")
        .and_then(|e| match e { worker::FormEntry::Field(v) => Some(v), _ => None })
        .and_then(|v| TokenTypeHint::parse(&v));

    // Client authentication.
    let creds = match client_auth_extract::extract(req.headers(), &form) {
        Some(c) => c,
        None    => return unauthorized(),
    };
    let clients = CloudflareClientRepository::new(&ctx.env);
    if let Err(_) = client_auth::verify_client_credentials(
        &clients, &creds.client_id, &creds.client_secret,
    ).await {
        log::emit(&cfg.log, Level::Warn, Category::Auth,
            "introspect: client auth failed",
            Some(&creds.client_id));
        return unauthorized();
    }

    // Look up active signing keys for verifying access-token JWTs.
    // **v0.41.0** — multi-key support (ADR-014 §Q4
    // resolved). Pre-v0.41.0 we used `keys.first()` — only the
    // most-recently-added active key would verify, so during a
    // signing-key rotation grace period an access token signed
    // with an older but still-active kid would falsely report
    // inactive. Now we build a slice of every active key's
    // (kid, raw_public_key) and pass it to `introspect_token`,
    // which does kid-directed lookup with a try-each fallback.
    let key_repo = CloudflareSigningKeyRepository::new(&ctx.env);
    let active = key_repo.list_active().await
        .map_err(|_| worker::Error::RustError("signing key lookup failed".into()))?;

    use base64::{Engine, engine::general_purpose::STANDARD};
    // Decode b64-encoded public keys once. Filter out any
    // malformed entries with a console warning rather than
    // failing the whole request — a single garbled key in the
    // active set shouldn't shadow the others. (In practice a
    // malformed `public_key_b64` is itself a structural bug
    // worth fixing, but we don't want it to take down
    // introspection while we figure that out.)
    let keys_raw: Vec<(String, Vec<u8>)> = active.iter()
        .filter_map(|k| match STANDARD.decode(&k.public_key_b64) {
            Ok(raw) => Some((k.kid.clone(), raw)),
            Err(_)  => {
                worker::console_warn!("introspect: malformed public_key_b64 for kid={}", k.kid);
                None
            }
        })
        .collect();
    let key_views: Vec<cesauth_core::oidc::introspect::IntrospectionKey<'_>> = keys_raw.iter()
        .map(|(kid, raw)| cesauth_core::oidc::introspect::IntrospectionKey {
            kid: kid.as_str(), public_key_raw: raw.as_slice(),
        })
        .collect();

    let families = CloudflareRefreshTokenFamilyStore::new(&ctx.env);
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let resp = introspect_token(
        &families,
        &key_views,
        &cfg.issuer,
        &cfg.issuer,  // audience: cesauth tokens are aud=iss for now
        30,           // leeway_secs
        &IntrospectInput { token: &token, hint, now_unix: now },
    ).await
        .map_err(|e| worker::Error::RustError(format!("introspect failed: {e:?}")))?;

    // Audit. Payload deliberately omits the token itself —
    // see `EventKind::TokenIntrospected` docs for why.
    let token_type = if !resp.active {
        "none"
    } else if resp.token_type.as_deref() == Some("Bearer") {
        "access_token"
    } else {
        "refresh_token"
    };
    let payload = serde_json::json!({
        "introspecter_client_id": creds.client_id,
        "token_type":             token_type,
        "active":                 resp.active,
    }).to_string();
    audit::write_owned(
        &ctx.env, EventKind::TokenIntrospected,
        None, Some(creds.client_id),
        Some(payload),
    ).await.ok();

    let mut http = Response::from_json(&resp)?;
    let _ = http.headers_mut().set("cache-control", "no-store");
    let _ = http.headers_mut().set("pragma",        "no-cache");
    Ok(http)
}

fn error_response(code: &str, status: u16, retry_after: Option<i64>) -> Result<Response> {
    let body = serde_json::json!({ "error": code });
    let mut resp = Response::from_json(&body)?.with_status(status);
    let _ = resp.headers_mut().set("cache-control", "no-store");
    if let Some(secs) = retry_after {
        let _ = resp.headers_mut().set("retry-after", &secs.to_string());
    }
    Ok(resp)
}

fn unauthorized() -> Result<Response> {
    let mut resp = error_response("invalid_client", 401, None)?;
    // RFC 6750 says protected-resource endpoints set this;
    // RFC 7662 §2.1 doesn't mandate it for /introspect but
    // leaving it lets standard OAuth client libraries
    // interpret the response correctly.
    let _ = resp.headers_mut().set("www-authenticate", r#"Basic realm="cesauth""#);
    Ok(resp)
}
