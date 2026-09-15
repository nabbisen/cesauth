//! `POST /token` - authorization-code exchange and refresh rotation.

use cesauth_cf::ports::{
    repo::{CloudflareClientRepository, CloudflareGrantRepository, CloudflareUserRepository},
    store::{CloudflareAuthChallengeStore, CloudflareRefreshTokenFamilyStore},
};
use cesauth_core::jwt::JwtSigner;
use cesauth_core::oidc::token::{TokenGrant, TokenRequest};
use cesauth_core::service::token as token_service;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::config::{Config, load_signing_key};
use crate::error::oauth_error_response;
use crate::log::{self, Category, Level};


pub async fn token<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let cfg = Config::from_env(&ctx.env)?;

    // RFC 137: read client credentials from the headers before the body is
    // consumed. `client_auth::extract` cannot be used here -- it needs
    // `worker::FormData`, and this route reads its body as text -- so the
    // Basic-first precedence is applied by `resolve_token_client_credentials`
    // below instead.
    let authorization_header_present =
        req.headers().get("authorization").ok().flatten().is_some();
    let basic = crate::client_auth::extract_from_basic(req.headers());

    // Parse form body. RFC 6749 says the token endpoint accepts
    // application/x-www-form-urlencoded; we do not accept JSON.
    let body = req.text().await.unwrap_or_default();
    let form: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(body.as_bytes()).into_owned().collect();

    let req_in = TokenRequest {
        grant_type:    form.get("grant_type").cloned().unwrap_or_default(),
        code:          form.get("code").cloned(),
        redirect_uri:  form.get("redirect_uri").cloned(),
        client_id:     form.get("client_id").cloned(),
        client_secret: form.get("client_secret").cloned(),
        code_verifier: form.get("code_verifier").cloned(),
        refresh_token: form.get("refresh_token").cloned(),
        scope:         form.get("scope").cloned(),
    };

    log::emit(&cfg.log, Level::Info, Category::Http,
        &format!("/token grant_type={}", req_in.grant_type),
        req_in.client_id.as_deref());

    let signer_pem = match load_signing_key(&ctx.env) {
        Ok(pem) => pem,
        Err(e)  => {
            log::emit(&cfg.log, Level::Error, Category::Config,
                &format!("load_signing_key failed: {e}"), None);
            return oauth_error_response(&cesauth_core::CoreError::Internal);
        }
    };
    let signer = match JwtSigner::from_pem(cfg.jwt_kid.clone(), &signer_pem, cfg.issuer.clone()) {
        Ok(s)  => s,
        Err(e) => {
            // Most common cause: the PEM in .dev.vars was escaped
            // with literal `\n` characters that weren't interpreted
            // as newlines. `JwtSigner::from_pem` uses the pkcs8 crate's
            // PEM parser, which needs real line breaks between
            // `-----BEGIN`/`-----END` and the base64 body.
            log::emit(&cfg.log, Level::Error, Category::Crypto,
                &format!("JwtSigner::from_pem failed: {e:?}. \
                          Is JWT_SIGNING_KEY a literal PEM with real \
                          line breaks? (See docs/local-development.md \
                          step 4.)"), None);
            return oauth_error_response(&cesauth_core::CoreError::JwtSigning);
        }
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let clients  = CloudflareClientRepository::new(&ctx.env);
    let codes    = CloudflareAuthChallengeStore::new(&ctx.env);
    let families = CloudflareRefreshTokenFamilyStore::new(&ctx.env);
    let grants   = CloudflareGrantRepository::new(&ctx.env);
    let users    = CloudflareUserRepository::new(&ctx.env);
    let rates    = cesauth_cf::ports::store::CloudflareRateLimitStore::new(&ctx.env);

    // RFC 041: single deps + config bundle replaces per-call arg lists.
    let deps = token_service::TokenDeps {
        clients: &clients,
        codes:   &codes,
        families: &families,
        grants:  &grants,
        users:   &users,
        rates:   &rates,
    };
    let tok_cfg = token_service::TokenConfig {
        access_ttl_secs:  cfg.access_token_ttl_secs,
        refresh_lifetime: cfg.refresh_lifetime,
        iss:              &cfg.issuer,
    };

    let grant = match req_in.classify_with_authorization(authorization_header_present) {
        Ok(g)  => g,
        Err(e) => return token_error_response(&e, authorization_header_present),
    };

    // RFC 137 T2/T3: which client this request speaks for, and the secret it
    // presented. Resolved once, for both grants; the service layer then
    // authenticates it against the stored client before touching the code or
    // the refresh family.
    let (client_id, client_secret) =
        match cesauth_core::service::client_auth::resolve_token_client_credentials(
            authorization_header_present,
            basic.as_ref().map(|c| (c.client_id.as_str(), c.client_secret.as_str())),
            req_in.client_id.as_deref(),
            req_in.client_secret.as_deref(),
        ) {
            Ok(v)  => v,
            Err(e) => return token_error_response(&e, authorization_header_present),
        };

    match grant {
        TokenGrant::AuthorizationCode(g) => {
            let _ch = match cesauth_core::types::ChallengeHandle::parse(g.code) {
                Ok(h) => h,
                Err(_) => return oauth_error_response(&cesauth_core::CoreError::InvalidGrant("invalid code format")),
            };
            let input = token_service::ExchangeCodeInput {
                code:          &_ch,
                redirect_uri:  g.redirect_uri,
                client_id:     &client_id,
                client_secret: client_secret.as_deref(),
                code_verifier: g.code_verifier,
                now_unix:      now,
            };
            match token_service::exchange_code(&deps, &signer, &tok_cfg, &input).await {
                Ok(tr) => {
                    audit::write_owned(
                        &ctx.env, EventKind::TokenIssued,
                        None, Some(client_id.clone()), None,
                    ).await.ok();
                    let mut resp = Response::from_json(&tr)?;
                    let _ = resp.headers_mut().set("cache-control", "no-store");
                    let _ = resp.headers_mut().set("pragma",        "no-cache");
                    Ok(resp)
                }
                Err(e) => {
                    log::emit(&cfg.log, Level::Warn, Category::Auth,
                        &format!("exchange_code failed: {e:?}"),
                        Some(&client_id));
                    audit::write_owned(
                        &ctx.env, EventKind::AuthFailed,
                        None, Some(client_id.clone()),
                        Some(format!("{e:?}")),
                    ).await.ok();
                    token_error_response(&e, authorization_header_present)
                }
            }
        }

        TokenGrant::RefreshToken(g) => {
            let input = token_service::RotateRefreshInput {
                refresh_token: g.refresh_token,
                client_id:     &client_id,
                client_secret: client_secret.as_deref(),
                scope:         g.scope,
                now_unix:      now,
                rate_limit_threshold:   cfg.refresh_rate_limit_threshold,
                rate_limit_window_secs: cfg.refresh_rate_limit_window_secs,
            };
            match token_service::rotate_refresh(&deps, &signer, &tok_cfg, &input).await {
                Ok(tr) => {
                    audit::write_owned(
                        &ctx.env, EventKind::TokenRefreshed,
                        None, Some(client_id.clone()), None,
                    ).await.ok();
                    let mut resp = Response::from_json(&tr)?;
                    let _ = resp.headers_mut().set("cache-control", "no-store");
                    Ok(resp)
                }
                Err(e) => {
                    log::emit(&cfg.log, Level::Warn, Category::Auth,
                        &format!("rotate_refresh failed: {e:?}"),
                        Some(&client_id));

                    // v0.34.0: dispatch on the variant. A reuse
                    // detection emits the dedicated audit event
                    // with forensic payload (family_id, presented
                    // jti, was_retired); other rotate failures
                    // (revoked, expired, unknown family) emit the
                    // generic refresh_rejected. The HTTP response
                    // is the same `invalid_grant` for both — see
                    // `oauth_error_response` for the rationale.
                    match &e {
                        cesauth_core::CoreError::RefreshTokenReuse { reused_jti, was_retired } => {
                            // Decode family_id from the presented
                            // refresh token. If the token is
                            // malformed we still record the event
                            // with an empty family — better
                            // partial visibility than no event at
                            // all.
                            let family_id = decode_family_id_lossy(g.refresh_token);
                            let payload = serde_json::json!({
                                "family_id":     family_id,
                                "client_id":     client_id,
                                "presented_jti": reused_jti,
                                "was_retired":   was_retired,
                            }).to_string();
                            audit::write_owned(
                                &ctx.env, EventKind::RefreshTokenReuseDetected,
                                None, Some(client_id.clone()),
                                Some(payload),
                            ).await.ok();
                        }
                        cesauth_core::CoreError::RateLimited { retry_after_secs } => {
                            // v0.37.0: distinct audit event for
                            // rate-limit. Operators monitoring for
                            // brute-force / scanning attacks
                            // alert on this kind specifically; it
                            // fires before the family DO is
                            // consulted so it doesn't imply
                            // reuse.
                            let family_id = decode_family_id_lossy(g.refresh_token);
                            let payload = serde_json::json!({
                                "family_id":        family_id,
                                "client_id":        client_id,
                                "threshold":        cfg.refresh_rate_limit_threshold,
                                "window_secs":      cfg.refresh_rate_limit_window_secs,
                                "retry_after_secs": retry_after_secs,
                            }).to_string();
                            audit::write_owned(
                                &ctx.env, EventKind::RefreshRateLimited,
                                None, Some(client_id.clone()),
                                Some(payload),
                            ).await.ok();
                        }
                        _ => {
                            audit::write_owned(
                                &ctx.env, EventKind::TokenRefreshRejected,
                                None, Some(client_id.clone()),
                                Some(format!("{e:?}")),
                            ).await.ok();
                        }
                    }
                    token_error_response(&e, authorization_header_present)
                }
            }
        }
    }
}

/// **RFC 137 C1-137** — `oauth_error_response`, plus the `WWW-Authenticate`
/// challenge RFC 6749 §5.2 requires on `invalid_client` when the client
/// authenticated with the `Authorization` header. The decision is the pure
/// `error::token_www_authenticate`; the status mapping is unchanged.
fn token_error_response(
    err:                          &cesauth_core::CoreError,
    authorization_header_present: bool,
) -> Result<Response> {
    let mut resp = oauth_error_response(err)?;
    if let Some(challenge) = crate::error::token_www_authenticate(err, authorization_header_present) {
        let _ = resp.headers_mut().set("www-authenticate", challenge);
    }
    Ok(resp)
}

/// Audit-only lossy decode of a refresh token's family_id. The
/// authoritative decode lives inside `cesauth_core::service::token`
/// and propagates errors as `CoreError::InvalidGrant`; we don't want
/// to fail-closed on the audit-write path just because a token is
/// malformed (we'd lose the reuse-detection signal we're trying to
/// record). On any decode failure this returns `"<malformed>"` so
/// the audit row carries SOMETHING to correlate against.
///
/// Mirrors the encoder in `core::service::token`:
/// `base64url(family_id "." jti "." expiry)`.
fn decode_family_id_lossy(token: &str) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(token.as_bytes()) else {
        return "<malformed>".to_owned();
    };
    let Ok(s) = std::str::from_utf8(&bytes) else {
        return "<malformed>".to_owned();
    };
    s.split('.').next().unwrap_or("<malformed>").to_owned()
}
