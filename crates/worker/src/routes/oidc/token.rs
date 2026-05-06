//! `POST /token` - authorization-code exchange and refresh rotation.

use cesauth_cf::ports::{
    repo::{CloudflareClientRepository, CloudflareGrantRepository},
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
            // as newlines. `JwtSigner::from_pem` wraps jsonwebtoken's
            // PKCS8 PEM parser, which needs real line breaks between
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

    let grant = match req_in.classify() {
        Ok(g)  => g,
        Err(e) => return oauth_error_response(&e),
    };

    match grant {
        TokenGrant::AuthorizationCode(g) => {
            let input = token_service::ExchangeCodeInput {
                code:          g.code,
                redirect_uri:  g.redirect_uri,
                client_id:     g.client_id,
                code_verifier: g.code_verifier,
                now_unix:      now,
            };
            match token_service::exchange_code(
                &clients, &codes, &families, &grants, &signer,
                cfg.access_token_ttl_secs, cfg.refresh_token_ttl_secs, &input,
            ).await {
                Ok(tr) => {
                    audit::write_owned(
                        &ctx.env, EventKind::TokenIssued,
                        None, Some(g.client_id.to_owned()), None,
                    ).await.ok();
                    let mut resp = Response::from_json(&tr)?;
                    let _ = resp.headers_mut().set("cache-control", "no-store");
                    let _ = resp.headers_mut().set("pragma",        "no-cache");
                    Ok(resp)
                }
                Err(e) => {
                    log::emit(&cfg.log, Level::Warn, Category::Auth,
                        &format!("exchange_code failed: {e:?}"),
                        Some(&g.client_id));
                    audit::write_owned(
                        &ctx.env, EventKind::AuthFailed,
                        None, Some(g.client_id.to_owned()),
                        Some(format!("{e:?}")),
                    ).await.ok();
                    oauth_error_response(&e)
                }
            }
        }

        TokenGrant::RefreshToken(g) => {
            let input = token_service::RotateRefreshInput {
                refresh_token: g.refresh_token,
                client_id:     g.client_id,
                scope:         g.scope,
                now_unix:      now,
            };
            match token_service::rotate_refresh(
                &clients, &families, &signer,
                cfg.access_token_ttl_secs, cfg.refresh_token_ttl_secs, &input,
            ).await {
                Ok(tr) => {
                    audit::write_owned(
                        &ctx.env, EventKind::TokenRefreshed,
                        None, Some(g.client_id.to_owned()), None,
                    ).await.ok();
                    let mut resp = Response::from_json(&tr)?;
                    let _ = resp.headers_mut().set("cache-control", "no-store");
                    Ok(resp)
                }
                Err(e) => {
                    log::emit(&cfg.log, Level::Warn, Category::Auth,
                        &format!("rotate_refresh failed: {e:?}"),
                        Some(&g.client_id));

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
                                "client_id":     g.client_id,
                                "presented_jti": reused_jti,
                                "was_retired":   was_retired,
                            }).to_string();
                            audit::write_owned(
                                &ctx.env, EventKind::RefreshTokenReuseDetected,
                                None, Some(g.client_id.to_owned()),
                                Some(payload),
                            ).await.ok();
                        }
                        _ => {
                            audit::write_owned(
                                &ctx.env, EventKind::TokenRefreshRejected,
                                None, Some(g.client_id.to_owned()),
                                Some(format!("{e:?}")),
                            ).await.ok();
                        }
                    }
                    oauth_error_response(&e)
                }
            }
        }
    }
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
