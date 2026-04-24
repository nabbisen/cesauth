//! `POST /revoke` - token revocation per RFC 7009.
//!
//! Always returns 200 on well-formed requests, regardless of whether
//! the token existed. This mitigates token-existence probing.

use cesauth_cf::ports::store::CloudflareRefreshTokenFamilyStore;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};


pub async fn revoke<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let body = req.text().await.unwrap_or_default();
    let form: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(body.as_bytes()).into_owned().collect();

    let token = form.get("token").cloned().unwrap_or_default();
    let client_id = form.get("client_id").cloned().unwrap_or_default();

    // For refresh tokens we decode the family id out of the opaque
    // form and tell the DO to revoke. For access tokens we do nothing:
    // they're short-lived and resource servers handle revocation by
    // consulting ActiveSession.
    if !token.is_empty() {
        if let Some((family_id, _)) = decode_refresh_best_effort(&token) {
            let families = CloudflareRefreshTokenFamilyStore::new(&ctx.env);
            let now = OffsetDateTime::now_utc().unix_timestamp();
            use cesauth_core::ports::store::RefreshTokenFamilyStore;
            let _ = families.revoke(&family_id, now).await;

            audit::write_owned(
                &ctx.env, EventKind::RevocationRequested,
                None, Some(client_id), Some("refresh".into()),
            ).await.ok();
        }
    }

    // Always 200, empty body (per RFC 7009 §2.2).
    Response::ok("")
}

fn decode_refresh_best_effort(token: &str) -> Option<(String, String)> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let bytes = URL_SAFE_NO_PAD.decode(token.as_bytes()).ok()?;
    let s     = std::str::from_utf8(&bytes).ok()?;
    let mut parts = s.split('.');
    let family_id = parts.next()?.to_owned();
    let jti       = parts.next()?.to_owned();
    Some((family_id, jti))
}
