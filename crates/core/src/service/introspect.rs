//! Token introspection per RFC 7662 (v0.38.0, ADR-014).
//!
//! `introspect_token` is the dispatch layer: given an opaque
//! token string and an optional `token_type_hint`, it determines
//! whether the token is currently active and what claims to
//! report. The actual checks delegate to the JWT signer (for
//! access tokens) or the refresh-token family store (for refresh
//! tokens).
//!
//! ## Hint vs fallback
//!
//! Per RFC 7662 §2.1, the AS MAY use the hint to optimize but is
//! not required to honor it. cesauth tries the hinted type
//! first; if that comes back negative (signature mismatch /
//! family-not-found), tries the other type before declaring the
//! token inactive. This matches the spec's "if it doesn't match,
//! try the other type" guidance.
//!
//! ## Privacy on the inactive path
//!
//! ALL inactive paths return `IntrospectionResponse::inactive()`.
//! The constructor is the only way to build a `false`-active
//! response, and it doesn't accept any other fields. This is
//! the RFC 7662 §2.2 MUST: an inactive response leaks nothing.
//!
//! ## No reuse detection
//!
//! Calling introspection with a retired jti just reports
//! inactive; the reuse-detection invariant only applies on the
//! `/token` rotation path. This is intentional — introspection
//! is a read-only API for resource servers; making it
//! side-effecting would let a malicious resource server revoke
//! families on demand.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::error::{CoreError, CoreResult};
use crate::jwt::AccessTokenClaims;
use crate::jwt::signer::verify;
use crate::oidc::introspect::{IntrospectInput, IntrospectionResponse, TokenTypeHint};
use crate::ports::store::RefreshTokenFamilyStore;

/// Top-level introspection. Returns `IntrospectionResponse` —
/// success and "token is inactive" both flow through `Ok`. Only
/// genuine infrastructure errors (storage unreachable, etc.)
/// surface as `Err`.
///
/// `iss` and `aud` are the values to validate JWT claims
/// against. `public_key_raw` is the Ed25519 public key in raw
/// 32-byte form (cesauth signs with EdDSA).
pub async fn introspect_token<FS>(
    families:        &FS,
    public_key_raw:  &[u8],
    iss:             &str,
    aud:             &str,
    leeway_secs:     u64,
    input:           &IntrospectInput<'_>,
) -> CoreResult<IntrospectionResponse>
where
    FS: RefreshTokenFamilyStore,
{
    let order = match input.hint {
        Some(TokenTypeHint::AccessToken) | None
            => [TokenKind::Access, TokenKind::Refresh],
        Some(TokenTypeHint::RefreshToken)
            => [TokenKind::Refresh, TokenKind::Access],
    };

    for kind in order {
        let result = match kind {
            TokenKind::Access => {
                introspect_access(public_key_raw, iss, aud, leeway_secs, input.token).await
            }
            TokenKind::Refresh => {
                introspect_refresh(families, input.token, input.now_unix).await
            }
        };
        match result {
            Ok(Some(resp)) => return Ok(resp),
            Ok(None)       => continue,
            Err(e)         => return Err(e),
        }
    }

    Ok(IntrospectionResponse::inactive())
}

#[derive(Debug, Clone, Copy)]
enum TokenKind { Access, Refresh }

async fn introspect_access(
    public_key_raw: &[u8],
    iss:            &str,
    aud:            &str,
    leeway_secs:    u64,
    token:          &str,
) -> CoreResult<Option<IntrospectionResponse>> {
    let claims: AccessTokenClaims = match verify(token, public_key_raw, iss, aud, leeway_secs) {
        Ok(c)  => c,
        Err(_) => return Ok(None),
    };
    Ok(Some(IntrospectionResponse::active_access(
        claims.scope,
        claims.cid,
        claims.sub,
        claims.jti,
        claims.iat,
        claims.exp,
    )))
}

async fn introspect_refresh<FS>(
    families: &FS,
    token:    &str,
    _now:     i64,
) -> CoreResult<Option<IntrospectionResponse>>
where
    FS: RefreshTokenFamilyStore,
{
    let Some((family_id, presented_jti, exp)) = decode_refresh_token(token) else {
        return Ok(None);
    };

    let fam = families.peek(&family_id)
        .await
        .map_err(|_| CoreError::Internal)?;

    let Some(fam) = fam else { return Ok(None); };
    if fam.revoked_at.is_some() { return Ok(None); }
    if fam.current_jti != presented_jti { return Ok(None); }

    Ok(Some(IntrospectionResponse::active_refresh(
        fam.scopes.join(" "),
        fam.client_id,
        fam.user_id,
        presented_jti,
        fam.created_at,
        exp,
    )))
}

/// Decode the wire format used by `service::token::encode_refresh`
/// without fate-sharing on the rotation path. The authoritative
/// decoder lives there; this is a duplicate of the read-side
/// to keep introspection independent.
fn decode_refresh_token(token: &str) -> Option<(String, String, i64)> {
    let bytes = URL_SAFE_NO_PAD.decode(token.as_bytes()).ok()?;
    let s = std::str::from_utf8(&bytes).ok()?;
    let mut parts = s.splitn(3, '.');
    let family_id = parts.next()?.to_owned();
    let jti       = parts.next()?.to_owned();
    let exp       = parts.next()?.parse::<i64>().ok()?;
    Some((family_id, jti, exp))
}

#[cfg(test)]
mod tests;
