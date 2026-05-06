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
use crate::jwt::signer::{extract_kid, verify};
use crate::oidc::introspect::{IntrospectInput, IntrospectionKey, IntrospectionResponse, TokenTypeHint};
use crate::ports::store::RefreshTokenFamilyStore;

/// Top-level introspection. Returns `IntrospectionResponse` —
/// success and "token is inactive" both flow through `Ok`. Only
/// genuine infrastructure errors (storage unreachable, etc.)
/// surface as `Err`.
///
/// `iss` and `aud` are the values to validate JWT claims
/// against. **v0.41.0** — `keys` is the **active set** of
/// signing keys (ADR-014 §Q4). Multiple keys can be
/// present during a signing-key rotation grace period; the
/// access-token path does kid-directed lookup with a
/// try-each fallback so an access token signed by any
/// active key verifies correctly. v0.38.0's behavior
/// (single key, only the most-recent) is the special case
/// of `keys.len() == 1`.
pub async fn introspect_token<FS>(
    families:    &FS,
    keys:        &[IntrospectionKey<'_>],
    iss:         &str,
    aud:         &str,
    leeway_secs: u64,
    input:       &IntrospectInput<'_>,
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
                introspect_access(keys, iss, aud, leeway_secs, input.token).await
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

/// Verify an access-token JWT against the active key set.
///
/// **v0.41.0 — multi-key strategy**:
///
/// 1. Extract the JWT's `kid` header without verifying.
///    If present and the kid matches one of the active
///    keys, try that key first. The fast path: one
///    crypto verify call.
/// 2. Fall through to trying every active key in turn if
///    (a) no `kid` header is present, (b) the `kid`
///    doesn't match anything in the active set, or (c)
///    the kid-matched key fails to verify (defensive —
///    shouldn't happen against a legitimate token).
/// 3. Return `Some(active_response)` on the first key
///    that verifies. Return `None` (inactive) if every
///    key fails.
///
/// The kid in the JWT header is **untrusted at this
/// point** — we use it only as a hint for key selection;
/// the cryptographic check still runs against the chosen
/// key. An attacker who forges a kid pointing at a key
/// they don't control still has to produce a valid
/// signature with that key, which they can't.
///
/// Returns:
/// - `Ok(Some(resp))` if any key verifies.
/// - `Ok(None)` if every key fails (inactive).
/// - `Err(_)` for internal errors (none currently).
async fn introspect_access(
    keys:        &[IntrospectionKey<'_>],
    iss:         &str,
    aud:         &str,
    leeway_secs: u64,
    token:       &str,
) -> CoreResult<Option<IntrospectionResponse>> {
    if keys.is_empty() {
        // No active signing keys at all — the deployment
        // is misconfigured or in a transitional state.
        // Inactive is the right answer here; the
        // operator's signing-key bootstrap path will
        // surface the misconfiguration via other signals.
        return Ok(None);
    }

    // Try kid-directed lookup first.
    if let Some(presented_kid) = extract_kid(token) {
        if let Some(matched) = keys.iter().find(|k| k.kid == presented_kid) {
            if let Ok(claims) = verify::<AccessTokenClaims>(
                token, matched.public_key_raw, iss, aud, leeway_secs,
            ) {
                return Ok(Some(IntrospectionResponse::active_access(
                    claims.scope, claims.cid, claims.sub, claims.jti, claims.iat, claims.exp,
                )));
            }
            // kid-matched key failed verification. Fall
            // through to try-each. This is defensive —
            // a legitimate cesauth token's kid should
            // always match its signing key. A mismatch
            // here means either an attacker forged a
            // kid (and try-each will reject all keys),
            // or there's a deeper bug we want to surface
            // by trying every key.
        }
    }

    // Fall through: try each active key. Stop on first
    // successful verification.
    for k in keys {
        if let Ok(claims) = verify::<AccessTokenClaims>(
            token, k.public_key_raw, iss, aud, leeway_secs,
        ) {
            return Ok(Some(IntrospectionResponse::active_access(
                claims.scope, claims.cid, claims.sub, claims.jti, claims.iat, claims.exp,
            )));
        }
    }
    Ok(None)
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
