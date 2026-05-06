//! Token endpoint flows.
//!
//! Two grants, one file:
//!
//! * `exchange_code` - authorization_code -> access + refresh (+ id).
//! * `rotate_refresh` - refresh_token -> new access + refresh.
//!
//! The only Cloudflare-awareness here is the shape of the ports: we
//! assume a DO-backed `AuthChallengeStore` will single-consume codes
//! and a DO-backed `RefreshTokenFamilyStore` will serialize rotations.
//! Swapping to the in-memory `adapter-test` is a matter of passing
//! different trait implementers.

use uuid::Uuid;

use crate::error::{CoreError, CoreResult};
use crate::jwt::{AccessTokenClaims, JwtSigner};
use crate::oidc::pkce::{self, ChallengeMethod};
use crate::oidc::token::TokenResponse;
use crate::ports::repo::{ClientRepository, Grant, GrantRepository};
use crate::ports::store::{
    AuthChallengeStore, Challenge, FamilyInit, RateLimitStore, RefreshTokenFamilyStore,
    RotateOutcome,
};
use crate::types::Scopes;

/// Input to `exchange_code`. All fields are borrowed from the incoming
/// request; the caller is responsible for parsing the HTTP form body.
#[derive(Debug)]
pub struct ExchangeCodeInput<'a> {
    pub code:          &'a str,
    pub redirect_uri:  &'a str,
    pub client_id:     &'a str,
    pub code_verifier: &'a str,
    pub now_unix:      i64,
}

/// Redeem an authorization code for tokens.
///
/// Consistency story, step by step:
///
/// 1. Load the client (eventual-consistency okay: clients change slowly).
/// 2. `take` the challenge from the `AuthChallengeStore`. This is the
///    single-consumption step and MUST be atomic - a parallel call
///    here must see `None`.
/// 3. Verify PKCE against the stored challenge.
/// 4. Mint tokens. The refresh-token family's initial jti is created
///    here; we do not let the DO mint it, because the jti also needs
///    to go into the signed JWT and the DO's RPC surface does not
///    return the raw bytes.
/// 5. Init the family and persist the grant record.
///
/// If step 5 fails after step 2, we've consumed a code without issuing
/// a token. That's a user-visible "try again" which is acceptable;
/// silently retrying step 2 would allow a leaked code to be reused.
pub async fn exchange_code<CR, AS, FS, GR>(
    clients:   &CR,
    codes:     &AS,
    families:  &FS,
    grants:    &GR,
    signer:    &JwtSigner,
    access_ttl_secs:  i64,
    refresh_ttl_secs: i64,
    input:     &ExchangeCodeInput<'_>,
) -> CoreResult<TokenResponse>
where
    CR: ClientRepository,
    AS: AuthChallengeStore,
    FS: RefreshTokenFamilyStore,
    GR: GrantRepository,
{
    // 1. Client.
    let client = clients
        .find(input.client_id)
        .await
        .map_err(|_| CoreError::Internal)?
        .ok_or(CoreError::InvalidClient)?;

    // 2. Consume the code.
    let challenge = codes
        .take(input.code)
        .await
        .map_err(|_| CoreError::Internal)?
        .ok_or(CoreError::InvalidGrant("code is unknown or already used"))?;

    let (user_id, scopes, code_challenge, code_challenge_method, redirect_uri, _nonce) =
        match challenge {
            Challenge::AuthCode {
                user_id,
                scopes,
                code_challenge,
                code_challenge_method,
                redirect_uri,
                nonce,
                ..
            } => (user_id, scopes, code_challenge, code_challenge_method, redirect_uri, nonce),
            _ => return Err(CoreError::InvalidGrant("handle is not a code")),
        };

    // Sanity: the redirect_uri submitted at /token must match what was
    // bound to the code at /authorize (RFC 6749 §4.1.3).
    if redirect_uri != input.redirect_uri {
        return Err(CoreError::InvalidGrant("redirect_uri mismatch"));
    }

    // 3. PKCE.
    let method = ChallengeMethod::parse(&code_challenge_method)?;
    pkce::verify(input.code_verifier, &code_challenge, method)?;

    // 4. Mint.
    let family_id   = Uuid::new_v4().to_string();
    let refresh_jti = Uuid::new_v4().to_string();
    let access_jti  = Uuid::new_v4().to_string();

    let claims = AccessTokenClaims {
        iss:   signer.issuer().to_owned(),
        sub:   user_id.clone(),
        aud:   client.id.clone(),
        exp:   input.now_unix + access_ttl_secs,
        iat:   input.now_unix,
        jti:   access_jti,
        scope: scopes.to_space_separated(),
        cid:   client.id.clone(),
    };
    let access_token = signer.sign(&claims)?;

    // 5. Init family + grant.
    families
        .init(&FamilyInit {
            family_id: family_id.clone(),
            user_id:   user_id.clone(),
            client_id: client.id.clone(),
            scopes:    scopes.0.clone(),
            first_jti: refresh_jti.clone(),
            now_unix:  input.now_unix,
        })
        .await
        .map_err(|_| CoreError::Internal)?;

    grants
        .create(&Grant {
            id:         family_id.clone(),
            user_id,
            client_id:  client.id.clone(),
            scopes:     scopes.0.clone(),
            issued_at:  input.now_unix,
            revoked_at: None,
        })
        .await
        .map_err(|_| CoreError::Internal)?;

    let refresh_token = encode_refresh(&family_id, &refresh_jti, refresh_ttl_secs, input.now_unix);

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: access_ttl_secs,
        refresh_token: Some(refresh_token),
        id_token: None,
        scope: scopes.to_space_separated(),
    })
}

/// Input to `rotate_refresh`.
#[derive(Debug)]
pub struct RotateRefreshInput<'a> {
    pub refresh_token: &'a str,
    pub client_id:     &'a str,
    pub scope:         Option<&'a str>,
    pub now_unix:      i64,
    /// **v0.37.0** — Per-family rate-limit configuration
    /// (ADR-011 §Q1). The threshold counts attempts against
    /// a single `family_id`; the window is how long the
    /// counter keeps memory. Setting `threshold = 0`
    /// disables the gate.
    pub rate_limit_threshold:   u32,
    pub rate_limit_window_secs: i64,
}

/// Rotate a refresh token. Reuse of a rotated-out token revokes the
/// entire family atomically (BCP RFC 9700 §4.14.2) - this is enforced
/// by the store's `rotate` semantics, not re-enforced here.
///
/// **v0.37.0** — Per-family rate limit (ADR-011 §Q1). Before
/// consulting the family DO, we record a hit against
/// `rate_limit:refresh:<family_id>` in the rate-limit store. If
/// the threshold is exceeded, return `CoreError::RateLimited`
/// without touching the family — protects against rapid-retry
/// scanning attacks that could exhaust the family's
/// `retired_jtis` ring before the legitimate party notices.
/// The atomic-revoke-on-reuse invariant continues to apply
/// regardless; rate limit is DoS bounding, not security.
pub async fn rotate_refresh<CR, FS, RL>(
    clients:  &CR,
    families: &FS,
    rates:    &RL,
    signer:   &JwtSigner,
    access_ttl_secs:  i64,
    refresh_ttl_secs: i64,
    input:    &RotateRefreshInput<'_>,
) -> CoreResult<TokenResponse>
where
    CR: ClientRepository,
    FS: RefreshTokenFamilyStore,
    RL: RateLimitStore,
{
    let (family_id, presented_jti) = decode_refresh(input.refresh_token)?;

    // v0.37.0: rate-limit check BEFORE the family rotate.
    // Bucketing on family_id is the right granularity:
    // - per-jti would not catch leaked-token replay (each
    //   attempt may carry a different stale jti);
    // - per-user_id would unrelated apps interfere;
    // - per-family_id catches "rapid attempts against one
    //   logical session" exactly.
    //
    // threshold = 0 disables the gate (operator opt-out).
    if input.rate_limit_threshold > 0 {
        let bucket = format!("refresh:{family_id}");
        let dec = rates.hit(
            &bucket,
            input.now_unix,
            input.rate_limit_window_secs,
            input.rate_limit_threshold,
            input.rate_limit_threshold,  // escalate at the same threshold
        )
        .await
        .map_err(|_| CoreError::Internal)?;
        if !dec.allowed {
            return Err(CoreError::RateLimited {
                retry_after_secs: dec.resets_in,
            });
        }
    }

    let client = clients
        .find(input.client_id)
        .await
        .map_err(|_| CoreError::Internal)?
        .ok_or(CoreError::InvalidClient)?;

    let new_jti = Uuid::new_v4().to_string();
    let outcome = families
        .rotate(&family_id, &presented_jti, &new_jti, input.now_unix)
        .await
        .map_err(|_| CoreError::Internal)?;

    match outcome {
        RotateOutcome::Rotated { new_current_jti } => {
            // Re-load the family to get user_id / scopes for the new
            // access token. Peek is fine here: we are inside the
            // rotate->peek ordering on the same DO instance, so the
            // peek sees the post-rotation state.
            let fam = families
                .peek(&family_id)
                .await
                .map_err(|_| CoreError::Internal)?
                .ok_or(CoreError::InvalidGrant("family vanished after rotate"))?;

            // Scope narrowing per RFC 6749 §6: clients MAY request a
            // narrower scope at refresh time but not wider.
            let scopes = match input.scope {
                Some(s) => {
                    let requested = Scopes::parse(s);
                    let narrowed  = requested.restrict_to(&fam.scopes);
                    if narrowed.0.len() != requested.0.len() {
                        return Err(CoreError::InvalidScope("scope would widen"));
                    }
                    narrowed
                }
                None => Scopes(fam.scopes.clone()),
            };

            let claims = AccessTokenClaims {
                iss:   signer.issuer().to_owned(),
                sub:   fam.user_id.clone(),
                aud:   client.id.clone(),
                exp:   input.now_unix + access_ttl_secs,
                iat:   input.now_unix,
                jti:   Uuid::new_v4().to_string(),
                scope: scopes.to_space_separated(),
                cid:   client.id.clone(),
            };
            let access_token = signer.sign(&claims)?;
            let refresh_token = encode_refresh(&family_id, &new_current_jti, refresh_ttl_secs, input.now_unix);

            Ok(TokenResponse {
                access_token,
                token_type: "Bearer",
                expires_in: access_ttl_secs,
                refresh_token: Some(refresh_token),
                id_token: None,
                scope: scopes.to_space_separated(),
            })
        }
        RotateOutcome::AlreadyRevoked => {
            Err(CoreError::InvalidGrant("refresh token revoked"))
        }
        RotateOutcome::ReusedAndRevoked { reused_jti, was_retired } => {
            // Distinct error from AlreadyRevoked. The worker
            // dispatches on the variant to emit a
            // `refresh_token_reuse_detected` audit event with
            // forensic payload (BCP §4.13 / RFC 9700 §4.14.2).
            //
            // To the wire, this still surfaces as
            // `invalid_grant` so the HTTP-level response is
            // indistinguishable from a legitimate-revoked
            // family — see `oauth_error_response` in the
            // worker's token route. Distinguishing them
            // externally would let an attacker probe whether a
            // presented jti is in `retired_jtis`.
            Err(CoreError::RefreshTokenReuse { reused_jti, was_retired })
        }
    }
}

// -------------------------------------------------------------------------
// Refresh token encoding.
//
// We encode the opaque refresh token as `family_id.jti.expiry` joined by
// `.` and base64url-encoded. This is not cryptographically protected -
// the DO check is authoritative. It's a convenient non-opaque form that
// keeps `/token` stateless on the HTTP edge.
// -------------------------------------------------------------------------

fn encode_refresh(family_id: &str, jti: &str, ttl_secs: i64, now_unix: i64) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let expiry = now_unix.saturating_add(ttl_secs);
    let raw = format!("{family_id}.{jti}.{expiry}");
    URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

fn decode_refresh(token: &str) -> CoreResult<(String, String)> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let bytes = URL_SAFE_NO_PAD
        .decode(token.as_bytes())
        .map_err(|_| CoreError::InvalidGrant("malformed refresh token"))?;
    let s = std::str::from_utf8(&bytes).map_err(|_| CoreError::InvalidGrant("malformed refresh token"))?;
    let mut parts = s.split('.');
    let family_id = parts.next().ok_or(CoreError::InvalidGrant("malformed refresh token"))?;
    let jti       = parts.next().ok_or(CoreError::InvalidGrant("malformed refresh token"))?;
    // We don't consult the third part (expiry) here; the DO is the
    // authority. It only exists for debugging / future eager rejection.
    let _expiry = parts.next();
    Ok((family_id.to_owned(), jti.to_owned()))
}

#[cfg(test)]
mod tests;
