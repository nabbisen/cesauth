//! Token endpoint flows.
//!
//! Two grants, one file:
//!
//! * `exchange_code` - authorization_code -> access + refresh (+ id).
//! * `rotate_refresh` - refresh_token -> new access + refresh.
//!
//! **RFC 041** — dependency injection via `TokenDeps` struct eliminates
//! the 5-type-parameter footprint that previous callers had to spell out.
//! Wire compatibility is unchanged; the worker constructs `TokenDeps`
//! inline before calling.

use uuid::Uuid;

pub mod exchange_pipeline;

use crate::error::{CoreError, CoreResult};
use crate::jwt::{AccessTokenClaims, JwtSigner};
use crate::oidc::id_token::{build_id_token_claims, sign_id_token};
use crate::types::{ClientId, FamilyId, Jti, UserId};
use crate::oidc::token::TokenResponse;
use crate::service::client_auth::authenticate_token_client;
use self::exchange_pipeline::{AuthenticatedClient, ConsumedCode};
use crate::ports::repo::{ClientRepository, Grant, GrantRepository, UserRepository};
use crate::ports::store::{
    AuthChallengeStore, FamilyInit, RateLimitStore, RefreshTokenFamilyStore,
    RotateOutcome,
};
use crate::types::Scopes;

/// Default id_token TTL: 1 hour (same as access token in the reference deployment).
// RFC 103: crate::timing::ID_TOKEN_TTL_SECS now in crate::timing

// ---------------------------------------------------------------------------
// Dependency + config structs (RFC 041)
// ---------------------------------------------------------------------------

/// All repository dependencies needed by the token endpoint flows.
///
/// Construct once per request and pass by reference to `exchange_code` /
/// `rotate_refresh`. This replaces the previous 4-5 generic type parameters
/// per function, making call sites readable and error messages tractable.
#[allow(missing_debug_implementations)]
pub struct TokenDeps<'r, CR, AS, FS, GR, UR, RL>
where
    CR: ClientRepository,
    AS: AuthChallengeStore,
    FS: RefreshTokenFamilyStore,
    GR: GrantRepository,
    UR: UserRepository,
    RL: RateLimitStore,
{
    pub clients:  &'r CR,
    pub codes:    &'r AS,
    pub families: &'r FS,
    pub grants:   &'r GR,
    pub users:    &'r UR,
    pub rates:    &'r RL,
}

/// Static configuration for token issuance (TTLs, issuer).
///
/// These values come from the deployment's `wrangler.toml` / `Config` struct
/// and are constant for the lifetime of the worker instance.
#[derive(Debug, Clone)]
pub struct TokenConfig<'a> {
    pub access_ttl_secs:  i64,
    /// **RFC 139** — the refresh-family lifetime policy (absolute cap and
    /// idle window), enforced by the family store at rotation.
    pub refresh_lifetime: crate::ports::store::RefreshLifetime,
    /// Issuer URL, e.g. `"https://auth.example.com"`.
    pub iss:              &'a str,
}

/// Input to `exchange_code`. All fields are borrowed from the incoming
/// request; the caller is responsible for parsing the HTTP form body.
#[derive(Debug)]
pub struct ExchangeCodeInput<'a> {
    pub code:          &'a crate::types::ChallengeHandle,
    pub redirect_uri:  &'a str,
    pub client_id:     &'a str,
    /// **RFC 137** — the secret the client presented, from HTTP Basic or the
    /// form body; `None` when it presented none. Required for every client
    /// that is not public (see `authenticate_token_client`).
    pub client_secret: Option<&'a str>,
    pub code_verifier: &'a str,
    pub now_unix:      i64,
}

/// Redeem an authorization code for tokens.
///
/// Consistency story, step by step:
///
/// 1. Load and authenticate the client (eventual-consistency okay: clients
///    change slowly). Authentication precedes the code, so a failed attempt
///    does not consume it.
/// 2. Walk the [`exchange_pipeline`] (RFC 117): `take` the challenge from the
///    `AuthChallengeStore` (the single-consumption step; MUST be atomic - a
///    parallel call here must see `None`), then bind it to the authenticated
///    client, bind the redirect URI, and verify PKCE. Each step consumes the
///    last, and the data tokens are minted from exists only at the end, so
///    minting before verifying does not compile.
/// 3. (Folded into step 2.)
/// 4. Mint tokens. The refresh-token family's initial jti is created
///    here; we do not let the DO mint it, because the jti also needs
///    to go into the signed JWT and the DO's RPC surface does not
///    return the raw bytes.
/// 5. Init the family and persist the grant record.
///
/// If step 5 fails after step 2, we've consumed a code without issuing
/// a token. That's a user-visible "try again" which is acceptable;
/// silently retrying step 2 would allow a leaked code to be reused.
pub async fn exchange_code<CR, AS, FS, GR, UR, RL>(
    deps:   &TokenDeps<'_, CR, AS, FS, GR, UR, RL>,
    signer: &JwtSigner,
    cfg:    &TokenConfig<'_>,
    input:  &ExchangeCodeInput<'_>,
) -> CoreResult<TokenResponse>
where
    CR: ClientRepository,
    AS: AuthChallengeStore,
    FS: RefreshTokenFamilyStore,
    GR: GrantRepository,
    UR: UserRepository,
    RL: RateLimitStore,
{
    // 1. Client — one read (RFC 026), then authenticate (RFC 137 T2). Kept
    //    ahead of the code so a failed attempt does not consume it (RFC 137
    //    §13.1); `authenticate` yields the proof `bind_client` requires.
    let view = deps.clients
        .find_auth_view(input.client_id)
        .await
        .map_err(|_| CoreError::Internal)?
        .ok_or(CoreError::InvalidClient)?;
    let client = AuthenticatedClient::authenticate(&view, input.client_secret)?;

    // 2–3. Consume the code and verify it, in the order RFC 117 §1 states.
    //      `take` demands the proof `authenticate` produced, so it cannot run
    //      before it. Expiry is the store's rule (RFC 140), applied inside
    //      `take`. The errors are those the procedural code returned.
    let mint = ConsumedCode::take(deps.codes, input.code, input.now_unix, &client).await?
        .bind_client(&client)?
        .bind_redirect(input.redirect_uri)?
        .verify_pkce(input.code_verifier)?
        .into_mint_input();
    let user_id  = mint.user_id();
    let scopes   = mint.scopes();
    let client_id = mint.client_id();

    // 4. Mint.
    let family_id   = FamilyId::mint();
    let refresh_jti = Jti::mint();
    let access_jti  = Uuid::new_v4().to_string();

    let claims = AccessTokenClaims {
        iss:   signer.issuer().to_owned(),
        sub:   user_id.to_owned(),
        aud:   client_id.to_owned(),
        exp:   input.now_unix + cfg.access_ttl_secs,
        iat:   input.now_unix,
        jti:   access_jti,
        scope: scopes.to_space_separated(),
        cid:   client_id.to_owned(),
    };
    let access_token = signer.sign(&claims)?;

    // 5. Init family + grant.
    deps.families
        .init(&FamilyInit {
            family_id: family_id.clone(),
            user_id:   UserId::from_storage(user_id.to_owned()),
            client_id: ClientId::from_storage(client_id.to_owned()),
            scopes:    scopes.0.clone(),
            first_jti: refresh_jti.clone(),
            now_unix:  input.now_unix,
            auth_time: mint.auth_time(),
        })
        .await
        .map_err(|_| CoreError::Internal)?;

    deps.grants
        .create(&Grant {
            id:         family_id.to_string(),
            user_id:    user_id.to_owned(),
            client_id:  client_id.to_owned(),
            scopes:     scopes.0.clone(),
            issued_at:  input.now_unix,
            revoked_at: None,
        })
        .await
        .map_err(|_| CoreError::Internal)?;

    let refresh_token = encode_refresh(&family_id, &refresh_jti);

    // RFC 001: issue id_token when the scopes include "openid".
    let id_token = if scopes.0.iter().any(|s| s == "openid") {
        let user = deps.users
            .find_by_id(user_id)
            .await
            .map_err(|_| CoreError::Internal)?
            .ok_or(CoreError::InvalidGrant("user deleted between authorize and token exchange"))?;
        let claims = build_id_token_claims(
            cfg.iss,
            &user,
            client_id,
            &scopes.0,
            // RFC 033 / OIDC Core §3.1.3.6: nonce from the authorization
            // request MUST be reflected in the id_token when present.
            // Refresh-path id_tokens correctly omit nonce (§12).
            mint.nonce(),
            mint.auth_time(),
            input.now_unix,
            crate::timing::ID_TOKEN_TTL_SECS,
        );
        Some(sign_id_token(&claims, signer)?)
    } else {
        None
    };

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: cfg.access_ttl_secs,
        refresh_token: Some(refresh_token),
        id_token,
        scope: scopes.to_space_separated(),
    })
}

/// Input to `rotate_refresh`.
#[derive(Debug)]
pub struct RotateRefreshInput<'a> {
    pub refresh_token: &'a str,
    pub client_id:     &'a str,
    /// **RFC 137** — the secret the client presented; `None` when it presented
    /// none. Same rule as `ExchangeCodeInput::client_secret`.
    pub client_secret: Option<&'a str>,
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
pub async fn rotate_refresh<CR, AS, FS, GR, UR, RL>(
    deps:   &TokenDeps<'_, CR, AS, FS, GR, UR, RL>,
    signer: &JwtSigner,
    cfg:    &TokenConfig<'_>,
    input:  &RotateRefreshInput<'_>,
) -> CoreResult<TokenResponse>
where
    CR: ClientRepository,
    AS: AuthChallengeStore,
    FS: RefreshTokenFamilyStore,
    GR: GrantRepository,
    UR: UserRepository,
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
        let bucket = format!("refresh:{}", family_id.as_str());
        let dec = deps.rates.hit(
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

    // RFC 137 T3: authenticate before the family is read, so a client that
    // fails authentication learns nothing about it and cannot revoke it.
    let client = deps.clients
        .find_auth_view(input.client_id)
        .await
        .map_err(|_| CoreError::Internal)?
        .ok_or(CoreError::InvalidClient)?;
    authenticate_token_client(&client, input.client_secret)?;

    // RFC 137 T4: a refresh token may only be redeemed by the client it was
    // issued to. The refresh grant has no PKCE layer, so before this nothing
    // bound a family to its client at all.
    //
    // Peek and compare BEFORE rotate — rotating first would let a mismatched
    // client advance the family before being rejected. `client_id` is
    // immutable after family init, so peek-then-rotate opens no window on the
    // value being compared (RFC 137 §12.4). The `fam` re-read inside the
    // `Rotated` arm below shadows this one; every field it uses there
    // (user_id, scopes, auth_time) is equally immutable.
    let fam = deps.families
        .peek(&family_id)
        .await
        .map_err(|_| CoreError::Internal)?
        .ok_or(CoreError::InvalidGrant("refresh token revoked"))?;

    if fam.client_id.as_str() != client.client_id {
        // Presentation by a client the token was not issued to is evidence
        // of leakage — the same signal as reuse — so the established response
        // applies: invalidate the whole family (RFC 9700 §4.14.2). The wire
        // error is the same `invalid_grant` as an unknown or revoked family.
        deps.families
            .revoke(&family_id, input.now_unix)
            .await
            .map_err(|_| CoreError::Internal)?;
        return Err(CoreError::InvalidGrant("refresh token was issued to a different client"));
    }

    let new_jti = Jti::mint();
    let outcome = deps.families
        .rotate(&family_id, &presented_jti, &new_jti, input.now_unix, &cfg.refresh_lifetime)
        .await
        .map_err(|_| CoreError::Internal)?;

    match outcome {
        RotateOutcome::Rotated { new_current_jti } => {
            // Re-load the family to get user_id / scopes for the new
            // access token. Peek is fine here: we are inside the
            // rotate->peek ordering on the same DO instance, so the
            // peek sees the post-rotation state.
            let fam = deps.families
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
                sub:   fam.user_id.to_string(),
                aud:   client.client_id.clone(),
                exp:   input.now_unix + cfg.access_ttl_secs,
                iat:   input.now_unix,
                jti:   Uuid::new_v4().to_string(),
                scope: scopes.to_space_separated(),
                cid:   client.client_id.clone(),
            };
            let access_token = signer.sign(&claims)?;
            let refresh_token = encode_refresh(&family_id, &new_current_jti);

            // RFC 001: issue fresh id_token when scopes include "openid".
            // ADR-008 §Q10: auth_time is the family's original auth time,
            // NOT the rotation moment.
            let id_token = if scopes.0.iter().any(|s| s == "openid") {
                let user = deps.users
                    .find_by_id(fam.user_id.as_str())
                    .await
                    .map_err(|_| CoreError::Internal)?
                    .ok_or(CoreError::InvalidGrant("user deleted; cannot issue id_token"))?;
                let claims_id = build_id_token_claims(
                    cfg.iss,
                    &user,
                    &client.client_id,
                    &scopes.0,
                    None, // no nonce on refresh (already consumed at authorization)
                    fam.auth_time,         // original auth event time
                    input.now_unix,        // iat for this id_token
                    crate::timing::ID_TOKEN_TTL_SECS,
                );
                Some(sign_id_token(&claims_id, signer)?)
            } else {
                None
            };

            Ok(TokenResponse {
                access_token,
                token_type: "Bearer",
                expires_in: cfg.access_ttl_secs,
                refresh_token: Some(refresh_token),
                id_token,
                scope: scopes.to_space_separated(),
            })
        }
        RotateOutcome::AlreadyRevoked => {
            Err(CoreError::InvalidGrant("refresh token revoked"))
        }
        RotateOutcome::Expired(_) => {
            // RFC 139: past the absolute cap or the idle window. The store has
            // already revoked the family in the same write. On the wire this is
            // `invalid_grant`, the same as a revoked family. No expiry check
            // happens here: the store decided (§7.4).
            Err(CoreError::InvalidGrant("refresh token expired"))
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
// The opaque refresh token is `base64url("{family_id}.{jti}")`. It is not
// cryptographically protected - the family store is authoritative. RFC 139
// §9.4 removed the third field, an unsigned expiry that rotation ignored and
// introspection echoed as `exp`: a family's lifetime lives in the store and
// the policy, never in the token. All three decoders (here, `introspect`,
// `revoke`) accept exactly two parts; a third part is malformed.
// -------------------------------------------------------------------------

fn encode_refresh(family_id: &FamilyId, jti: &Jti) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let raw = format!("{}.{}", family_id.as_str(), jti.as_str());
    URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

fn decode_refresh(token: &str) -> CoreResult<(FamilyId, Jti)> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let bytes = URL_SAFE_NO_PAD
        .decode(token.as_bytes())
        .map_err(|_| CoreError::InvalidGrant("malformed refresh token"))?;
    let s = std::str::from_utf8(&bytes).map_err(|_| CoreError::InvalidGrant("malformed refresh token"))?;
    // Exactly two parts (RFC 139 §9.4): a third part is malformed, not ignored.
    let parts: Vec<&str> = s.split('.').collect();
    let [family_id, jti] = parts.as_slice() else {
        return Err(CoreError::InvalidGrant("malformed refresh token"));
    };
    Ok((FamilyId::from_storage(*family_id), Jti::from_storage(*jti)))
}

#[cfg(test)]
mod tests;
