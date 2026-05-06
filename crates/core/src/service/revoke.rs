//! RFC 7009 token revocation service (v0.42.0).
//!
//! ## Background
//!
//! v0.27.0 shipped `POST /revoke` as a public endpoint:
//! anyone with a refresh token could submit it and the
//! family DO would mark the family revoked. That matched
//! RFC 7009 §2.1's permissive guidance for public clients
//! but was insufficient for confidential clients. Per RFC
//! 7009 §2.1:
//!
//! > Confidential or credentialed clients MUST authenticate
//! > with the authorization server.
//!
//! And §2:
//!
//! > The authorization server first validates the client
//! > credentials (in case of a confidential or credentialed
//! > client) and then verifies whether the token was issued
//! > to the client making the revocation request.
//!
//! v0.42.0 implements both gates.
//!
//! ## What this module is
//!
//! Pure logic that orchestrates the policy decisions:
//! given a token + optional client credentials + the
//! repositories needed to look up things, classify the
//! request into one of four [`RevokeOutcome`] variants and
//! perform the side effect (family DO revoke) when
//! authorized. The worker handler wraps this with form
//! parsing + audit-event emission + HTTP response shaping.
//!
//! ## What this module isn't
//!
//! Not a request parser. Not a response formatter. Not an
//! audit-event writer. The worker's
//! `routes::oidc::revoke::revoke` does all of that around
//! the call to [`revoke_refresh_token`].
//!
//! ## Why a pure service
//!
//! The four-way classification + the cid-binding gate are
//! easy to get wrong (e.g., a confidential client probing
//! whether a token belongs to another client by the
//! response shape). Putting the logic in core with full
//! unit-test coverage lets us pin the policy explicitly.

use crate::error::CoreResult;
use crate::ports::repo::ClientRepository;
use crate::ports::store::RefreshTokenFamilyStore;
use crate::service::client_auth::{
    verify_client_credentials_optional, ClientAuthOutcome,
};

/// Outcome of a revocation attempt. The four variants
/// distinguish reasons for the worker's audit + log
/// channels; per RFC 7009 §2.2 the wire response is
/// always 200 with empty body for all of them
/// (well-formed requests).
#[derive(Debug, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// Token decoded, client authentication policy
    /// satisfied, family DO revoked. The success case.
    Revoked {
        family_id:   String,
        client_id:   String,
        auth_mode:   RevokeAuthMode,
    },

    /// Token couldn't be decoded as a refresh token.
    /// Could be: (a) malformed/garbage input, (b) a
    /// JWT access token (cesauth doesn't support
    /// access-token revocation; access tokens are
    /// short-lived JWTs without server-side state).
    /// Wire response is 200 empty either way per RFC
    /// 7009 §2.2.
    NotRevocable,

    /// Token decoded, but its family didn't exist in
    /// the store (already deleted, or never existed).
    /// Idempotent no-op; same wire response as Revoked.
    UnknownFamily,

    /// Token decoded successfully, but client
    /// authentication policy was not satisfied. Two
    /// sub-cases (collapsed for the audit log because
    /// they have the same wire response — silent 200):
    ///   - Confidential client; credentials
    ///     missing / wrong.
    ///   - Authenticated client's id doesn't match
    ///     the token's `cid`.
    Unauthorized {
        /// What kind of authentication-policy failure
        /// happened. Useful for log/audit attribution
        /// but the wire response is identical.
        reason: UnauthorizedReason,
    },
}

/// How the request authenticated. Surfaced in audit so
/// operators can spot patterns (sudden spike in
/// `Unauthenticated` revokes might be a token-stealing
/// attacker probing).
#[derive(Debug, PartialEq, Eq)]
pub enum RevokeAuthMode {
    /// The token's owning client is registered as
    /// public; revocation succeeded by token-possession
    /// alone.
    PublicClient,
    /// Confidential client; credentials presented and
    /// matched the stored hash; client_id matches the
    /// token's cid.
    ConfidentialClient,
}

/// Reason a revocation attempt was denied at the
/// authentication-policy layer.
#[derive(Debug, PartialEq, Eq)]
pub enum UnauthorizedReason {
    /// Confidential client; either no credentials
    /// presented or wrong secret. (Conflated for the
    /// usual privacy reasons.)
    ConfidentialAuthFailed,
    /// Token's `cid` claim refers to a confidential
    /// client, but the authenticated client_id is
    /// different. RFC 7009 §2.1 explicitly requires
    /// "the token was issued to the client making the
    /// revocation request" — a mismatch fails this gate.
    /// Silent 200 to avoid revealing cross-client
    /// token ownership.
    ClientIdCidMismatch,
}

/// Inputs to [`revoke_refresh_token`].
#[derive(Debug)]
pub struct RevokeInput<'a> {
    /// The opaque refresh token from the request body.
    pub token: &'a str,
    /// Hint from `token_type_hint` (RFC 7009 §2.1). We
    /// accept the parameter but the current
    /// implementation only handles refresh tokens; if a
    /// hint says `access_token` we still try refresh
    /// decoding and return `NotRevocable` if it fails.
    pub hint:  Option<TokenTypeHint>,
    /// `client_id` form field (or extracted from
    /// Authorization: Basic). Required by RFC 7009
    /// §2.3 for confidential clients; optional
    /// otherwise.
    pub client_id: Option<&'a str>,
    /// Plaintext `client_secret` from credentials, if
    /// any. The worker's
    /// `client_auth::extract` populates this from
    /// either Authorization: Basic or form-body
    /// `client_secret`.
    pub client_secret: Option<&'a str>,
    /// Current unix time. Used as the `revoked_at`
    /// timestamp in the family DO mutation.
    pub now_unix: i64,
}

/// RFC 7009 §2.1 `token_type_hint`. The worker parses
/// the form parameter into this enum before calling.
#[derive(Debug, PartialEq, Eq)]
pub enum TokenTypeHint {
    AccessToken,
    RefreshToken,
}

impl TokenTypeHint {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "access_token"  => Some(TokenTypeHint::AccessToken),
            "refresh_token" => Some(TokenTypeHint::RefreshToken),
            _               => None,
        }
    }
}

/// Top-level revocation. Decides authentication mode,
/// validates the cid binding when authenticated,
/// performs the family DO revoke when authorized, and
/// returns a [`RevokeOutcome`] for the caller to attach
/// to its audit event.
///
/// The wire response shape is the same for every
/// outcome (`200 OK` with empty body per RFC 7009
/// §2.2); the four variants are for audit/log
/// attribution only.
pub async fn revoke_refresh_token<FS, CR>(
    families: &FS,
    clients:  &CR,
    input:    &RevokeInput<'_>,
) -> CoreResult<RevokeOutcome>
where
    FS: RefreshTokenFamilyStore,
    CR: ClientRepository,
{
    // Step 1: decode the token.
    let Some((family_id, _jti)) = decode_refresh_best_effort(input.token) else {
        return Ok(RevokeOutcome::NotRevocable);
    };

    // Step 2: peek the family to recover the cid (the
    // client_id the token was issued to).
    let Some(family_state) = families.peek(&family_id).await
        .map_err(|_| crate::error::CoreError::Internal)?
    else {
        return Ok(RevokeOutcome::UnknownFamily);
    };
    let token_cid = family_state.client_id.clone();

    // Step 3: authentication mode for the client
    // making the request. Per RFC 7009 §2:
    // "The authorization server first validates the
    // client credentials (in case of a confidential
    // or credentialed client) and then verifies
    // whether the token was issued to the client
    // making the revocation request."
    //
    // We follow that ordering: authenticate against
    // the request's `client_id` (or the token's cid
    // if the request didn't supply one — public-
    // client paths), then check the cid binding.
    //
    // Picking the client_id to authenticate AGAINST:
    //   - If the request supplied client_id (form
    //     field or Basic header), use that. We're
    //     validating the requestor's own claim.
    //   - Otherwise fall back to the token's cid —
    //     this is the "public client revoke by
    //     token possession alone" path.
    let auth_client_id = input.client_id.unwrap_or(token_cid.as_str());
    let outcome = verify_client_credentials_optional(
        clients,
        auth_client_id,
        input.client_secret,
    ).await?;

    // Step 4: enforce authentication policy + cid
    // binding.
    let auth_mode = match outcome {
        ClientAuthOutcome::PublicOrUnknown => {
            // The auth target (request's client_id or
            // token's cid fallback) is registered as
            // public OR doesn't exist. Two sub-cases:
            //
            //   (a) The request didn't supply client_id
            //       and the token's cid is public.
            //       Token possession is sufficient;
            //       proceed.
            //   (b) The request supplied client_id and
            //       it's public (or unknown). We still
            //       need to check the cid binding —
            //       a public client trying to revoke
            //       a confidential client's token must
            //       not succeed even if the public
            //       client's id is what they
            //       presented. The cid binding is
            //       enforced below.
            //
            // For case (a): if input.client_id is None,
            // by construction the auth target IS the
            // token's cid, so the binding holds
            // trivially.
            //
            // For case (b): the cid binding gate
            // catches mismatches.
            if let Some(req_cid) = input.client_id {
                if req_cid != token_cid {
                    return Ok(RevokeOutcome::Unauthorized {
                        reason: UnauthorizedReason::ClientIdCidMismatch,
                    });
                }
            }
            RevokeAuthMode::PublicClient
        }
        ClientAuthOutcome::AuthenticationFailed => {
            return Ok(RevokeOutcome::Unauthorized {
                reason: UnauthorizedReason::ConfidentialAuthFailed,
            });
        }
        ClientAuthOutcome::Authenticated => {
            // Confidential client authenticated
            // against the request's client_id. Now
            // check the cid binding: the request's
            // client_id MUST match the token's cid.
            // RFC 7009 §2: "the token was issued to
            // the client making the revocation
            // request".
            //
            // input.client_id is guaranteed Some here
            // (Authenticated requires it; we
            // authenticated against `auth_client_id`,
            // and `auth_client_id` came from
            // input.client_id or fell back to
            // token_cid — but the fallback path is
            // public, not authenticated, so by the
            // time we're here, input.client_id is
            // Some(_)).
            let req_client_id = input.client_id
                .expect("Authenticated outcome implies client_id was supplied");
            if req_client_id != token_cid {
                return Ok(RevokeOutcome::Unauthorized {
                    reason: UnauthorizedReason::ClientIdCidMismatch,
                });
            }
            RevokeAuthMode::ConfidentialClient
        }
    };

    // Step 5: revoke. Best-effort; a store error
    // surfaces as Internal.
    families.revoke(&family_id, input.now_unix).await
        .map_err(|_| crate::error::CoreError::Internal)?;

    Ok(RevokeOutcome::Revoked {
        family_id,
        client_id: token_cid,
        auth_mode,
    })
}

/// Best-effort decoder for the refresh-token format.
/// **NOT a verifier** — anyone can construct a token
/// that decodes successfully; the family DO + the
/// upstream `families.peek` call are the gate. The
/// decoder only exists to recover the `family_id` so
/// we know which DO to consult.
///
/// Format (matching v0.27.0): `b64url(<family_id>.<jti>.<other>)`.
fn decode_refresh_best_effort(token: &str) -> Option<(String, String)> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let bytes = URL_SAFE_NO_PAD.decode(token.as_bytes()).ok()?;
    let s     = std::str::from_utf8(&bytes).ok()?;
    let mut parts = s.split('.');
    let family_id = parts.next()?.to_owned();
    let jti       = parts.next()?.to_owned();
    Some((family_id, jti))
}

#[cfg(test)]
mod tests;
