//! Types for RFC 7662 OAuth 2.0 Token Introspection (v0.38.0, ADR-014).
//!
//! The introspection endpoint lets a registered (typically resource-
//! server) client ask the auth server "is this token valid right
//! now and what are its claims?". The endpoint is necessary because:
//!
//! - Refresh tokens are opaque to bearers — only the issuer can
//!   say whether a presented refresh token is current vs retired
//!   vs from a revoked family.
//! - Access tokens, while signed JWTs that the resource server
//!   could verify locally, may have been revoked since issuance
//!   (refresh-family revocation cascades to the access tokens
//!   issued from that family — but only the issuer knows that).
//!
//! ## Privacy invariant (RFC 7662 §2.2)
//!
//! When the endpoint returns `active = false`, the response MUST
//! NOT include any other claims. This prevents an attacker who has
//! obtained an old or invalid token from learning anything about
//! it. cesauth's [`IntrospectionResponse`] enforces this via two
//! constructors — `inactive()` returns the bare-`active` shape;
//! the active path is the only one that can populate other
//! fields.

use serde::{Deserialize, Serialize};

/// Hint about what kind of token is being introspected. RFC 7662
/// §2.1 lets the client send this so the AS can avoid trying both
/// token types; the AS is permitted to ignore the hint, and cesauth
/// does try the fallback if the hinted check fails (matching the
/// spec's "try the hint first; if it doesn't match, try the other
/// type" guidance).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenTypeHint {
    AccessToken,
    RefreshToken,
}

/// **v0.41.0** — One signing key in the active set, in
/// the form the introspection service consumes (kid +
/// raw 32-byte Ed25519 public key). The worker decodes
/// the base64-encoded `public_key_b64` from
/// `PublicSigningKey` once and assembles a slice of these
/// for the introspection call.
///
/// Held by-borrow as a `&[IntrospectionKey<'_>]` so callers
/// don't have to allocate; the borrow's lifetime ties to
/// the worker's signing-key buffer that lives only for
/// the request duration.
#[derive(Debug)]
pub struct IntrospectionKey<'a> {
    pub kid:            &'a str,
    pub public_key_raw: &'a [u8],
}

impl TokenTypeHint {
    /// Parse from the `token_type_hint` form parameter. RFC 7662
    /// §2.1 lists `access_token` and `refresh_token` as the
    /// registered values. Unrecognized hints are ignored per
    /// spec — return `None` so the caller can fall back to
    /// "try both".
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "access_token"  => Some(Self::AccessToken),
            "refresh_token" => Some(Self::RefreshToken),
            _               => None,
        }
    }
}

/// Input to `introspect_token`. The `token` is the opaque value
/// the requester wants checked; `hint` is the optional
/// `token_type_hint` from the form. The caller (the worker
/// `/introspect` handler) is responsible for client authentication
/// before calling `introspect_token` — by the time we're here, the
/// requesting client is already trusted.
#[derive(Debug)]
pub struct IntrospectInput<'a> {
    pub token:    &'a str,
    pub hint:     Option<TokenTypeHint>,
    pub now_unix: i64,
}

/// RFC 7662 §2.2 introspection response.
///
/// Fields beyond `active` are populated **only** when `active =
/// true`. The privacy invariant in the spec is critical: an
/// inactive response must surface nothing about the token. The
/// type's `inactive()` constructor enforces this — there's no way
/// to construct an `active = false` response with non-default
/// claims through this API.
///
/// ## Field semantics (RFC 7662 §2.2)
///
/// - `active`: REQUIRED. Whether the token is currently active.
/// - `scope`: OPTIONAL. Space-delimited, like the OAuth scope
///   parameter.
/// - `client_id`: OPTIONAL. The client that the token was issued
///   to.
/// - `token_type`: OPTIONAL. e.g., `"Bearer"`. cesauth includes
///   this for access tokens.
/// - `exp`, `iat`: OPTIONAL Unix-seconds timestamps. cesauth
///   populates them from the JWT claims (access) or family state
///   (refresh).
/// - `sub`: OPTIONAL. The subject of the token (user_id for
///   user-issued tokens).
/// - `jti`: OPTIONAL. The token's unique identifier.
///
/// cesauth omits `username`, `nbf`, `aud`, `iss` from v0.38.0 —
/// they're optional and the resource servers we anticipate
/// supporting don't need them (`sub` covers user identity;
/// `iss` is the cesauth deployment, knowable out-of-band).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntrospectionResponse {
    pub active: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl IntrospectionResponse {
    /// The bare `{"active": false}` response. RFC 7662 §2.2 MUST
    /// for inactive tokens — no other fields permitted, lest an
    /// attacker learn something about a token they shouldn't have
    /// access to (e.g., the user_id of a leaked-then-expired
    /// access token).
    pub fn inactive() -> Self {
        Self {
            active: false,
            scope: None, client_id: None, token_type: None,
            exp: None, iat: None, sub: None, jti: None,
        }
    }

    /// Active access-token response. The resource server can use
    /// `scope` for authorization decisions, `sub` for user
    /// identification, and `exp` / `iat` for cache TTL hints.
    pub fn active_access(
        scope:     String,
        client_id: String,
        sub:       String,
        jti:       String,
        iat:       i64,
        exp:       i64,
    ) -> Self {
        Self {
            active: true,
            scope: Some(scope),
            client_id: Some(client_id),
            token_type: Some("Bearer".to_owned()),
            exp: Some(exp),
            iat: Some(iat),
            sub: Some(sub),
            jti: Some(jti),
        }
    }

    /// Active refresh-token response. Refresh tokens don't carry
    /// per-token `iat` separately from the family's
    /// `last_rotated_at`, and they don't carry an explicit `exp`
    /// (lifetime is the family's `created_at + refresh_ttl`). We
    /// return what we have.
    ///
    /// `token_type` is omitted: refresh tokens don't have an
    /// HTTP-Authorization `Bearer` semantic — they're scoped to
    /// the `/token` endpoint.
    pub fn active_refresh(
        scope:     String,
        client_id: String,
        sub:       String,
        jti:       String,
        iat:       i64,
        exp:       i64,
    ) -> Self {
        Self {
            active: true,
            scope: Some(scope),
            client_id: Some(client_id),
            token_type: None,
            exp: Some(exp),
            iat: Some(iat),
            sub: Some(sub),
            jti: Some(jti),
        }
    }
}
