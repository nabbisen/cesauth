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

    /// **v0.46.0** — cesauth-specific extensions namespaced
    /// under `x_cesauth` per RFC 7662 §2.2 ("Specific
    /// implementations MAY extend this structure with their
    /// own service-specific response names as top-level
    /// members"). Present only when the introspect path has
    /// extension data to surface — when `None`, serializes
    /// out entirely (no key in the JSON body). Resource
    /// servers consuming only the RFC 7662 fields are
    /// unaffected.
    ///
    /// Currently surfaced for refresh-token introspection
    /// to expose: family-state classification (current /
    /// retired / revoked / unknown), revocation reason
    /// (admin / reuse-detected / user-revoke), and the
    /// current_jti (lets a resource server detect "the
    /// token I have is stale" without trying to refresh).
    /// Access-token introspection currently returns no
    /// x_cesauth field; the access-token claim shape is
    /// already self-descriptive.
    #[serde(skip_serializing_if = "Option::is_none", rename = "x_cesauth")]
    pub x_cesauth: Option<CesauthIntrospectionExt>,
}

/// **v0.46.0** — cesauth-specific extension fields
/// surfaced under the `x_cesauth` key in introspection
/// responses. RFC 7662 §2.2 explicitly permits this.
///
/// All fields are optional; the struct serializes only
/// the fields present (`#[serde(skip_serializing_if =
/// "Option::is_none")]`).
///
/// **Privacy note**: introspection is gated on
/// confidential-client authentication (RFC 7662 §2.1 +
/// v0.38.0's `verify_client_credentials`). Public clients
/// can't hit the endpoint. So these fields are only
/// returned to authenticated resource servers /
/// confidential clients. Even so, we deliberately don't
/// expose the family_id (treated as opaque token-internal
/// state) or full reuse-jti payloads (could be abused as
/// an oracle).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CesauthIntrospectionExt {
    /// Classification of why this token is or isn't
    /// active. See [`FamilyState`] for variants.
    ///
    /// Distinct from the spec's `active` field: a token
    /// can be `active=false` for many reasons, and an RS
    /// dashboard wants to break those down. A token with
    /// `active=true` always has `family_state="current"`;
    /// a token with `active=false` has one of the other
    /// three (`retired`, `revoked`, or `unknown`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_state: Option<FamilyClassification>,

    /// When the family was revoked (Unix seconds), if the
    /// family_state is `revoked`. Set together with
    /// [`Self::revoke_reason`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,

    /// Why the family was revoked. See [`RevokeReason`]
    /// for variants. Distinguishes admin-initiated vs
    /// reuse-detected revocation — operationally
    /// significant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoke_reason: Option<RevokeReason>,

    /// On a `family_state="retired"` response, the
    /// `current_jti` of the family — i.e., the jti that
    /// IS currently valid. Lets a resource server
    /// holding a stale token recognize "my token is
    /// behind by one rotation; the user has a fresh
    /// token now". Not surfaced for revoked families
    /// (no current jti exists) or unknown families
    /// (no family).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_jti: Option<String>,
}

/// Classification of refresh-token introspection states.
/// Maps to the family-state machine.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FamilyClassification {
    /// The presented jti matches `family.current_jti`
    /// AND the family isn't revoked. Active path.
    Current,
    /// The presented jti is in `family.retired_jtis` —
    /// it was once valid, but has since been rotated
    /// past. The user has a fresher token; this one is
    /// inactive but not "lost". RS dashboards can
    /// distinguish "stale due to rotation" from "stale
    /// due to revocation" via this state.
    Retired,
    /// The family was revoked (`family.revoked_at`
    /// is Some). Pair with [`CesauthIntrospectionExt::revoked_at`]
    /// + [`CesauthIntrospectionExt::revoke_reason`].
    Revoked,
    /// The family doesn't exist in the store. Could be:
    /// already-swept, never-issued, malformed-token-
    /// after-decode-but-no-record. Conflated for the
    /// usual privacy reasons.
    Unknown,
}

/// Why a family was revoked. Surfaced under
/// `x_cesauth.revoke_reason` to let resource-server
/// dashboards distinguish operationally-different
/// revocation paths.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RevokeReason {
    /// Reuse-detected revocation: a retired jti was
    /// presented to `/token`, ADR-011 §Q1 defense
    /// kicked in, family was revoked. Security teams
    /// alert on this.
    ReuseDetected,
    /// Explicit revocation via `/revoke` endpoint or
    /// admin-initiated session revocation. v0.46.0
    /// can't distinguish those two further (the
    /// family-state machine doesn't track WHO
    /// initiated the revoke); future work could split
    /// this into `User`/`Admin` if demand surfaces.
    Explicit,
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
            x_cesauth: None,
        }
    }

    /// **v0.46.0** — `inactive` response with a cesauth
    /// extension envelope. Used by the refresh-token
    /// introspection path to surface family-state
    /// classification (retired / revoked / unknown) +
    /// revocation metadata, when the introspecter has
    /// authenticated as a confidential client and may
    /// benefit from the operational context.
    ///
    /// The spec-required `active=false` is preserved
    /// (RFC 7662 §2.2). The extension fields are namespaced
    /// under `x_cesauth` and serialize out entirely if
    /// every field inside is `None` (rare but possible —
    /// the test pin checks).
    pub fn inactive_with_ext(ext: CesauthIntrospectionExt) -> Self {
        Self {
            active: false,
            scope: None, client_id: None, token_type: None,
            exp: None, iat: None, sub: None, jti: None,
            x_cesauth: Some(ext),
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
            x_cesauth: None,
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
            x_cesauth: None,
        }
    }

    /// **v0.46.0** — Active refresh-token response with the
    /// cesauth extension envelope (always
    /// `family_state: Current` for an active response).
    /// The current_jti is omitted because the response
    /// already carries `jti` at the top level for the
    /// active path.
    pub fn active_refresh_with_ext(
        scope:     String,
        client_id: String,
        sub:       String,
        jti:       String,
        iat:       i64,
        exp:       i64,
    ) -> Self {
        let mut resp = Self::active_refresh(scope, client_id, sub, jti, iat, exp);
        resp.x_cesauth = Some(CesauthIntrospectionExt {
            family_state:  Some(FamilyClassification::Current),
            revoked_at:    None,
            revoke_reason: None,
            current_jti:   None,
        });
        resp
    }
}
