//! **RFC 141** — OIDC client registration: validation, secret minting,
//! and the operations the `/admin/console/clients` routes wire up.
//!
//! Three things this module is careful about:
//!
//! * **§4.3's validation runs once, in [`validate_registration`],
//!   called from both [`register_client`] and [`update_client`].**
//!   The `client_type` <=> `token_auth_method` coupling is checked
//!   here — not only in the route — so a future caller of this module
//!   cannot bypass it (RFC 141 §6.3).
//! * **The minted secret is a [`RawSecret`]** (RFC 116): no `Clone`,
//!   no `Serialize`, zeroized on drop. It crosses this module's
//!   boundary exactly once, in [`Registered::secret`] /
//!   [`rotate_secret`]'s return value, and the route layer's one
//!   `.expose()` call puts it in exactly one response body (RFC 141
//!   §4.2 / §6.1).
//! * **`client_type` and `token_auth_method` are immutable after
//!   creation.** See the port trait's doc on
//!   [`ClientRepository::update`](crate::ports::repo::ClientRepository::update)
//!   for why: allowing either to change on update would require
//!   re-running §4.3's coupling check (and the secret-presence
//!   consequences — minting one, or clearing one) at a second site.
//!   To change either, delete and re-register.

use crate::oidc::discovery::KNOWN_SCOPES;
use crate::ports::repo::ClientRepository;
use crate::ports::PortError;
use crate::types::secret::RawSecret;
use crate::types::{ClientType, OidcClient, TokenAuthMethod};

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Why a registration (create or update) request was rejected.
///
/// Deliberately **not** `CoreError`: this is a pure JSON admin API (RFC
/// 141 §4.1), not an OAuth wire response, and `CoreError::InvalidRequest`
/// takes only a `&'static str` — it cannot name the offending field's
/// *value*, which every variant here does. The route layer maps this
/// directly to its JSON error body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientValidationError {
    NameEmpty,
    NoRedirectUris,
    RedirectUriNotAbsolute(String),
    NoAllowedScopes,
    UnknownScope(String),
    /// RFC 141 §4.3 — PKCE is mandatory and S256-only; the field exists
    /// so a client can see that cesauth requires it, not so it can opt
    /// out.
    RequirePkceFalse,
    /// RFC 141 §4.3 — the only representable pairs are `public` + `none`
    /// (and no secret) or `confidential` + (`client_secret_basic` or
    /// `client_secret_post`) (and a secret). Everything else is the
    /// combination RFC 137 §12.2 rejects at `/token`, made unrepresentable
    /// here instead.
    TypeMethodMismatch { client_type: ClientType, token_auth_method: TokenAuthMethod },
}

impl std::fmt::Display for ClientValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NameEmpty => write!(f, "name must not be empty"),
            Self::NoRedirectUris => write!(f, "redirect_uris must have at least one entry"),
            Self::RedirectUriNotAbsolute(u) => write!(
                f, "redirect_uri '{u}' is not an absolute URI (scheme://host…, and no '#' fragment)",
            ),
            Self::NoAllowedScopes => write!(f, "allowed_scopes must have at least one entry"),
            Self::UnknownScope(s) => write!(
                f, "allowed_scopes: '{s}' is not a scope cesauth issues (known: {})",
                KNOWN_SCOPES.join(", "),
            ),
            Self::RequirePkceFalse => write!(
                f, "require_pkce cannot be set to false: PKCE is mandatory and S256-only",
            ),
            Self::TypeMethodMismatch { client_type, token_auth_method } => write!(
                f,
                "client_type={client_type:?} is incompatible with token_auth_method={token_auth_method:?}: \
                 public requires none (and no secret); confidential requires client_secret_basic \
                 or client_secret_post (and a secret)",
            ),
        }
    }
}

/// RFC 141 §4.3, run on every create and every (bounded) update. Returns
/// the first failure, not an exhaustive list — this is an admin API with
/// one operator at a time.
pub fn validate_registration(
    name:              &str,
    client_type:       ClientType,
    redirect_uris:      &[String],
    allowed_scopes:     &[String],
    token_auth_method: TokenAuthMethod,
    require_pkce:      bool,
) -> Result<(), ClientValidationError> {
    if name.trim().is_empty() {
        return Err(ClientValidationError::NameEmpty);
    }
    if redirect_uris.is_empty() {
        return Err(ClientValidationError::NoRedirectUris);
    }
    for uri in redirect_uris {
        if !is_absolute_uri_without_fragment(uri) {
            return Err(ClientValidationError::RedirectUriNotAbsolute(uri.clone()));
        }
    }
    if allowed_scopes.is_empty() {
        return Err(ClientValidationError::NoAllowedScopes);
    }
    for scope in allowed_scopes {
        if !KNOWN_SCOPES.contains(&scope.as_str()) {
            return Err(ClientValidationError::UnknownScope(scope.clone()));
        }
    }
    if !require_pkce {
        return Err(ClientValidationError::RequirePkceFalse);
    }
    let type_method_ok = matches!(
        (client_type, token_auth_method),
        (ClientType::Public,       TokenAuthMethod::None)
        | (ClientType::Confidential, TokenAuthMethod::ClientSecretBasic)
        | (ClientType::Confidential, TokenAuthMethod::ClientSecretPost)
    );
    if !type_method_ok {
        return Err(ClientValidationError::TypeMethodMismatch { client_type, token_auth_method });
    }
    Ok(())
}

/// RFC 141 §4.3 — the same notion of "valid" `/authorize` will later use
/// to match against (`oidc::authorization::AuthorizationRequest::validate`,
/// an exact-string membership check, no normalization). Registration
/// cannot run that check (there is no incoming request to match yet); what
/// it *can* enforce is that every registered URI is at least a
/// syntactically well-formed absolute URI, so the matcher downstream is
/// comparing two URIs, never a URI against a string that could never have
/// matched anything.
///
/// Absolute: `scheme://`, where `scheme` starts with an ASCII letter and
/// contains only `[A-Za-z0-9+.-]`, followed by a non-empty remainder. No
/// `#` fragment (RFC 6749 §3.1.2).
fn is_absolute_uri_without_fragment(uri: &str) -> bool {
    if uri.contains('#') {
        return false;
    }
    let Some(scheme_end) = uri.find("://") else { return false; };
    let (scheme, rest) = (&uri[..scheme_end], &uri[scheme_end + 3..]);
    let mut chars = scheme.chars();
    let Some(first) = chars.next() else { return false; };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
        return false;
    }
    !rest.is_empty()
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Same shape as `AuthFailure` / `TenantAdminFailure` elsewhere in `core`:
/// a storage error (`From<PortError>`) and a validation error
/// (`From<ClientValidationError>`) collapse into one type per operation,
/// instead of a route layer matching on two.
#[derive(Debug)]
pub enum ClientOpError {
    Validation(ClientValidationError),
    /// Operation-specific precondition failures that are not field
    /// validation: rotating a secret for a client with no secret.
    NotConfidential,
    NotFound,
    Conflict,
    /// Storage error, or the platform CSPRNG failed while minting a
    /// secret (RFC 011's `CsrfRngFailure` is the precedent for treating a
    /// `getrandom` failure as this class of error, not a validation one).
    Internal,
}

impl From<PortError> for ClientOpError {
    fn from(e: PortError) -> Self {
        match e {
            PortError::NotFound => Self::NotFound,
            PortError::Conflict => Self::Conflict,
            PortError::PreconditionFailed(_) | PortError::Unavailable | PortError::Serialization => Self::Internal,
        }
    }
}

impl From<ClientValidationError> for ClientOpError {
    fn from(e: ClientValidationError) -> Self { Self::Validation(e) }
}

/// 256 bits of CSPRNG entropy, base64url — the same shape magic-link
/// OTPs and CSRF tokens use elsewhere in this codebase. Returned as a
/// [`RawSecret`] so it cannot be cloned, serialized, or accidentally
/// logged; the caller's one legitimate read is `.expose()`.
fn mint_client_secret() -> Result<RawSecret, ClientOpError> {
    use base64::Engine;
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).map_err(|_| ClientOpError::Internal)?;
    Ok(RawSecret::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)))
}

/// What the caller supplies to register a new client. `id` is shape-
/// validated at the route boundary (`ClientId::parse`, RFC 116); this
/// module does not mint one — an operator may want a specific,
/// memorable `client_id`.
#[derive(Debug, Clone)]
pub struct NewClient {
    pub id:                String,
    pub name:               String,
    pub client_type:        ClientType,
    pub redirect_uris:      Vec<String>,
    pub allowed_scopes:     Vec<String>,
    pub token_auth_method:  TokenAuthMethod,
    pub audience:           Option<String>,
}

/// A successful registration. `secret` is `Some` only for a confidential
/// client — RFC 141 §4.2: shown exactly once, by the route layer, and
/// never again. `Debug` is safe to derive: `RawSecret`'s own `Debug`
/// prints only `RawSecret(REDACTED)`.
#[derive(Debug)]
pub struct Registered {
    pub client: OidcClient,
    pub secret: Option<RawSecret>,
}

/// RFC 141 §4.1 create. Validates (§4.3), mints a secret for a
/// confidential client (§4.2), and stores the result.
pub async fn register_client<CR: ClientRepository>(
    clients: &CR,
    new:     NewClient,
) -> Result<Registered, ClientOpError> {
    validate_registration(
        &new.name, new.client_type, &new.redirect_uris, &new.allowed_scopes,
        new.token_auth_method, true,
    )?;

    let secret      = match new.client_type {
        ClientType::Public       => None,
        ClientType::Confidential => Some(mint_client_secret()?),
    };
    let secret_hash  = secret.as_ref().map(|s| s.sha256());

    let client = OidcClient {
        id:                new.id,
        name:              new.name,
        client_type:       new.client_type,
        redirect_uris:     new.redirect_uris,
        allowed_scopes:    new.allowed_scopes,
        token_auth_method: new.token_auth_method,
        require_pkce:      true,
        audience:          new.audience,
    };

    clients.create(&client, secret_hash.as_ref().map(|h| h.as_storage_str())).await?;
    Ok(Registered { client, secret })
}

/// RFC 141 §4.1 list.
pub async fn list_clients<CR: ClientRepository>(clients: &CR) -> Result<Vec<OidcClient>, ClientOpError> {
    Ok(clients.list().await?)
}

/// The mutable fields an update may change. `client_type` is not here —
/// see this module's doc and `ClientRepository::update`'s. `token_auth_method`
/// **is** (RFC 141 C1-141 item 3): pass the client's existing value to leave
/// it unchanged, or a different one of the two confidential methods to
/// switch transport.
#[derive(Debug, Clone)]
pub struct ClientUpdate {
    pub name:              String,
    pub redirect_uris:     Vec<String>,
    pub allowed_scopes:    Vec<String>,
    pub token_auth_method: TokenAuthMethod,
    pub audience:          Option<String>,
}

/// RFC 141 §4.1 update, extended by C1-141 item 3. Re-validates with the
/// client's **existing, immutable** `client_type` and the update's
/// (possibly changed) `token_auth_method` — the same §4.3 validator
/// `register_client` calls, run again at the same site, not a second one.
/// A row that passed §4.3 at creation cannot be edited into one that
/// wouldn't: switching a confidential client to `token_auth_method: None`
/// (which would only be valid for `Public`) is rejected here exactly as it
/// would be at creation, because `client_type` cannot change to match it.
pub async fn update_client<CR: ClientRepository>(
    clients:   &CR,
    client_id: &str,
    update:    ClientUpdate,
) -> Result<OidcClient, ClientOpError> {
    let mut existing = clients.find(client_id).await?.ok_or(ClientOpError::NotFound)?;
    validate_registration(
        &update.name, existing.client_type, &update.redirect_uris,
        &update.allowed_scopes, update.token_auth_method, true,
    )?;
    existing.name              = update.name;
    existing.redirect_uris     = update.redirect_uris;
    existing.allowed_scopes    = update.allowed_scopes;
    existing.token_auth_method = update.token_auth_method;
    existing.audience          = update.audience;
    clients.update(&existing).await?;
    Ok(existing)
}

/// RFC 141 §4.1/§4.2 rotate-secret. Confidential clients only — a public
/// client has no secret to rotate, and minting one for it would be a
/// secret `/token` never reads (its auth method is `none`).
pub async fn rotate_secret<CR: ClientRepository>(
    clients:   &CR,
    client_id: &str,
) -> Result<RawSecret, ClientOpError> {
    let client = clients.find(client_id).await?.ok_or(ClientOpError::NotFound)?;
    if !matches!(client.client_type, ClientType::Confidential) {
        return Err(ClientOpError::NotConfidential);
    }
    let secret = mint_client_secret()?;
    clients.set_secret_hash(client_id, Some(secret.sha256().as_storage_str())).await?;
    Ok(secret)
}

/// RFC 141 §4 / §9 q2 — hard delete. `grants` and `consent` cascade at
/// the storage layer; this function is a thin, named call site so
/// "delete a client" is one grep, not a repo method reached directly
/// from a route.
pub async fn delete_client<CR: ClientRepository>(
    clients:   &CR,
    client_id: &str,
) -> Result<(), ClientOpError> {
    clients.delete(client_id).await?;
    Ok(())
}

#[cfg(test)]
mod tests;
