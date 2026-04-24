//! `/token` - request and response shapes for the two grant types we
//! support: `authorization_code` and `refresh_token`.
//!
//! Only the wire format and local validation live here. The actual
//! redemption of codes / rotation of refresh tokens happens inside the
//! relevant Durable Object (see `cesauth-do`).

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};

/// Form body of a `/token` POST.
///
/// OAuth allows `grant_type` to take many values; we recognize only the
/// two we actually implement and reject everything else with
/// `unsupported_grant_type`.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenRequest {
    pub grant_type:    String,

    // authorization_code path
    pub code:          Option<String>,
    pub redirect_uri:  Option<String>,
    pub client_id:     Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,

    // refresh_token path
    pub refresh_token: Option<String>,
    pub scope:         Option<String>,
}

#[derive(Debug, Clone)]
pub enum TokenGrant<'a> {
    AuthorizationCode(AuthorizationCodeGrant<'a>),
    RefreshToken(RefreshTokenGrant<'a>),
}

#[derive(Debug, Clone)]
pub struct AuthorizationCodeGrant<'a> {
    pub code:          &'a str,
    pub redirect_uri:  &'a str,
    pub client_id:     &'a str,
    pub code_verifier: &'a str,
}

#[derive(Debug, Clone)]
pub struct RefreshTokenGrant<'a> {
    pub refresh_token: &'a str,
    pub client_id:     &'a str,
    pub scope:         Option<&'a str>,
}

impl TokenRequest {
    /// Dispatch on `grant_type` and pull the required fields.
    ///
    /// Borrowed output because the fields are used synchronously by the
    /// caller and there is no reason to clone strings we'll forget in a
    /// microsecond.
    pub fn classify(&self) -> CoreResult<TokenGrant<'_>> {
        match self.grant_type.as_str() {
            "authorization_code" => Ok(TokenGrant::AuthorizationCode(AuthorizationCodeGrant {
                code:          self.code.as_deref()
                    .ok_or(CoreError::InvalidRequest("code is required"))?,
                redirect_uri:  self.redirect_uri.as_deref()
                    .ok_or(CoreError::InvalidRequest("redirect_uri is required"))?,
                client_id:     self.client_id.as_deref()
                    .ok_or(CoreError::InvalidRequest("client_id is required"))?,
                code_verifier: self.code_verifier.as_deref()
                    .ok_or(CoreError::InvalidRequest("code_verifier is required"))?,
            })),

            "refresh_token" => Ok(TokenGrant::RefreshToken(RefreshTokenGrant {
                refresh_token: self.refresh_token.as_deref()
                    .ok_or(CoreError::InvalidRequest("refresh_token is required"))?,
                client_id:     self.client_id.as_deref()
                    .ok_or(CoreError::InvalidRequest("client_id is required"))?,
                scope:         self.scope.as_deref(),
            })),

            other => Err(CoreError::UnsupportedGrantType(other.to_owned())),
        }
    }
}

/// The successful response body. `id_token` is only present when the
/// original authorize request included the `openid` scope.
#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    pub access_token:  String,
    pub token_type:    &'static str,     // always "Bearer"
    pub expires_in:    i64,
    pub refresh_token: Option<String>,
    pub id_token:      Option<String>,
    pub scope:         String,
}

impl TokenResponse {
    pub fn bearer(access_token: String, expires_in: i64, scope: String) -> Self {
        Self {
            access_token,
            token_type: "Bearer",
            expires_in,
            refresh_token: None,
            id_token:      None,
            scope,
        }
    }
}

/// RFC 6749 §5.2 error codes.
///
/// Serialized with the exact snake_case token OAuth wants; the
/// `#[serde(rename_all)]` below enforces that so renaming a variant in
/// Rust source cannot silently change the wire format.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenError {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenErrorResponse {
    pub error:             TokenError,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

#[cfg(test)]
mod tests;
