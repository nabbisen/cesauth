//! `/authorize` - the Authorization Code + PKCE entry point.
//!
//! What this module does:
//!
//! * Parses the query string into a typed `AuthorizationRequest`.
//! * Runs the cheap, stateless validations (response_type, redirect_uri
//!   allow-list, PKCE presence).
//!
//! What it does NOT do:
//!
//! * Authenticate the user. That is the WebAuthn / Magic Link flow.
//! * Issue a code. That happens in the `AuthChallenge` Durable Object,
//!   which alone can guarantee single-consumption.

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::oidc::pkce::ChallengeMethod;
use crate::types::{OidcClient, Scopes};

/// Parsed authorization request.
///
/// Missing `state` or `nonce` is legal per spec but discouraged. We keep
/// them as `Option` and let the worker layer decide whether to issue a
/// warning-level audit event if absent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub response_type:         String,
    pub client_id:             String,
    pub redirect_uri:          String,
    pub scope:                 Option<String>,
    pub state:                 Option<String>,
    pub nonce:                 Option<String>,
    pub code_challenge:        String,
    pub code_challenge_method: String,
    /// OIDC `prompt` parameter (§3.1.2.1). Space-separated list. We
    /// understand `none` and `login`; any other value is rejected in
    /// `validate()`. `consent` and `select_account` would require a
    /// consent UI + account picker that cesauth does not ship.
    pub prompt:                Option<String>,
    /// OIDC `max_age` parameter. Maximum acceptable age of the end-user
    /// authentication, in seconds. If the current session is older, the
    /// worker layer must re-authenticate the user.
    pub max_age:               Option<i64>,
}

/// Which `prompt` value, if any, was asserted by the AR. Parsed once in
/// `AuthorizationRequest::validate` so handlers do not re-parse strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prompt {
    /// No `prompt` parameter, or `prompt=` was empty.
    Unspecified,
    /// `prompt=none`: do not interact with the user. If no active,
    /// non-revoked, fresh-enough session exists, return `login_required`.
    None,
    /// `prompt=login`: force re-authentication even if a valid session
    /// cookie is present.
    Login,
}

/// The data we persist in the `AuthChallenge` DO after a successful
/// authorize call, so the `/token` endpoint can redeem it later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredChallenge {
    pub client_id:             String,
    pub redirect_uri:          String,
    pub user_id:               String,
    pub scopes:                Scopes,
    pub nonce:                 Option<String>,
    pub code_challenge:        String,
    pub code_challenge_method: ChallengeMethod,
    pub issued_at:             i64,
    pub expires_at:            i64,
}

/// Cheap, stateless outcome of `AuthorizationRequest::validate`. Exposes
/// the parsed PKCE method and the parsed `prompt` value so handlers do
/// not re-walk the strings.
#[derive(Debug, Clone)]
pub struct AuthorizationPolicy {
    pub pkce_method: ChallengeMethod,
    pub prompt:      Prompt,
    pub max_age:     Option<i64>,
}

impl AuthorizationRequest {
    /// Cheap, stateless validations. Anything that requires a DB lookup
    /// (is this client real? does this user have consent?) is the
    /// caller's responsibility.
    ///
    /// The `client` argument is the already-loaded client record - we do
    /// not load it here because that would couple `core` to storage.
    pub fn validate(&self, client: &OidcClient) -> CoreResult<AuthorizationPolicy> {
        if self.response_type != "code" {
            return Err(CoreError::InvalidRequest("response_type must be 'code'"));
        }

        if self.client_id != client.id {
            // The client is loaded by the caller using self.client_id,
            // so a mismatch here is a caller bug. We still check as a
            // defense in depth.
            return Err(CoreError::InvalidClient);
        }

        // Exact match on redirect_uri per OAuth 2.1 recommendations -
        // no prefix matches, no query-string wildcards.
        if !client.redirect_uris.iter().any(|u| u == &self.redirect_uri) {
            return Err(CoreError::InvalidRequest("redirect_uri is not registered"));
        }

        if client.require_pkce && self.code_challenge.is_empty() {
            return Err(CoreError::InvalidRequest("code_challenge is required"));
        }

        let pkce_method = ChallengeMethod::parse(&self.code_challenge_method)?;
        let prompt      = self.parse_prompt()?;

        if let Some(m) = self.max_age {
            if m < 0 {
                return Err(CoreError::InvalidRequest("max_age must be >= 0"));
            }
        }

        Ok(AuthorizationPolicy { pkce_method, prompt, max_age: self.max_age })
    }

    /// Parse the `prompt` parameter. Only `none` and `login` are
    /// accepted; `consent` / `select_account` are rejected because
    /// cesauth does not implement a consent UI or account picker.
    /// Specifying both `none` and `login` is a contradiction and per
    /// OIDC §3.1.2.1 is rejected with `invalid_request`.
    fn parse_prompt(&self) -> CoreResult<Prompt> {
        let raw = match self.prompt.as_deref() {
            None => return Ok(Prompt::Unspecified),
            Some(s) if s.trim().is_empty() => return Ok(Prompt::Unspecified),
            Some(s) => s,
        };

        let mut saw_none  = false;
        let mut saw_login = false;
        for tok in raw.split_ascii_whitespace() {
            match tok {
                "none"  => saw_none  = true,
                "login" => saw_login = true,
                // `consent` and `select_account` are defined by the spec
                // but unsupported here; rejecting is preferable to
                // silently ignoring because a client that asks for
                // consent and doesn't get it would proceed incorrectly.
                "consent" | "select_account" =>
                    return Err(CoreError::InvalidRequest("prompt value not supported")),
                _ => return Err(CoreError::InvalidRequest("prompt value unknown")),
            }
        }

        match (saw_none, saw_login) {
            (true, true)  => Err(CoreError::InvalidRequest("prompt=none conflicts with prompt=login")),
            (true, false) => Ok(Prompt::None),
            (false, true) => Ok(Prompt::Login),
            (false, false) => Ok(Prompt::Unspecified),
        }
    }
}

/// Decide whether an existing session satisfies the AR's freshness
/// requirements. Pure function: takes the session's `auth_time` and the
/// AR's `max_age`, compared against `now_unix`. Returns `true` if the
/// session is fresh enough; `false` if the handler must force re-auth.
///
/// A missing `max_age` means no freshness constraint, so any non-
/// revoked session passes. A zero `max_age` means "the user must have
/// authenticated just now" - essentially `prompt=login` expressed via
/// timing.
pub fn session_satisfies_max_age(
    session_auth_time: i64,
    max_age:           Option<i64>,
    now_unix:          i64,
) -> bool {
    match max_age {
        None    => true,
        Some(m) => now_unix.saturating_sub(session_auth_time) <= m,
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod redirect_uri_proptests;
