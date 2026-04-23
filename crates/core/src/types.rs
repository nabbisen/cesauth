//! Cross-module value types.
//!
//! Things that are narrow enough to be "just a struct" but appear in more
//! than one module. Anything truly module-local should stay in that
//! module.

use serde::{Deserialize, Serialize};

/// A stable string identifier used throughout the schema. Currently a
/// UUIDv4 string, but the alias lets us swap representations later
/// without thrashing call sites.
pub type Id = String;

/// Unix epoch seconds. We use `i64` everywhere (not `u64`) because SQLite
/// D1 returns signed integers and negative-before-epoch is a legitimate
/// corner case for imported data.
pub type UnixSeconds = i64;

/// A user as stored in D1. `email` is optional to support username-less
/// passkey-first registration: a user can exist with a pure WebAuthn
/// credential and no email at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id:             Id,
    pub email:          Option<String>,
    pub email_verified: bool,
    pub display_name:   Option<String>,
    pub status:         UserStatus,
    pub created_at:     UnixSeconds,
    pub updated_at:     UnixSeconds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    Active,
    Disabled,
    Deleted,
}

/// An OIDC client registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClient {
    pub id:                 Id,
    pub name:               String,
    pub client_type:        ClientType,
    pub redirect_uris:      Vec<String>,
    pub allowed_scopes:     Vec<String>,
    pub token_auth_method:  TokenAuthMethod,
    pub require_pkce:       bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientType {
    Public,
    Confidential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenAuthMethod {
    None,
    ClientSecretBasic,
    ClientSecretPost,
}

/// Scope list passed around in parsed form. We intern as `String` for
/// simplicity; swapping to `Cow<'static, str>` would let us avoid a few
/// allocations per request but the code noise is not worth it yet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scopes(pub Vec<String>);

impl Scopes {
    pub fn parse(space_separated: &str) -> Self {
        Self(
            space_separated
                .split_whitespace()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_owned())
                .collect(),
        )
    }

    pub fn contains(&self, s: &str) -> bool {
        self.0.iter().any(|x| x == s)
    }

    pub fn to_space_separated(&self) -> String {
        self.0.join(" ")
    }

    /// Intersect with the client's allow-list. Unknown scopes are silently
    /// dropped - this matches RFC 6749 §3.3 which says the server MAY
    /// return a different scope than requested.
    pub fn restrict_to(&self, allowed: &[String]) -> Self {
        Self(
            self.0
                .iter()
                .filter(|s| allowed.iter().any(|a| a == *s))
                .cloned()
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_parse_handles_multiple_spaces() {
        let s = Scopes::parse("openid   profile\temail");
        assert_eq!(s.0, vec!["openid", "profile", "email"]);
    }

    #[test]
    fn scopes_restrict_drops_unknown() {
        let requested = Scopes::parse("openid profile evil");
        let allowed   = vec!["openid".to_string(), "profile".to_string()];
        let out       = requested.restrict_to(&allowed);
        assert_eq!(out.0, vec!["openid", "profile"]);
    }
}
