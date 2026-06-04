//! OIDC `/userinfo` endpoint — RFC 040 / OIDC Core §5.3.
//!
//! Pure function: takes a verified access token's claims and the `User`
//! record, returns the `UserInfoClaims` object to be serialised.  I/O
//! (token verification, user lookup) lives in the worker handler.
//!
//! **Claim population rules** (mirror `id_token.rs`, minus time claims):
//!
//! | Scope       | Claims added                                      |
//! |-------------|---------------------------------------------------|
//! | `openid`    | `sub` (always, even without openid — defence in depth) |
//! | `email`     | `email`, `email_verified` when user has an email  |
//! | `profile`   | `name` when user has a display name               |

use serde::{Deserialize, Serialize};

use crate::types::User;

/// Claims returned by `GET /userinfo` or `POST /userinfo`.
///
/// Unlike the id_token, the userinfo response omits JWT-specific
/// time claims (`iss`, `exp`, `iat`, `auth_time`).  It is a plain
/// JSON object, not a signed JWT (OIDC Core §5.3.2).
///
/// Optional fields are elided from the JSON wire form when `None`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserInfoClaims {
    /// Subject — always present; equals the `user_id` from the access token.
    pub sub: String,

    /// User's email address (requires `email` scope and non-null email).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Whether `email` has been verified (requires `email` scope and non-null email).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    /// User's display name (requires `profile` scope and non-null display_name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Build the `/userinfo` response claims.
///
/// `sub`    — the authenticated user's ID, taken from the access token (`sub` claim).
/// `user`   — the user record loaded from `UserRepository::find_by_id(sub)`.
/// `scopes` — the scopes granted on the access token that was presented.
///
/// The caller is responsible for verifying the access token and ensuring
/// `sub` matches `user.id`.
pub fn build_userinfo_claims(sub: &str, user: &User, scopes: &[String]) -> UserInfoClaims {
    let has_email   = scopes.iter().any(|s| s == "email");
    let has_profile = scopes.iter().any(|s| s == "profile");

    UserInfoClaims {
        sub: sub.to_owned(),
        email: if has_email { user.email.clone() } else { None },
        email_verified: if has_email && user.email.is_some() {
            Some(user.email_verified)
        } else {
            None
        },
        name: if has_profile { user.display_name.clone() } else { None },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{User, UserStatus};

    fn user_with(email: Option<&str>, verified: bool, name: Option<&str>) -> User {
        User {
            id:             "u-test".to_owned(),
            tenant_id:      "t-default".to_owned(),
            email:          email.map(str::to_owned),
            email_verified: verified,
            display_name:   name.map(str::to_owned),
            account_type:   crate::tenancy::AccountType::HumanUser,
            status:         UserStatus::Active,
            created_at:     0,
            updated_at:     0,
        }
    }

    fn scopes(s: &[&str]) -> Vec<String> { s.iter().map(|x| x.to_string()).collect() }

    #[test]
    fn openid_only_returns_only_sub() {
        let user = user_with(Some("alice@example.com"), true, Some("Alice"));
        let claims = build_userinfo_claims("u-test", &user, &scopes(&["openid"]));
        assert_eq!(claims.sub, "u-test");
        assert!(claims.email.is_none(),         "no email without email scope");
        assert!(claims.email_verified.is_none(), "no email_verified without email scope");
        assert!(claims.name.is_none(),           "no name without profile scope");
    }

    #[test]
    fn email_scope_adds_email_claims() {
        let user = user_with(Some("alice@example.com"), true, None);
        let claims = build_userinfo_claims("u-test", &user, &scopes(&["openid", "email"]));
        assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        assert_eq!(claims.email_verified, Some(true));
    }

    #[test]
    fn email_verified_false_reflected_correctly() {
        let user = user_with(Some("bob@example.com"), false, None);
        let claims = build_userinfo_claims("u-test", &user, &scopes(&["openid", "email"]));
        assert_eq!(claims.email_verified, Some(false));
    }

    #[test]
    fn no_email_on_user_omits_both_email_fields_even_with_scope() {
        let user = user_with(None, false, None);
        let claims = build_userinfo_claims("u-test", &user, &scopes(&["openid", "email"]));
        assert!(claims.email.is_none(),          "no email field when user.email is None");
        assert!(claims.email_verified.is_none(), "no email_verified when user.email is None");
    }

    #[test]
    fn profile_scope_adds_name() {
        let user = user_with(None, false, Some("Alice Smith"));
        let claims = build_userinfo_claims("u-test", &user, &scopes(&["openid", "profile"]));
        assert_eq!(claims.name.as_deref(), Some("Alice Smith"));
    }

    #[test]
    fn no_display_name_omits_name_even_with_scope() {
        let user = user_with(None, false, None);
        let claims = build_userinfo_claims("u-test", &user, &scopes(&["openid", "profile"]));
        assert!(claims.name.is_none(), "name absent when display_name is None");
    }

    #[test]
    fn all_scopes_returns_all_available_claims() {
        let user = user_with(Some("c@example.com"), true, Some("C User"));
        let claims = build_userinfo_claims("u-c", &user, &scopes(&["openid", "email", "profile"]));
        assert!(claims.email.is_some());
        assert!(claims.email_verified.is_some());
        assert!(claims.name.is_some());
        assert_eq!(claims.sub, "u-c");
    }

    #[test]
    fn no_openid_scope_still_returns_sub() {
        // Defence-in-depth: even if openid was somehow absent, sub is always set.
        let user = user_with(None, false, None);
        let claims = build_userinfo_claims("u-x", &user, &scopes(&["email"]));
        assert_eq!(claims.sub, "u-x");
    }

    #[test]
    fn claims_serialise_to_json_without_null_fields() {
        let user = user_with(None, false, None);
        let claims = build_userinfo_claims("u-test", &user, &scopes(&["openid"]));
        let json = serde_json::to_string(&claims).unwrap();
        // Only `sub` should appear; no null fields.
        assert!(json.contains("\"sub\""));
        assert!(!json.contains("\"email\""),          "null fields must be omitted");
        assert!(!json.contains("\"email_verified\""), "null fields must be omitted");
        assert!(!json.contains("\"name\""),           "null fields must be omitted");
    }

    #[test]
    fn unknown_scope_does_not_add_claims() {
        let user = user_with(Some("x@example.com"), true, Some("X"));
        let claims = build_userinfo_claims("u-test", &user, &scopes(&["openid", "frobnicate"]));
        assert!(claims.email.is_none(), "unknown scope must not add email");
        assert!(claims.name.is_none(),  "unknown scope must not add name");
    }
}
