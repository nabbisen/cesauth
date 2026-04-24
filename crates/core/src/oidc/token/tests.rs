//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;

#[test]
fn classify_auth_code_requires_all_fields() {
    let req = TokenRequest {
        grant_type:    "authorization_code".into(),
        code:          Some("abc".into()),
        redirect_uri:  Some("https://app/cb".into()),
        client_id:     Some("c".into()),
        client_secret: None,
        code_verifier: None,    // missing!
        refresh_token: None,
        scope:         None,
    };
    assert!(req.classify().is_err());
}

#[test]
fn classify_unknown_grant_type() {
    let req = TokenRequest {
        grant_type:    "password".into(),
        code:          None,
        redirect_uri:  None,
        client_id:     None,
        client_secret: None,
        code_verifier: None,
        refresh_token: None,
        scope:         None,
    };
    assert!(matches!(req.classify(), Err(CoreError::UnsupportedGrantType(_))));
}
