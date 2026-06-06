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

// ── RFC 065: comprehensive classify() coverage ────────────────────────────

fn auth_code_request() -> TokenRequest {
    TokenRequest {
        grant_type:    "authorization_code".to_owned(),
        code:          Some("code-abc".to_owned()),
        redirect_uri:  Some("https://app.example/callback".to_owned()),
        client_id:     Some("client-1".to_owned()),
        client_secret: None,
        code_verifier: Some("verifier-xyz".to_owned()),
        refresh_token: None,
        scope:         None,
    }
}

fn refresh_request() -> TokenRequest {
    TokenRequest {
        grant_type:    "refresh_token".to_owned(),
        code:          None,
        redirect_uri:  None,
        client_id:     Some("client-1".to_owned()),
        client_secret: None,
        code_verifier: None,
        refresh_token: Some("rt-token-abc".to_owned()),
        scope:         None,
    }
}

#[test]
fn classify_auth_code_success() {
    let req = auth_code_request();
    let g = req.classify().unwrap();
    match g {
        TokenGrant::AuthorizationCode(ag) => {
            assert_eq!(ag.code,          "code-abc");
            assert_eq!(ag.redirect_uri,  "https://app.example/callback");
            assert_eq!(ag.client_id,     "client-1");
            assert_eq!(ag.code_verifier, "verifier-xyz");
        }
        other => panic!("expected AuthorizationCode, got {other:?}"),
    }
}

#[test]
fn classify_refresh_success() {
    let req = refresh_request();
    let g = req.classify().unwrap();
    match g {
        TokenGrant::RefreshToken(rg) => {
            assert_eq!(rg.refresh_token, "rt-token-abc");
            assert_eq!(rg.client_id,     "client-1");
            assert!(rg.scope.is_none());
        }
        other => panic!("expected RefreshToken, got {other:?}"),
    }
}

#[test]
fn classify_refresh_with_scope() {
    let mut req = refresh_request();
    req.scope = Some("openid".to_owned());
    match req.classify().unwrap() {
        TokenGrant::RefreshToken(rg) => assert_eq!(rg.scope, Some("openid")),
        _ => panic!("expected RefreshToken"),
    }
}

#[test]
fn classify_auth_code_missing_code() {
    let mut req = auth_code_request();
    req.code = None;
    assert!(req.classify().is_err(), "missing code must fail");
}

#[test]
fn classify_auth_code_missing_redirect_uri() {
    let mut req = auth_code_request();
    req.redirect_uri = None;
    assert!(req.classify().is_err());
}

#[test]
fn classify_auth_code_missing_client_id() {
    let mut req = auth_code_request();
    req.client_id = None;
    assert!(req.classify().is_err());
}

#[test]
fn classify_refresh_missing_refresh_token() {
    let mut req = refresh_request();
    req.refresh_token = None;
    assert!(req.classify().is_err(), "missing refresh_token must fail");
}

#[test]
fn classify_refresh_missing_client_id() {
    let mut req = refresh_request();
    req.client_id = None;
    assert!(req.classify().is_err());
}

// ── TokenResponse ─────────────────────────────────────────────────────────

#[test]
fn token_response_bearer_constructor() {
    let r = TokenResponse::bearer("at-123".to_owned(), 3600, "openid".to_owned());
    assert_eq!(r.token_type, "Bearer");
    assert_eq!(r.access_token, "at-123");
    assert_eq!(r.expires_in, 3600);
    assert_eq!(r.scope, "openid");
    assert!(r.refresh_token.is_none());
    assert!(r.id_token.is_none());
}

#[test]
fn token_response_serializes_bearer() {
    let r = TokenResponse::bearer("tok".to_owned(), 3600, "openid".to_owned());
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"token_type\":\"Bearer\""));
    assert!(json.contains("\"expires_in\":3600"));
}

// ── TokenError serialization ──────────────────────────────────────────────

#[test]
fn token_error_serializes_snake_case() {
    assert_eq!(
        serde_json::to_string(&TokenError::UnsupportedGrantType).unwrap(),
        "\"unsupported_grant_type\""
    );
    assert_eq!(
        serde_json::to_string(&TokenError::InvalidRequest).unwrap(),
        "\"invalid_request\""
    );
}
