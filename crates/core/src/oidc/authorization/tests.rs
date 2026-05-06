//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;
use crate::types::{ClientType, TokenAuthMethod};

fn sample_client() -> OidcClient {
    OidcClient {
        id:                "client-a".into(),
        name:              "Sample".into(),
        client_type:       ClientType::Public,
        redirect_uris:     vec!["https://app.example/cb".into()],
        allowed_scopes:    vec!["openid".into()],
        token_auth_method: TokenAuthMethod::None,
        require_pkce:      true,
        audience:          None,
    }
}

fn sample_request() -> AuthorizationRequest {
    AuthorizationRequest {
        response_type:         "code".into(),
        client_id:             "client-a".into(),
        redirect_uri:          "https://app.example/cb".into(),
        scope:                 Some("openid".into()),
        state:                 Some("xyz".into()),
        nonce:                 Some("n".into()),
        code_challenge:        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
        code_challenge_method: "S256".into(),
        prompt:                None,
        max_age:               None,
    }
}

#[test]
fn happy_path() {
    let req = sample_request();
    let cli = sample_client();
    let pol = req.validate(&cli).unwrap();
    assert!(matches!(pol.pkce_method, ChallengeMethod::S256));
    assert_eq!(pol.prompt, Prompt::Unspecified);
    assert!(pol.max_age.is_none());
}

#[test]
fn rejects_unregistered_redirect() {
    let mut req = sample_request();
    req.redirect_uri = "https://attacker.example/cb".into();
    assert!(req.validate(&sample_client()).is_err());
}

#[test]
fn rejects_non_code_response_type() {
    let mut req = sample_request();
    req.response_type = "token".into();
    assert!(req.validate(&sample_client()).is_err());
}

#[test]
fn rejects_missing_pkce_when_required() {
    let mut req = sample_request();
    req.code_challenge = String::new();
    assert!(req.validate(&sample_client()).is_err());
}

#[test]
fn parses_prompt_login() {
    let mut req = sample_request();
    req.prompt = Some("login".into());
    assert_eq!(req.validate(&sample_client()).unwrap().prompt, Prompt::Login);
}

#[test]
fn parses_prompt_none() {
    let mut req = sample_request();
    req.prompt = Some("none".into());
    assert_eq!(req.validate(&sample_client()).unwrap().prompt, Prompt::None);
}

#[test]
fn rejects_prompt_consent_unsupported() {
    let mut req = sample_request();
    req.prompt = Some("consent".into());
    assert!(req.validate(&sample_client()).is_err());
}

#[test]
fn rejects_prompt_none_and_login_together() {
    // OIDC §3.1.2.1: explicitly prohibited combination.
    let mut req = sample_request();
    req.prompt = Some("none login".into());
    assert!(req.validate(&sample_client()).is_err());
}

#[test]
fn blank_prompt_is_unspecified() {
    let mut req = sample_request();
    req.prompt = Some("   ".into());
    assert_eq!(req.validate(&sample_client()).unwrap().prompt, Prompt::Unspecified);
}

#[test]
fn rejects_negative_max_age() {
    let mut req = sample_request();
    req.max_age = Some(-5);
    assert!(req.validate(&sample_client()).is_err());
}

#[test]
fn max_age_satisfies_freshness() {
    // auth_time = 1000, max_age = 60, now = 1050 -> fresh
    assert!(session_satisfies_max_age(1000, Some(60), 1050));
    // auth_time = 1000, max_age = 60, now = 1061 -> stale
    assert!(!session_satisfies_max_age(1000, Some(60), 1061));
    // Exact boundary: now - auth_time == max_age is still fresh.
    assert!(session_satisfies_max_age(1000, Some(60), 1060));
    // No max_age -> always fresh.
    assert!(session_satisfies_max_age(0, None, i64::MAX));
    // max_age=0 + now > auth_time -> stale (the "just re-authenticate" case).
    assert!(!session_satisfies_max_age(1000, Some(0), 1001));
}
