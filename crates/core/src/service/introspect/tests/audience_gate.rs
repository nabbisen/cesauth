//! Originally a nested `mod audience_gate` inside
//! `crates/core/src/service/introspect/tests.rs`. Split into its
//! own file in v0.76.0 (test-file modularization continued from
//! v0.75.0; see CHANGELOG).

use super::super::{
    apply_introspection_audience_gate, IntrospectionGateOutcome,
};
use crate::oidc::introspect::IntrospectionResponse;

fn active_with_aud(aud: &str) -> IntrospectionResponse {
    IntrospectionResponse::active_access(
        "openid".into(), "client_X".into(),
        "user_alice".into(), "jti_abc".into(),
        100, 200,
        Some(aud.into()),
    )
}

fn active_no_aud() -> IntrospectionResponse {
    // Refresh-token shape: active=true, aud=None.
    IntrospectionResponse::active_refresh(
        "openid".into(), "client_X".into(),
        "user_alice".into(), "jti_abc".into(),
        100, 200,
    )
}

#[test]
fn unscoped_client_passes_through_active_response() {
    // Client has no `audience` configured → gate is
    // no-op. This is the default behavior for every
    // pre-v0.50.0 client and for any deployment that
    // hasn't opted in.
    let resp = active_with_aud("rs.example.com");
    let out = apply_introspection_audience_gate(resp.clone(), None);
    match out {
        IntrospectionGateOutcome::PassedThrough(r) => assert_eq!(r, resp),
        other => panic!("expected PassedThrough, got {other:?}"),
    }
}

#[test]
fn matching_audience_passes_through() {
    let resp = active_with_aud("rs.example.com");
    let out = apply_introspection_audience_gate(
        resp.clone(),
        Some("rs.example.com"),
    );
    match out {
        IntrospectionGateOutcome::PassedThrough(r) => {
            assert_eq!(r, resp);
            assert!(r.active);
            assert_eq!(r.aud.as_deref(), Some("rs.example.com"));
        }
        other => panic!("expected PassedThrough, got {other:?}"),
    }
}

#[test]
fn mismatched_audience_returns_inactive_no_leak() {
    // Critical privacy pin: on denial the wire form
    // is bare `{"active":false}`. The original
    // active response's claims (scope, sub, jti, etc.)
    // MUST NOT survive into the returned response —
    // that would be a token-existence side-channel.
    let resp = active_with_aud("rs.example.com");
    let out = apply_introspection_audience_gate(
        resp,
        Some("other.example.com"),
    );
    match out {
        IntrospectionGateOutcome::AudienceDenied {
            response,
            requesting_client_audience,
            token_audience,
        } => {
            assert!(!response.active,
                "denied response must be inactive");
            assert_eq!(response, IntrospectionResponse::inactive(),
                "denied response must be byte-equal to bare inactive() — \
                 no claim leaks via response shape");
            assert_eq!(requesting_client_audience, "other.example.com");
            assert_eq!(token_audience,             "rs.example.com");
        }
        other => panic!("expected AudienceDenied, got {other:?}"),
    }
}

#[test]
fn mismatch_response_serializes_to_bare_inactive() {
    // Defense-in-depth pin: even if a future change
    // adds a field to IntrospectionResponse that the
    // gate forgets to clear, the wire form must
    // still be bare `{"active":false}`.
    let resp = active_with_aud("rs.example.com");
    let out = apply_introspection_audience_gate(
        resp,
        Some("attacker.example.com"),
    );
    let response = match out {
        IntrospectionGateOutcome::AudienceDenied { response, .. } => response,
        other => panic!("expected AudienceDenied, got {other:?}"),
    };
    let json = serde_json::to_string(&response).unwrap();
    assert_eq!(json, r#"{"active":false}"#,
        "v0.38.0 inactive-response wire-form invariant must hold for \
         audience-denied responses too");
}

#[test]
fn already_inactive_response_passes_through_unchanged() {
    // Inactive responses already leak nothing. The
    // gate is a no-op on them — no point in re-
    // wrapping into AudienceDenied (which would
    // produce a confusing audit event for what was
    // a normal inactive path).
    let resp = IntrospectionResponse::inactive();
    let out = apply_introspection_audience_gate(
        resp.clone(),
        Some("scoped.example.com"),
    );
    match out {
        IntrospectionGateOutcome::PassedThrough(r) => assert_eq!(r, resp),
        other => panic!("expected PassedThrough, got {other:?}"),
    }
}

#[test]
fn refresh_token_response_with_no_aud_passes_through() {
    // v0.50.0 documented behavior: refresh-token
    // responses don't carry `aud` (the family doesn't
    // record audience). The gate falls through. A
    // future iteration may scope refresh
    // introspection separately; v0.50.0 explicitly
    // doesn't.
    let resp = active_no_aud();
    assert!(resp.aud.is_none(), "test pre-condition");
    let out = apply_introspection_audience_gate(
        resp.clone(),
        Some("scoped.example.com"),
    );
    match out {
        IntrospectionGateOutcome::PassedThrough(r) => assert_eq!(r, resp),
        other => panic!("expected PassedThrough, got {other:?}"),
    }
}

#[test]
fn empty_string_audiences_compared_byte_exact() {
    // Defensive: configured audience of "" matches
    // ONLY tokens with aud="" — empty string is a
    // legitimate (if unusual) value. Strict byte
    // equality is the contract.
    let resp = active_with_aud("");
    let out_match = apply_introspection_audience_gate(
        resp.clone(),
        Some(""),
    );
    assert!(matches!(out_match, IntrospectionGateOutcome::PassedThrough(_)),
        "empty matches empty");

    let resp = active_with_aud("");
    let out_mismatch = apply_introspection_audience_gate(
        resp,
        Some("rs.example.com"),
    );
    assert!(matches!(out_mismatch, IntrospectionGateOutcome::AudienceDenied { .. }),
        "empty does NOT match non-empty");
}

#[test]
fn case_sensitive_audience_comparison() {
    // Audiences are compared byte-exact. Standards
    // (RFC 7519 §4.1.3) treat aud as case-sensitive
    // strings. cesauth follows the spec.
    let resp = active_with_aud("RS.Example.com");
    let out = apply_introspection_audience_gate(
        resp,
        Some("rs.example.com"),
    );
    assert!(matches!(out, IntrospectionGateOutcome::AudienceDenied { .. }),
        "case difference means mismatch — RFC 7519 §4.1.3 is case-sensitive");
}

#[test]
fn substring_match_does_not_satisfy_gate() {
    // Defensive: an attacker setting their client's
    // audience to a substring of the real audience
    // must not pass. Comparison is exact, not prefix
    // / contains.
    let resp = active_with_aud("rs.example.com");
    let out_substring = apply_introspection_audience_gate(
        resp.clone(),
        Some("rs"),
    );
    assert!(matches!(out_substring, IntrospectionGateOutcome::AudienceDenied { .. }));

    let resp = active_with_aud("rs.example.com");
    let out_superstring = apply_introspection_audience_gate(
        resp,
        Some("rs.example.com.attacker.org"),
    );
    assert!(matches!(out_superstring, IntrospectionGateOutcome::AudienceDenied { .. }));
}

#[test]
fn mismatched_audience_audit_payload_contains_both_values() {
    // The handler will lift these fields into the
    // audit payload. Pin the contract: AudienceDenied
    // exposes BOTH the configured client audience
    // AND the actual token audience for operator
    // troubleshooting (these are operator-controlled
    // identifiers, not secret material).
    let resp = active_with_aud("token.aud.example");
    let out = apply_introspection_audience_gate(
        resp,
        Some("client.aud.example"),
    );
    match out {
        IntrospectionGateOutcome::AudienceDenied {
            requesting_client_audience,
            token_audience,
            ..
        } => {
            assert_eq!(requesting_client_audience, "client.aud.example");
            assert_eq!(token_audience,             "token.aud.example");
        }
        other => panic!("expected AudienceDenied, got {other:?}"),
    }
}
