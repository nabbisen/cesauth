//! Originally a nested `mod refresh_ext` inside
//! `crates/core/src/service/introspect/tests.rs`. Split into its
//! own file in v0.76.0 (test-file modularization continued from
//! v0.75.0; see CHANGELOG).

use super::*;
use crate::oidc::introspect::{
    CesauthIntrospectionExt, FamilyClassification, RevokeReason,
};

/// Helper: directly mutate a stored family's
/// retired_jtis / reused_jti / reused_at / reuse_was_retired
/// fields. Used to set up the v0.46.0 enhancement test
/// scenarios without going through `rotate` (which the
/// stub doesn't implement — introspect tests don't
/// otherwise need it).
fn mutate_family<F>(store: &StubFamilyStore, family_id: &str, f: F)
where F: FnOnce(&mut FamilyState) {
    let mut m = store.map.lock().unwrap();
    if let Some(state) = m.get_mut(family_id) {
        f(state);
    }
}

// ---------- current path: x_cesauth surfaces "current" ----------

#[tokio::test]
async fn active_refresh_response_carries_x_cesauth_current() {
    let store = StubFamilyStore::default();
    install_family(&store, "fam_ok", "user_a", "client_X",
                   "jti_curr", &["openid"]).await;

    let token = encode_token("fam_ok", "jti_curr", 999_999);
    let resp = introspect_token(
        &store, &fake_keys(), ISS, 30,
        &IntrospectInput {
            token: &token,
            hint:  Some(TokenTypeHint::RefreshToken),
            now_unix: 200,
        },
    ).await.unwrap();

    assert!(resp.active);
    let ext = resp.x_cesauth.expect("x_cesauth must be present on active refresh");
    assert_eq!(ext.family_state, Some(FamilyClassification::Current),
        "active refresh must surface family_state=current");
    // Don't echo current_jti on the active path — top-level `jti`
    // already carries it.
    assert_eq!(ext.current_jti,   None);
    assert_eq!(ext.revoked_at,    None);
    assert_eq!(ext.revoke_reason, None);
}

// ---------- revoked path: x_cesauth surfaces "revoked" ----------

#[tokio::test]
async fn revoked_family_returns_inactive_with_explicit_reason() {
    // Family revoked via the explicit path (no
    // reused_jti). Pre-v0.46.0 this returned bare
    // active=false; v0.46.0 surfaces revoked_at +
    // revoke_reason=explicit.
    let store = StubFamilyStore::default();
    install_family(&store, "fam_rev", "user_a", "client_X",
                   "jti_curr", &["openid"]).await;
    // Revoke at t=500.
    store.revoke("fam_rev", 500).await.unwrap();

    let token = encode_token("fam_rev", "jti_curr", 999_999);
    let resp = introspect_token(
        &store, &fake_keys(), ISS, 30,
        &IntrospectInput {
            token: &token,
            hint:  Some(TokenTypeHint::RefreshToken),
            now_unix: 600,
        },
    ).await.unwrap();

    assert!(!resp.active, "revoked family must report inactive");
    let ext = resp.x_cesauth.expect("revoked path must surface x_cesauth");
    assert_eq!(ext.family_state,  Some(FamilyClassification::Revoked));
    assert_eq!(ext.revoked_at,    Some(500));
    assert_eq!(ext.revoke_reason, Some(RevokeReason::Explicit));
    assert_eq!(ext.current_jti,   None,
        "current_jti omitted for revoked families (no current jti)");
}

#[tokio::test]
async fn reuse_detected_family_returns_inactive_with_reuse_reason() {
    // Family revoked via ADR-011 §Q1 reuse defense
    // (reused_jti is Some). v0.46.0 distinguishes
    // this from explicit revocation — security teams
    // alert on reuse_detected specifically.
    let store = StubFamilyStore::default();
    install_family(&store, "fam_reuse", "user_a", "client_X",
                   "jti_curr", &["openid"]).await;
    mutate_family(&store, "fam_reuse", |s| {
        s.revoked_at        = Some(600);
        s.reused_jti        = Some("jti_old_retired".into());
        s.reused_at         = Some(599);
        s.reuse_was_retired = Some(true);
    });

    let token = encode_token("fam_reuse", "jti_curr", 999_999);
    let resp = introspect_token(
        &store, &fake_keys(), ISS, 30,
        &IntrospectInput {
            token: &token,
            hint:  Some(TokenTypeHint::RefreshToken),
            now_unix: 700,
        },
    ).await.unwrap();

    assert!(!resp.active);
    let ext = resp.x_cesauth.unwrap();
    assert_eq!(ext.revoke_reason, Some(RevokeReason::ReuseDetected),
        "reuse-detected revocation must be distinguishable from explicit");
    assert_eq!(ext.revoked_at,    Some(600));
    // We deliberately do NOT surface `reused_jti` itself
    // — could be an oracle for forensic JTI guessing.
}

// ---------- retired path: x_cesauth surfaces "retired" + current_jti ---

#[tokio::test]
async fn retired_jti_returns_inactive_with_current_jti_hint() {
    // The introspecter holds a token whose jti is
    // in retired_jtis. v0.46.0 surfaces the current
    // jti so the RS knows "the user has a fresher
    // token" without trying to refresh.
    let store = StubFamilyStore::default();
    install_family(&store, "fam_rot", "user_a", "client_X",
                   "jti_v2", &["openid"]).await;
    mutate_family(&store, "fam_rot", |s| {
        s.retired_jtis = vec!["jti_v1".into()];
    });

    // Present the v1 (retired) jti.
    let token = encode_token("fam_rot", "jti_v1", 999_999);
    let resp = introspect_token(
        &store, &fake_keys(), ISS, 30,
        &IntrospectInput {
            token: &token,
            hint:  Some(TokenTypeHint::RefreshToken),
            now_unix: 700,
        },
    ).await.unwrap();

    assert!(!resp.active, "retired jti is not active");
    let ext = resp.x_cesauth.unwrap();
    assert_eq!(ext.family_state, Some(FamilyClassification::Retired));
    assert_eq!(ext.current_jti,  Some("jti_v2".into()),
        "retired path must surface current_jti as a stale-token hint");
}

// ---------- unknown path: family-id-existence privacy ----------

#[tokio::test]
async fn unknown_family_returns_unknown_classification() {
    // Token decoded as refresh shape but no such
    // family exists. Family-existence shouldn't be
    // distinguishable from "swept" — the same
    // Unknown classification covers both.
    let store = StubFamilyStore::default();
    // No family installed.

    let token = encode_token("fam_ghost", "jti_anything", 999_999);
    let resp = introspect_token(
        &store, &fake_keys(), ISS, 30,
        &IntrospectInput {
            token: &token,
            hint:  Some(TokenTypeHint::RefreshToken),
            now_unix: 700,
        },
    ).await.unwrap();

    assert!(!resp.active);
    let ext = resp.x_cesauth.unwrap();
    assert_eq!(ext.family_state, Some(FamilyClassification::Unknown));
    assert_eq!(ext.current_jti,  None);
}

#[tokio::test]
async fn jti_mismatch_without_retired_membership_is_unknown_not_retired() {
    // Privacy invariant: if the presented jti
    // doesn't match current and isn't in
    // retired_jtis, classification must be
    // Unknown (not Retired). Retired implies
    // "this jti was once valid"; surfacing that
    // for an arbitrary forged jti would let an
    // attacker confirm family-id existence.
    let store = StubFamilyStore::default();
    install_family(&store, "fam_priv", "user_a", "client_X",
                   "jti_curr", &["openid"]).await;
    // No retired jtis.

    let token = encode_token("fam_priv", "jti_forged", 999_999);
    let resp = introspect_token(
        &store, &fake_keys(), ISS, 30,
        &IntrospectInput {
            token: &token,
            hint:  Some(TokenTypeHint::RefreshToken),
            now_unix: 700,
        },
    ).await.unwrap();

    assert!(!resp.active);
    let ext = resp.x_cesauth.unwrap();
    assert_eq!(ext.family_state, Some(FamilyClassification::Unknown),
        "forged-jti-against-real-family must classify as Unknown, \
         not Retired — Retired would leak family existence");
    assert_eq!(ext.current_jti, None,
        "current_jti must NOT be surfaced when the introspecter \
         didn't prove possession of a once-valid jti");
}

// ---------- malformed tokens still fall through to access ----------

#[tokio::test]
async fn truly_malformed_token_falls_through_no_ext() {
    // A token that doesn't even decode as refresh
    // shape (e.g., a JWT or pure garbage) must NOT
    // produce an x_cesauth response — that would
    // prevent the access-token fallback from
    // running. Pre-v0.46.0 this returned None to
    // fall through; v0.46.0 preserves that.
    let store = StubFamilyStore::default();
    let resp = introspect_token(
        &store, &fake_keys(), ISS, 30,
        &IntrospectInput {
            token: "not.a.refresh.token",  // 4 parts; not refresh shape
            hint:  None,                    // no hint = try access first
            now_unix: 700,
        },
    ).await.unwrap();
    // The token also fails access-token verify (bad
    // base64, wrong shape) → final inactive.
    assert!(!resp.active);
    assert!(resp.x_cesauth.is_none(),
        "no x_cesauth surfaces for a token that didn't even decode as refresh");
}

// ---------- access-token responses don't carry x_cesauth (yet) ------

#[tokio::test]
async fn access_token_path_does_not_set_x_cesauth() {
    // The access-token path returns x_cesauth=None
    // because the JWT claim shape is already
    // self-descriptive. This test pins that
    // contract — if a future release adds
    // x_cesauth to the access path, the test
    // should be updated alongside.
    //
    // We can't easily build a valid access JWT
    // here without the multi_key test machinery;
    // pin via the inactive-default path: an empty
    // token with hint=access goes through access
    // verify (fails, returns Ok(None)) then
    // refresh (decode_refresh_token returns None,
    // no Some path), then orchestrator returns
    // inactive(). That inactive() must have
    // x_cesauth=None.
    let store = StubFamilyStore::default();
    let resp = introspect_token(
        &store, &fake_keys(), ISS, 30,
        &IntrospectInput {
            token: "x.y.z",
            hint:  Some(TokenTypeHint::AccessToken),
            now_unix: 700,
        },
    ).await.unwrap();
    assert!(!resp.active);
    assert!(resp.x_cesauth.is_none(),
        "the bare inactive() response must not carry x_cesauth");
}

// ---------- serde shape ----------

#[test]
fn x_cesauth_field_serializes_under_correct_key() {
    // Pin the wire JSON key. RFC 7662 §2.2 talks
    // about "service-specific response names";
    // common convention is `x_*` prefix so
    // resource-server consumers know which fields
    // are spec-defined and which are extensions.
    // Cesauth picks `x_cesauth` as a single
    // namespace envelope.
    let resp = IntrospectionResponse::inactive_with_ext(CesauthIntrospectionExt {
        family_state:  Some(FamilyClassification::Retired),
        revoked_at:    None,
        revoke_reason: None,
        current_jti:   Some("jti_curr".into()),
    });
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains(r#""x_cesauth":"#),
        "extension envelope must use the x_cesauth key: {json}");
    assert!(json.contains(r#""family_state":"retired""#),
        "FamilyClassification must serialize as snake_case: {json}");
    assert!(json.contains(r#""current_jti":"jti_curr""#));
}

#[test]
fn x_cesauth_omitted_when_none() {
    // Default introspection responses (pre-v0.46.0
    // shape) must not surface x_cesauth at all.
    // Verifies the skip_serializing_if attribute.
    let resp = IntrospectionResponse::inactive();
    let json = serde_json::to_string(&resp).unwrap();
    assert!(!json.contains("x_cesauth"),
        "x_cesauth must NOT appear in serialized JSON when None: {json}");
}

#[test]
fn revoke_reason_serializes_as_snake_case() {
    let resp = IntrospectionResponse::inactive_with_ext(CesauthIntrospectionExt {
        family_state:  Some(FamilyClassification::Revoked),
        revoked_at:    Some(500),
        revoke_reason: Some(RevokeReason::ReuseDetected),
        current_jti:   None,
    });
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains(r#""revoke_reason":"reuse_detected""#),
        "ReuseDetected must serialize as snake_case: {json}");
}
