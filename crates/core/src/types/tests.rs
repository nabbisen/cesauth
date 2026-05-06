//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

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

// ---------------------------------------------------------------------
// v0.6.0: User gained `tenant_id` and `account_type`.
// ---------------------------------------------------------------------

#[test]
fn user_serializes_with_tenant_and_account_type() {
    let u = User {
        id: "u1".into(),
        tenant_id: "tenant-default".into(),
        email: Some("a@b.c".into()),
        email_verified: true,
        display_name: None,
        account_type: crate::tenancy::AccountType::HumanUser,
        status: UserStatus::Active,
        created_at: 1, updated_at: 2,
    };
    let j = serde_json::to_string(&u).unwrap();
    // Snake-case for both new fields.
    assert!(j.contains(r#""tenant_id":"tenant-default""#),
        "expected tenant_id field, got {j}");
    assert!(j.contains(r#""account_type":"human_user""#),
        "expected account_type=human_user, got {j}");
}

#[test]
fn user_deserializes_pre_0_4_1_payload_with_defaults() {
    // Pre-0.6.0 payloads (in tests, in cached caches anywhere) had
    // neither `tenant_id` nor `account_type`. The `serde(default)`
    // attributes on those fields make the rounder-trip safe across
    // a version bump without forcing a coordinated rollout.
    let pre = r#"{
        "id": "u1",
        "email": null,
        "email_verified": false,
        "display_name": null,
        "status": "active",
        "created_at": 0,
        "updated_at": 0
    }"#;
    let u: User = serde_json::from_str(pre).unwrap();
    assert_eq!(u.tenant_id, crate::tenancy::DEFAULT_TENANT_ID);
    assert_eq!(u.account_type, crate::tenancy::AccountType::HumanUser);
}

#[test]
fn account_type_default_is_human_user() {
    // Documentation-style check: this is what the migration also
    // assumes when backfilling pre-0.6.0 rows.
    let u: User = serde_json::from_str(r#"{
        "id": "u1", "tenant_id": "t",
        "email": null, "email_verified": false, "display_name": null,
        "status": "active", "created_at": 0, "updated_at": 0
    }"#).unwrap();
    assert_eq!(u.account_type, crate::tenancy::AccountType::HumanUser);
}
