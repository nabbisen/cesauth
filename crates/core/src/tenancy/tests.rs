//! Tenancy domain tests.
//!
//! These are pure-domain checks — slug validation, state enum
//! round-trip, parent-group logic. Storage-bound tests (round-trip
//! against a real port) live in `adapter-test::tenancy::tests`.

use super::types::*;

#[test]
fn account_type_round_trip() {
    for s in &[
        "anonymous", "human_user", "service_account",
        "system_operator", "external_federated_user",
    ] {
        let t = AccountType::from_str(s).expect("known account type");
        assert_eq!(t.as_str(), *s);
    }
    assert!(AccountType::from_str("admin").is_none(),
        "admin is NOT an account type (§5 禁止事項)");
}

#[test]
fn group_parent_helpers() {
    let tenant_scoped = GroupParent::Tenant;
    assert!(tenant_scoped.is_tenant_scoped());
    assert!(tenant_scoped.organization_id().is_none());

    let org_scoped = GroupParent::Organization { organization_id: "org-1".into() };
    assert!(!org_scoped.is_tenant_scoped());
    assert_eq!(org_scoped.organization_id(), Some("org-1"));
}

#[test]
fn tenant_status_serializes_as_snake_case() {
    let t = Tenant {
        id: "t".into(), slug: "acme".into(), display_name: "Acme".into(),
        status: TenantStatus::Suspended,
        created_at: 0, updated_at: 0,
    };
    let json = serde_json::to_string(&t).unwrap();
    assert!(json.contains(r#""status":"suspended""#),
        "Tenant status should serialize as snake_case, got {json}");
}

#[test]
fn default_tenant_id_is_stable() {
    // This constant is referenced from the D1 migration; changing it
    // silently would break backfilled rows. Test guards against that.
    assert_eq!(DEFAULT_TENANT_ID, "tenant-default");
}

// Slug validation — exercised via service::create_tenant in the
// adapter-test integration tests. The pure validator is private in
// service.rs; the integration tests cover its edges.
