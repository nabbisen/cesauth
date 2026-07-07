//! Originally part of `crates/core/src/authz/tests.rs`.
//! Split into a sibling file in v0.78.0 (test-file modularization).

use super::common::*;

// v0.15.0 — check_permissions_batch
// ---------------------------------------------------------------------

#[tokio::test]
async fn batch_with_no_queries_returns_empty_without_io() {
    use super::super::service::check_permissions_batch;

    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();

    let out = check_permissions_batch(&asgs, &roles, &crate::types::UserId::from_storage("u"), &[], 100,
    ).await.unwrap();
    assert!(out.is_empty(),
        "empty queries → empty results, no fall-through");
}

#[tokio::test]
async fn batch_matches_per_query_check_permission_results() {
    // The whole point: batch should produce the same answers as
    // calling `check_permission` once per (slug, scope). If the
    // batch helper diverges, callers using affordance gating
    // would render different UI from what the per-route check
    // would allow.
    use super::super::service::{check_permission, check_permissions_batch};

    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();
    roles.create(&role("r-admin", None, "admin", &[
        PermissionCatalog::TENANT_READ,
        PermissionCatalog::ORGANIZATION_CREATE,
    ])).await.unwrap();
    asgs.create(&assignment("a", "u", "r-admin",
        Scope::Tenant { tenant_id: "t-acme".into() })).await.unwrap();

    let queries: &[(&str, ScopeRef<'_>)] = &[
        (PermissionCatalog::TENANT_READ,         ScopeRef::Tenant { tenant_id: "t-acme" }),
        (PermissionCatalog::ORGANIZATION_CREATE, ScopeRef::Tenant { tenant_id: "t-acme" }),
        (PermissionCatalog::GROUP_DELETE,        ScopeRef::Tenant { tenant_id: "t-acme" }),
        (PermissionCatalog::TENANT_READ,         ScopeRef::Tenant { tenant_id: "other-tenant" }),
    ];

    let batch_out = check_permissions_batch(&asgs, &roles, &crate::types::UserId::from_storage("u"), queries, 100,
    ).await.unwrap();

    // Compare against per-call results.
    for (i, (slug, scope)) in queries.iter().enumerate() {
        let single = check_permission(&asgs, &roles, &crate::types::UserId::from_storage("u"), slug, *scope, 100,
        ).await.unwrap();
        assert_eq!(batch_out[i], single,
            "batch result at index {i} must match per-query check");
    }

    // Spot-check: index 0 is allowed (TENANT_READ at t-acme),
    // index 2 is denied (no GROUP_DELETE in role), index 3 is
    // denied (different tenant scope).
    assert!(batch_out[0].is_allowed());
    assert!(batch_out[1].is_allowed());
    assert!(!batch_out[2].is_allowed());
    assert!(!batch_out[3].is_allowed());
}

#[tokio::test]
async fn batch_no_assignments_denies_every_query_with_NoAssignments() {
    use super::super::service::check_permissions_batch;

    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();
    // No assignments for user "u".

    let queries: &[(&str, ScopeRef<'_>)] = &[
        (PermissionCatalog::TENANT_READ,    ScopeRef::Tenant { tenant_id: "t" }),
        (PermissionCatalog::GROUP_CREATE,   ScopeRef::Tenant { tenant_id: "t" }),
        (PermissionCatalog::ROLE_ASSIGN,    ScopeRef::Tenant { tenant_id: "t" }),
    ];
    let out = check_permissions_batch(&asgs, &roles, &crate::types::UserId::from_storage("u"), queries, 100)
        .await.unwrap();

    assert_eq!(out.len(), 3);
    for o in &out {
        assert_eq!(*o, CheckOutcome::Denied(DenyReason::NoAssignments));
    }
}

#[tokio::test]
async fn batch_with_dangling_role_id_denies_gracefully() {
    // A role assignment points at a role row that no longer
    // exists. check_permission handles this by skipping; batch
    // should preserve the same behaviour rather than panicking
    // or treating the dangling assignment as a match.
    use super::super::service::check_permissions_batch;

    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();
    asgs.create(&assignment("a", "u", "ghost-role",
        Scope::Tenant { tenant_id: "t".into() })).await.unwrap();

    let queries: &[(&str, ScopeRef<'_>)] = &[
        (PermissionCatalog::TENANT_READ, ScopeRef::Tenant { tenant_id: "t" }),
    ];
    let out = check_permissions_batch(&asgs, &roles, &crate::types::UserId::from_storage("u"), queries, 100)
        .await.unwrap();
    assert_eq!(out[0], CheckOutcome::Denied(DenyReason::PermissionMissing));
}

#[tokio::test]
async fn batch_respects_expiration_per_query() {
    use super::super::service::check_permissions_batch;

    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();
    roles.create(&role("r-admin", None, "admin", &[
        PermissionCatalog::TENANT_READ,
    ])).await.unwrap();
    let mut a = assignment("a", "u", "r-admin",
        Scope::Tenant { tenant_id: "t".into() });
    a.expires_at = Some(50);  // expired by now=100
    asgs.create(&a).await.unwrap();

    let queries: &[(&str, ScopeRef<'_>)] = &[
        (PermissionCatalog::TENANT_READ, ScopeRef::Tenant { tenant_id: "t" }),
    ];
    let out = check_permissions_batch(&asgs, &roles, &crate::types::UserId::from_storage("u"), queries, 100)
        .await.unwrap();
    // Expired → Denied(Expired), same as single check.
    assert_eq!(out[0], CheckOutcome::Denied(DenyReason::Expired));
}

// =========================================================================
