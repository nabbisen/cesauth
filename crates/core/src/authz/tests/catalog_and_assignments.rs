//! Originally part of `crates/core/src/authz/tests.rs`.
//! Split into a sibling file in v0.78.0 (test-file modularization).

use super::common::*;

// Catalog shape
// ---------------------------------------------------------------------

#[test]
fn permission_catalog_has_no_duplicates() {
    use std::collections::BTreeSet;
    let set: BTreeSet<_> = PermissionCatalog::ALL.iter().copied().collect();
    assert_eq!(set.len(), PermissionCatalog::ALL.len(),
        "duplicate entry in PermissionCatalog::ALL");
}

#[test]
fn permission_catalog_includes_expected_staples() {
    // Sanity: the catalog should be non-empty and include the
    // headline permissions mentioned in the spec §16.3.
    assert!(PermissionCatalog::ALL.len() >= 20);
    assert!(PermissionCatalog::ALL.contains(&PermissionCatalog::TENANT_READ));
    assert!(PermissionCatalog::ALL.contains(&PermissionCatalog::AUDIT_READ));
}

// ---------------------------------------------------------------------
// No assignments
// ---------------------------------------------------------------------

#[tokio::test]
async fn unassigned_user_is_denied_with_no_assignments() {
    let roles = StubRoles::default();
    let asgs  = StubAssignments::default();
    let out = check_permission(
        &asgs, &roles, "u-ghost",
        PermissionCatalog::TENANT_READ,
        ScopeRef::Tenant { tenant_id: "t-1" },
        100,
    ).await.unwrap();
    assert_eq!(out, CheckOutcome::Denied(DenyReason::NoAssignments));
}

// ---------------------------------------------------------------------
