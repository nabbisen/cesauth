//! Originally part of `crates/core/src/migrate/tests.rs` (a single
//! 1,154-line `mod tests { ... }` block). Split into a sibling
//! file in v0.77.0 — test-file modularization (continuation of
//! v0.75.0–v0.76.0 maintenance track).

use super::*;            // reaches the parent `mod tests` (sample_manifest, etc.)
use super::super::*;     // reaches `migrate` (Manifest, FORMAT_VERSION, etc.)

// -----------------------------------------------------------------
// Import — invariant checks (v0.21.0)
// -----------------------------------------------------------------

/// A `SeenSnapshot` populated with a small known-good fixture.
/// Each test starts from this and assert what flips when a
/// reference is missing.
fn fixture_seen() -> SeenSnapshot {
    let mut s = SeenSnapshot::default();
    s.insert("tenants", "t-1".into());
    s.insert("tenants", "t-2".into());
    s.insert("users",   "u-1".into());
    s.insert("users",   "u-2".into());
    s.insert("organizations", "o-1".into());
    s.insert("groups",  "g-1".into());
    s.insert("roles",   "r-1".into());
    s
}

#[test]
fn check_user_tenant_ref_passes_for_known_tenant() {
    let mut seen = fixture_seen();
    let row = serde_json::json!({"id":"u-3","tenant_id":"t-1"});
    assert!(check_user_tenant_ref("users", &row, &mut seen).is_none());
}

#[test]
fn check_user_tenant_ref_fails_for_unknown_tenant() {
    let mut seen = fixture_seen();
    let row = serde_json::json!({"id":"u-3","tenant_id":"t-missing"});
    let r = check_user_tenant_ref("users", &row, &mut seen);
    assert!(r.is_some());
    assert!(r.unwrap().contains("missing tenant"));
}

#[test]
fn check_user_tenant_ref_skips_other_tables() {
    // Defensive: a check function must only fire for its
    // owned table. Returning a violation for an unrelated
    // row is a worse failure than missing a violation.
    let mut seen = fixture_seen();
    let row = serde_json::json!({"id":"t-1","tenant_id":"missing-but-irrelevant"});
    assert!(check_user_tenant_ref("tenants", &row, &mut seen).is_none());
}

#[test]
fn check_membership_user_ref_fires_only_for_membership_tables() {
    let mut seen = fixture_seen();
    let row = serde_json::json!({"user_id":"u-missing"});
    // Membership tables fire.
    for t in &["user_tenant_memberships", "user_organization_memberships", "user_group_memberships"] {
        let r = check_membership_user_ref(t, &row, &mut seen);
        assert!(r.is_some(), "should fire on {t}");
    }
    // Non-membership tables don't fire.
    for t in &["users", "tenants", "organizations"] {
        let r = check_membership_user_ref(t, &row, &mut seen);
        assert!(r.is_none(), "should not fire on {t}");
    }
}

#[test]
fn check_membership_container_dispatches_per_table() {
    let mut seen = fixture_seen();

    // tenant_id checked against tenants
    let r = check_membership_container_ref("user_tenant_memberships",
        &serde_json::json!({"tenant_id":"t-missing"}), &mut seen);
    assert!(r.unwrap().contains("missing tenants"));

    // organization_id checked against organizations
    let r = check_membership_container_ref("user_organization_memberships",
        &serde_json::json!({"organization_id":"o-missing"}), &mut seen);
    assert!(r.unwrap().contains("missing organizations"));

    // group_id checked against groups
    let r = check_membership_container_ref("user_group_memberships",
        &serde_json::json!({"group_id":"g-missing"}), &mut seen);
    assert!(r.unwrap().contains("missing groups"));
}

#[test]
fn check_role_assignment_refs_catches_both_sides() {
    let mut seen = fixture_seen();

    // Missing role
    let r = check_role_assignment_refs("role_assignments",
        &serde_json::json!({"role_id":"r-missing","user_id":"u-1"}), &mut seen);
    assert!(r.unwrap().contains("missing role"));

    // Missing user
    let r = check_role_assignment_refs("role_assignments",
        &serde_json::json!({"role_id":"r-1","user_id":"u-missing"}), &mut seen);
    assert!(r.unwrap().contains("missing user"));

    // Both present
    let r = check_role_assignment_refs("role_assignments",
        &serde_json::json!({"role_id":"r-1","user_id":"u-1"}), &mut seen);
    assert!(r.is_none());
}

