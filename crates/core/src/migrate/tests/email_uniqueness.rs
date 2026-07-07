//! Originally part of `crates/core/src/migrate/tests.rs` (a single
//! 1,154-line `mod tests { ... }` block). Split into a sibling
//! file in v0.77.0 — test-file modularization (continuation of
//! v0.75.0–v0.76.0 maintenance track).

use super::*;            // reaches the parent `mod tests` (sample_manifest, etc.)
use super::super::*;     // reaches `migrate` (Manifest, FORMAT_VERSION, etc.)
use super::import_pipeline::{build_dump, run_import, VecSink};

// -----------------------------------------------------------------
// v0.22.0 — email uniqueness + scoped secondary index
// -----------------------------------------------------------------

#[test]
fn scoped_secondary_index_tracks_per_tuple() {
    // The `record_scoped_secondary` returns true on duplicate
    // (i.e., the value was already present). Pin the
    // semantic — checks rely on this exact return value.
    let mut s = SeenSnapshot::default();
    // First insert: not a duplicate.
    let dup = s.record_scoped_secondary(
        "users", "tenant_id", "t-1", "alice@x".into());
    assert!(!dup, "first insert must report not-already-present");
    // Second insert of same value: duplicate.
    let dup = s.record_scoped_secondary(
        "users", "tenant_id", "t-1", "alice@x".into());
    assert!(dup, "second insert must report already-present");
    // Different scope, same value: not a duplicate.
    let dup = s.record_scoped_secondary(
        "users", "tenant_id", "t-2", "alice@x".into());
    assert!(!dup, "scope change must reset uniqueness");
}

#[test]
fn check_user_email_unique_skips_when_table_not_users() {
    let mut s = SeenSnapshot::default();
    let row = serde_json::json!({"email":"a@x","tenant_id":"t-1"});
    assert!(check_user_email_unique_per_tenant("tenants", &row, &mut s).is_none());
    assert!(check_user_email_unique_per_tenant("groups",  &row, &mut s).is_none());
}

#[test]
fn check_user_email_unique_passes_for_distinct_emails() {
    let mut s = SeenSnapshot::default();
    let r1 = check_user_email_unique_per_tenant("users",
        &serde_json::json!({"email":"alice@x","tenant_id":"t-1"}), &mut s);
    let r2 = check_user_email_unique_per_tenant("users",
        &serde_json::json!({"email":"bob@x","tenant_id":"t-1"}), &mut s);
    assert!(r1.is_none());
    assert!(r2.is_none());
}

#[test]
fn check_user_email_unique_flags_duplicate_within_tenant() {
    let mut s = SeenSnapshot::default();
    let r1 = check_user_email_unique_per_tenant("users",
        &serde_json::json!({"email":"alice@x","tenant_id":"t-1"}), &mut s);
    assert!(r1.is_none());
    let r2 = check_user_email_unique_per_tenant("users",
        &serde_json::json!({"email":"alice@x","tenant_id":"t-1"}), &mut s);
    let reason = r2.expect("duplicate must be flagged");
    assert!(reason.contains("duplicates an earlier user"));
    assert!(reason.contains("alice@x"));
    assert!(reason.contains("t-1"));
}

#[test]
fn check_user_email_unique_allows_same_email_in_different_tenants() {
    // Per-tenant uniqueness, not global uniqueness. The
    // schema permits the same email in two distinct tenants.
    let mut s = SeenSnapshot::default();
    let r1 = check_user_email_unique_per_tenant("users",
        &serde_json::json!({"email":"alice@x","tenant_id":"t-1"}), &mut s);
    let r2 = check_user_email_unique_per_tenant("users",
        &serde_json::json!({"email":"alice@x","tenant_id":"t-2"}), &mut s);
    assert!(r1.is_none());
    assert!(r2.is_none(), "same email in distinct tenants must pass");
}

#[test]
fn check_user_email_unique_is_case_insensitive() {
    // cesauth's schema declares email UNIQUE COLLATE NOCASE.
    // The check must mirror that semantic.
    let mut s = SeenSnapshot::default();
    let r1 = check_user_email_unique_per_tenant("users",
        &serde_json::json!({"email":"Alice@example.COM","tenant_id":"t-1"}), &mut s);
    assert!(r1.is_none());
    let r2 = check_user_email_unique_per_tenant("users",
        &serde_json::json!({"email":"alice@example.com","tenant_id":"t-1"}), &mut s);
    assert!(r2.is_some(), "case difference must NOT escape the check");
}

#[test]
fn check_user_email_unique_skips_users_without_email() {
    // Anonymous users have no email; the check must not
    // panic or flag them. The first row sets up the tenant;
    // the second is anonymous (no email field).
    let mut s = SeenSnapshot::default();
    let r = check_user_email_unique_per_tenant("users",
        &serde_json::json!({"id":"u-anon","tenant_id":"t-1"}), &mut s);
    assert!(r.is_none(), "missing email field must not trigger the check");
}

#[test]
fn import_flags_duplicate_email_within_tenant() {
    // End-to-end through the import driver. Two users in the
    // same tenant with the same email — the second is
    // flagged.
    let tables = ["tenants", "users"];
    let rows = vec![
        ("tenants", serde_json::json!({"id":"t-1"})),
        ("users",   serde_json::json!({"id":"u-1","tenant_id":"t-1","email":"alice@x"})),
        ("users",   serde_json::json!({"id":"u-2","tenant_id":"t-1","email":"alice@x"})),
    ];
    let mut cursor = build_dump(&tables, rows, None);
    let mut sink = VecSink::new();
    let report = run_import(&mut cursor, &mut sink,
        default_invariant_checks(), false).unwrap();
    assert!(!report.is_clean());
    // Find the email violation specifically — other checks
    // shouldn't fire on this fixture.
    let email_v = report.violations.iter()
        .find(|v| v.reason.contains("duplicates"))
        .expect("email-uniqueness violation should be present");
    assert_eq!(email_v.row_id, "u-2");
    assert_eq!(email_v.table, "users");
}

