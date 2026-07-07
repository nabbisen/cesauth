//! Originally part of `crates/core/src/migrate/tests.rs` (a single
//! 1,154-line `mod tests { ... }` block). Split into a sibling
//! file in v0.77.0 — test-file modularization (continuation of
//! v0.75.0–v0.76.0 maintenance track).

use super::*;            // reaches the parent `mod tests` (sample_manifest, etc.)
use super::super::*;     // reaches `migrate` (Manifest, FORMAT_VERSION, etc.)

// -----------------------------------------------------------------
// Redaction (v0.20.0)
// -----------------------------------------------------------------

#[test]
fn apply_redaction_hashed_email_is_deterministic() {
    // Hashing the same source email twice must produce the
    // same redacted value. Without this, re-exporting the same
    // database would produce diff-noise in the dump and break
    // any "did the dump change" check operators rely on.
    let p = lookup_profile("prod-to-staging").unwrap();
    let mut row1 = serde_json::json!({"email": "alice@example.com"});
    let mut row2 = serde_json::json!({"email": "alice@example.com"});
    apply_redaction(p, "users", &mut row1);
    apply_redaction(p, "users", &mut row2);
    assert_eq!(row1, row2);
    // Format check: anon-XXXXXXXX@example.invalid
    let s = row1["email"].as_str().unwrap();
    assert!(s.starts_with("anon-"));
    assert!(s.ends_with("@example.invalid"));
}

#[test]
fn apply_redaction_hashed_email_distinguishes_distinct_emails() {
    // The whole point of HashedEmail is to preserve UNIQUE
    // across redaction. Two distinct source emails must
    // produce distinct redacted values.
    let p = lookup_profile("prod-to-staging").unwrap();
    let mut a = serde_json::json!({"email": "alice@example.com"});
    let mut b = serde_json::json!({"email": "bob@example.com"});
    apply_redaction(p, "users", &mut a);
    apply_redaction(p, "users", &mut b);
    assert_ne!(a["email"], b["email"]);
}

#[test]
fn apply_redaction_static_string_is_uniform() {
    // For display_name, all rows collapse to "[redacted]".
    // That's intentional — display_name has no UNIQUE
    // constraint, and uniformity makes the dump diff-clean
    // in unrelated columns.
    let p = lookup_profile("prod-to-staging").unwrap();
    let mut a = serde_json::json!({"display_name": "Alice"});
    let mut b = serde_json::json!({"display_name": "Bob"});
    apply_redaction(p, "users", &mut a);
    apply_redaction(p, "users", &mut b);
    assert_eq!(a["display_name"], "[redacted]");
    assert_eq!(b["display_name"], "[redacted]");
}

#[test]
fn apply_redaction_skips_unmatched_table() {
    // A profile that targets `users` must not transform
    // rows from `tenants`, even if the column name happens
    // to match. The rule is `(table, column)` keyed.
    let p = lookup_profile("prod-to-staging").unwrap();
    // tenants doesn't have email but try with display_name
    // which exists on users in prod-to-staging.
    let mut row = serde_json::json!({"display_name": "Acme Corp"});
    apply_redaction(p, "tenants", &mut row);
    assert_eq!(row["display_name"], "Acme Corp",
        "tenants.display_name must NOT be redacted by users-targeted rules");
}

#[test]
fn apply_redaction_preserves_unrelated_columns() {
    // Columns not mentioned by the profile pass through.
    let p = lookup_profile("prod-to-staging").unwrap();
    let mut row = serde_json::json!({
        "id": "u-1",
        "email": "alice@example.com",
        "tenant_id": "tenant-default",
    });
    apply_redaction(p, "users", &mut row);
    assert_eq!(row["id"], "u-1");
    assert_eq!(row["tenant_id"], "tenant-default");
    // Email transformed.
    assert!(row["email"].as_str().unwrap().contains("@example.invalid"));
}

#[test]
fn apply_redaction_null_kind_drops_value() {
    // The Null kind sets the value to JSON null. Used for
    // optional columns that don't carry invariants.
    let p = lookup_profile("prod-to-dev").unwrap();
    let mut row = serde_json::json!({"name": "ops-2026-01"});
    apply_redaction(p, "admin_tokens", &mut row);
    assert_eq!(row["name"], serde_json::Value::Null);
}

