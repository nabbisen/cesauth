//! Originally part of `crates/migrate-test/tests/migration_chain.rs`.
//! Split into a sibling file in v0.77.0 (test-file modularization track).

use rusqlite::Connection;
use super::common::*;

// RFC 032 — 0016 repair migration: COLLATE NOCASE survives
// ---------------------------------------------------------------------------

#[test]
fn repair_migration_collate_nocase_survives_full_chain() {
    // After applying the full chain (including 0016), email uniqueness
    // must be case-insensitive — same invariant as the RFC 020 test,
    // but now also validates that 0016 does not break a clean install.
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000_i64;
    conn.execute(
        "INSERT INTO users (id, tenant_id, email, email_verified, account_type, status, created_at, updated_at)
         VALUES ('u-r1', 'tenant-default', 'Repair@test.com', 0, 'human_user', 'active', ?1, ?1)",
        rusqlite::params![now],
    ).expect("first insert");

    let result = conn.execute(
        "INSERT INTO users (id, tenant_id, email, email_verified, account_type, status, created_at, updated_at)
         VALUES ('u-r2', 'tenant-default', 'repair@test.com', 0, 'human_user', 'active', ?1, ?1)",
        rusqlite::params![now],
    );
    assert!(result.is_err(),
        "after 0016: COLLATE NOCASE must reject case-variant of existing email");
}

#[test]
fn repair_migration_authenticators_fk_points_at_users() {
    let conn = apply_all_migrations().unwrap();
    let mut stmt = conn.prepare("PRAGMA foreign_key_list(authenticators)").unwrap();
    let tables: Vec<String> = stmt.query_map([], |row| row.get::<_, String>(2))
        .unwrap().filter_map(|r| r.ok()).collect();
    assert!(tables.iter().all(|t| t != "users_pre_0004" && t != "users_pre_0016"),
        "authenticators FK must not reference any pre_NNNN table: {:?}", tables);
    assert!(tables.iter().any(|t| t == "users"),
        "authenticators FK must reference `users`: {:?}", tables);
}

// ---------------------------------------------------------------------------
// RFC 037 — groups FK is RESTRICT (hard delete of org/group is refused)
// ---------------------------------------------------------------------------

#[test]
fn groups_fk_on_delete_is_restrict_not_set_null() {
    // Verify that attempting to hard-delete a referenced organization
    // is rejected (RESTRICT), not silently corrupting tenant_id.
    let conn = apply_all_migrations().unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    let now = 1_700_000_000_i64;

    conn.execute(
        "INSERT OR IGNORE INTO tenants (id, slug, display_name, status, created_at, updated_at)
         VALUES ('t-r', 't-r', 'T', 'active', ?1, ?1)",
        rusqlite::params![now],
    ).unwrap();
    conn.execute(
        "INSERT INTO organizations (id, tenant_id, slug, display_name, status, created_at, updated_at)
         VALUES ('org-r', 't-r', 'org-r', 'Org', 'active', ?1, ?1)",
        rusqlite::params![now],
    ).unwrap();
    conn.execute(
        "INSERT INTO groups (id, tenant_id, parent_kind, organization_id, slug, display_name, status, created_at, updated_at)
         VALUES ('grp-r', 't-r', 'organization', 'org-r', 'grp', 'Grp', 'active', ?1, ?1)",
        rusqlite::params![now],
    ).unwrap();

    // Hard delete the referenced organization — must be REJECTED (RESTRICT).
    let result = conn.execute("DELETE FROM organizations WHERE id = 'org-r'", []);
    assert!(
        result.is_err(),
        "hard delete of referenced organization must fail with RESTRICT FK"
    );
}

// ---------------------------------------------------------------------------
// RFC 043 — 0018: invitation_tokens table exists
// ---------------------------------------------------------------------------

#[test]
fn invitation_tokens_table_exists_after_0018() {
    let conn = apply_all_migrations().unwrap();
    // Should be able to insert a minimal row.
    let now = 1_700_000_000i64;
    conn.execute(
        "INSERT INTO invitation_tokens
           (id, tenant_id, email, role, issued_by, issued_at, expires_at)
         VALUES ('inv-1', 'tenant-default', 'alice@test.com', 'member', 'admin-1', ?1, ?1 + 259200)",
        rusqlite::params![now],
    ).expect("invitation_tokens insert should succeed after 0018");
}

#[test]
fn invitation_tokens_unique_pending_per_email_tenant() {
    let conn = apply_all_migrations().unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    let now = 1_700_000_000i64;

    conn.execute(
        "INSERT INTO invitation_tokens
           (id, tenant_id, email, role, issued_by, issued_at, expires_at)
         VALUES ('inv-a', 'tenant-default', 'bob@test.com', 'member', 'admin-1', ?1, ?1 + 259200)",
        rusqlite::params![now],
    ).unwrap();

    // Second pending invite for same tenant+email must be rejected.
    let result = conn.execute(
        "INSERT INTO invitation_tokens
           (id, tenant_id, email, role, issued_by, issued_at, expires_at)
         VALUES ('inv-b', 'tenant-default', 'bob@test.com', 'admin', 'admin-1', ?1, ?1 + 259200)",
        rusqlite::params![now],
    );
    assert!(result.is_err(),
        "unique index must prevent two pending invitations for the same email in the same tenant");
}

// ---------------------------------------------------------------------------
// RFC 044 — 0019: deletion_requests table exists
// ---------------------------------------------------------------------------

#[test]
fn deletion_requests_table_exists_after_0019() {
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000i64;
    conn.execute(
        "INSERT INTO deletion_requests
           (id, user_id, tenant_id, requested_at, requested_by, scheduled_at, status)
         VALUES ('del-1', 'u-ghost', 'tenant-default', ?1, 'u-ghost', ?1 + 2592000, 'pending')",
        rusqlite::params![now],
    ).expect("deletion_requests insert should succeed after 0019");
}

#[test]
fn deletion_requests_unique_pending_per_user() {
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000i64;
    conn.execute(
        "INSERT INTO deletion_requests
           (id, user_id, tenant_id, requested_at, requested_by, scheduled_at, status)
         VALUES ('del-x', 'u-double', 'tenant-default', ?1, 'u-double', ?1 + 2592000, 'pending')",
        rusqlite::params![now],
    ).unwrap();

    let result = conn.execute(
        "INSERT INTO deletion_requests
           (id, user_id, tenant_id, requested_at, requested_by, scheduled_at, status)
         VALUES ('del-y', 'u-double', 'tenant-default', ?1, 'admin', ?1 + 2592000, 'pending')",
        rusqlite::params![now],
    );
    assert!(result.is_err(),
        "unique index must prevent two pending deletion requests for the same user");
}

// ---------------------------------------------------------------------------
