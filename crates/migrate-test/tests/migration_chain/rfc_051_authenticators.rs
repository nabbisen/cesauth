//! Originally part of `crates/migrate-test/tests/migration_chain.rs`.
//! Split into a sibling file in v0.77.0 (test-file modularization track).

use rusqlite::Connection;
use super::common::*;

// RFC 051 — 0020: authenticators.tenant_id added
// ---------------------------------------------------------------------------

#[test]
fn authenticators_has_tenant_id_after_0020() {
    let conn = apply_all_migrations().unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    let now = 1_700_000_000i64;

    // Create a user first so FK holds
    conn.execute(
        "INSERT INTO users (id, tenant_id, email_verified, account_type, status, created_at, updated_at)
         VALUES ('u-auth-t', 'tenant-default', 0, 'human_user', 'active', ?1, ?1)",
        rusqlite::params![now],
    ).unwrap();

    // Authenticator insert MUST include tenant_id now
    conn.execute(
        "INSERT INTO authenticators
           (id, user_id, tenant_id, credential_id, public_key, sign_count, created_at)
         VALUES ('aut-1', 'u-auth-t', 'tenant-default', 'cred-123', X'deadbeef', 0, ?1)",
        rusqlite::params![now],
    ).expect("authenticator insert with tenant_id must succeed after 0020");
}

#[test]
fn authenticators_tenant_index_exists_after_0020() {
    let conn = apply_all_migrations().unwrap();
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master
         WHERE type='index' AND name='idx_authenticators_tenant'",
        [], |row| row.get(0),
    ).unwrap();
    assert!(count > 0, "idx_authenticators_tenant must exist after 0020");
}
