//! Originally part of `crates/migrate-test/tests/migration_chain.rs`.
//! Split into a sibling file in v0.77.0 (test-file modularization track).

use rusqlite::Connection;
use super::common::*;

// RFC 023 — Test 9: cross-tenant group→organization reference is rejected
// ---------------------------------------------------------------------------

#[test]
fn cross_tenant_group_organization_reference_rejected() {
    let conn = apply_all_migrations().unwrap();
    // Enable FK enforcement for this connection (already done in apply, but be explicit).
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    let now = 1_700_000_000_i64;

    // Create two tenants.
    conn.execute(
        "INSERT OR IGNORE INTO tenants (id, slug, display_name, status, created_at, updated_at)
         VALUES ('t1', 't1', 'Tenant One',   'active', ?1, ?1)",
        rusqlite::params![now],
    ).unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO tenants (id, slug, display_name, status, created_at, updated_at)
         VALUES ('t2', 't2', 'Tenant Two',   'active', ?1, ?1)",
        rusqlite::params![now],
    ).unwrap();

    // An organization in tenant T1.
    conn.execute(
        "INSERT INTO organizations (id, tenant_id, slug, display_name, status, created_at, updated_at)
         VALUES ('org-t1', 't1', 'org-t1', 'Org T1', 'active', ?1, ?1)",
        rusqlite::params![now],
    ).unwrap();

    // A group in tenant T2 that tries to reference the T1 organization.
    // The composite FK (t2, org-t1) must not find a row in
    // organizations(tenant_id='t2', id='org-t1') → constraint violation.
    let result = conn.execute(
        "INSERT INTO groups (id, tenant_id, parent_kind, organization_id, slug, display_name, status, created_at, updated_at)
         VALUES ('grp-cross', 't2', 'organization', 'org-t1', 'cross', 'Cross', 'active', ?1, ?1)",
        rusqlite::params![now],
    );

    assert!(
        result.is_err(),
        "a group in tenant T2 referencing an organization in tenant T1 must be \
         rejected by the composite FK constraint (RFC 023)"
    );
}

// ---------------------------------------------------------------------------
// RFC 023 — Test 10: same-tenant group→organization reference is accepted
// ---------------------------------------------------------------------------

#[test]
fn same_tenant_group_organization_reference_accepted() {
    let conn = apply_all_migrations().unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    let now = 1_700_000_000_i64;

    conn.execute(
        "INSERT OR IGNORE INTO tenants (id, slug, display_name, status, created_at, updated_at)
         VALUES ('t-ok', 't-ok', 'Tenant OK', 'active', ?1, ?1)",
        rusqlite::params![now],
    ).unwrap();

    conn.execute(
        "INSERT INTO organizations (id, tenant_id, slug, display_name, status, created_at, updated_at)
         VALUES ('org-ok', 't-ok', 'org-ok', 'Org OK', 'active', ?1, ?1)",
        rusqlite::params![now],
    ).unwrap();

    conn.execute(
        "INSERT INTO groups (id, tenant_id, parent_kind, organization_id, slug, display_name, status, created_at, updated_at)
         VALUES ('grp-ok', 't-ok', 'organization', 'org-ok', 'grp', 'Group OK', 'active', ?1, ?1)",
        rusqlite::params![now],
    ).expect("same-tenant group→org reference must be accepted");
}

// ---------------------------------------------------------------------------
