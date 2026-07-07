//! Originally part of `crates/migrate-test/tests/migration_chain.rs`.
//! Split into a sibling file in v0.77.0 (test-file modularization track).

use rusqlite::Connection;
use super::common::*;

// Test 1 — full chain applies without error
// ---------------------------------------------------------------------------

#[test]
fn migration_chain_applies_to_fresh_database() {
    apply_all_migrations()
        .expect("migration chain should apply cleanly to a fresh database");
}

// ---------------------------------------------------------------------------
// Test 2 — foreign key check after full chain
// ---------------------------------------------------------------------------

#[test]
fn no_dangling_foreign_keys_after_full_chain() {
    let conn = apply_all_migrations().unwrap();

    // PRAGMA foreign_key_check returns one row per violation.
    let mut stmt = conn
        .prepare("PRAGMA foreign_key_check")
        .unwrap();
    let violations: Vec<String> = stmt
        .query_map([], |row| {
            let table: String = row.get(0)?;
            let rowid: i64 = row.get(1)?;
            let parent: String = row.get(2)?;
            let fkid: i64 = row.get(3)?;
            Ok(format!("table={table} rowid={rowid} parent={parent} fkid={fkid}"))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();

    assert!(
        violations.is_empty(),
        "foreign_key_check found violations after applying all migrations:\n{}",
        violations.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Test 3 — no FK in authenticators points at users_pre_0004
// ---------------------------------------------------------------------------

#[test]
fn authenticators_fk_does_not_reference_users_pre_0004() {
    let conn = apply_all_migrations().unwrap();

    let mut stmt = conn
        .prepare("PRAGMA foreign_key_list(authenticators)")
        .unwrap();
    let tables: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(2))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();

    for table in &tables {
        assert_ne!(
            table.as_str(),
            "users_pre_0004",
            "authenticators still has a FK pointing at users_pre_0004; \
             the 0004 child-table rebuild is missing"
        );
    }

    assert!(
        tables.iter().any(|t| t == "users"),
        "authenticators FK should reference `users` but found: {:?}",
        tables
    );
}

// ---------------------------------------------------------------------------
// Test 4 — email uniqueness is case-insensitive within a tenant
// ---------------------------------------------------------------------------

#[test]
fn email_uniqueness_is_case_insensitive_within_tenant() {
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000_i64;

    // Insert first user with mixed-case email.
    conn.execute(
        "INSERT INTO users (id, tenant_id, email, email_verified, account_type, status, created_at, updated_at)
         VALUES ('u1', 'tenant-default', 'Alice@example.com', 0, 'human_user', 'active', ?1, ?1)",
        rusqlite::params![now],
    ).expect("first insert should succeed");

    // A second insert with the same email but different case must fail.
    let result = conn.execute(
        "INSERT INTO users (id, tenant_id, email, email_verified, account_type, status, created_at, updated_at)
         VALUES ('u2', 'tenant-default', 'alice@example.com', 0, 'human_user', 'active', ?1, ?1)",
        rusqlite::params![now],
    );

    assert!(
        result.is_err(),
        "inserting 'alice@example.com' when 'Alice@example.com' already exists \
         in the same tenant must fail (COLLATE NOCASE not working)"
    );
}

// ---------------------------------------------------------------------------
// Test 5 — same email is allowed in different tenants
// ---------------------------------------------------------------------------

#[test]
fn same_email_allowed_in_different_tenants() {
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000_i64;

    // We need a second tenant row for the FK to be valid.
    conn.execute(
        "INSERT OR IGNORE INTO tenants (id, slug, display_name, status, created_at, updated_at)
         VALUES ('tenant-two', 'tenant-two', 'Tenant Two', 'active', ?1, ?1)",
        rusqlite::params![now],
    ).expect("second tenant insert");

    conn.execute(
        "INSERT INTO users (id, tenant_id, email, email_verified, account_type, status, created_at, updated_at)
         VALUES ('u1', 'tenant-default', 'alice@example.com', 0, 'human_user', 'active', ?1, ?1)",
        rusqlite::params![now],
    ).expect("first tenant user");

    conn.execute(
        "INSERT INTO users (id, tenant_id, email, email_verified, account_type, status, created_at, updated_at)
         VALUES ('u2', 'tenant-two', 'alice@example.com', 0, 'human_user', 'active', ?1, ?1)",
        rusqlite::params![now],
    ).expect("second tenant user — same email is OK in a different tenant");
}

// ---------------------------------------------------------------------------
// Test 6 — schema_meta final version matches migration file count
// ---------------------------------------------------------------------------

#[test]
fn schema_meta_version_matches_migration_count() {
    let conn = apply_all_migrations().unwrap();
    let expected = expected_schema_version();

    let actual: u32 = conn
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM schema_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .expect("schema_meta should have a schema_version row");

    assert_eq!(
        actual, expected,
        "schema_meta.schema_version ({actual}) does not match \
         the count of migration files ({expected})"
    );
}

// ---------------------------------------------------------------------------
// Test 7 — PermissionCatalog::ALL entries are all present in DB
//           (also covers RFC 022 invariant)
// ---------------------------------------------------------------------------

#[test]
fn permission_catalog_all_present_in_database() {
    let conn = apply_all_migrations().unwrap();

    for &slug in cesauth_core::authz::PermissionCatalog::ALL {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM permissions WHERE name = ?1",
                rusqlite::params![slug],
                |row| row.get(0),
            )
            .unwrap_or(0);

        assert_eq!(
            count, 1,
            "PermissionCatalog::ALL entry '{}' is missing from the \
             `permissions` table seed in migrations/",
            slug
        );
    }
}

// ---------------------------------------------------------------------------
// Test 8 — system_admin role is a superset of all other built-in roles
// ---------------------------------------------------------------------------

#[test]
fn system_admin_role_is_superset_of_all_built_in_roles() {
    let conn = apply_all_migrations().unwrap();

    // Roles store permissions as comma-separated TEXT column.
    let get_perms = |slug: &str| -> std::collections::HashSet<String> {
        let permissions: String = conn
            .query_row(
                "SELECT permissions FROM roles WHERE slug = ?1 AND tenant_id IS NULL",
                rusqlite::params![slug],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| panic!("built-in role '{slug}' not found"));
        permissions
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    let system_admin_perms = get_perms("system_admin");

    let other_roles = [
        "system_readonly",
        "tenant_admin",
        "tenant_readonly",
        "organization_admin",
        "organization_member",
    ];

    for role_slug in &other_roles {
        let perms = get_perms(role_slug);
        for perm in &perms {
            assert!(
                system_admin_perms.contains(perm),
                "system_admin is missing '{}' which is granted to '{}'",
                perm,
                role_slug
            );
        }
    }
}

// ---------------------------------------------------------------------------
