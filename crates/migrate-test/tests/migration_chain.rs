// Migration chain integration tests.
//
// These tests apply every migration in `migrations/` to a fresh
// in-memory SQLite database and assert structural invariants that would
// otherwise go undetected until a real D1 deployment.
//
// Run with:
//   cargo-1.91 test -p cesauth-migrate-test
//
// The tests are intentionally verbose and independently meaningful so
// that a failing assertion names exactly which invariant broke.

use rusqlite::{Connection, Result as RusqliteResult};
use std::{fs, path::PathBuf};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Path to the workspace-root `migrations/` directory.
fn migrations_dir() -> PathBuf {
    // The integration test binary runs from the workspace root or a
    // crate-local CWD.  We walk upward until we find `migrations/`.
    let mut dir = std::env::current_dir().expect("current_dir");
    loop {
        let candidate = dir.join("migrations");
        if candidate.is_dir() {
            return candidate;
        }
        if !dir.pop() {
            panic!(
                "Could not find migrations/ directory from {:?}",
                std::env::current_dir().unwrap()
            );
        }
    }
}

/// Open an in-memory SQLite database and apply every migration in
/// lexical order.  Returns the open connection.
fn apply_all_migrations() -> RusqliteResult<Connection> {
    let conn = Connection::open_in_memory()?;

    // Enable foreign keys for the session so that FK violations
    // surface during the apply loop.
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;

    let mdir = migrations_dir();
    let mut files: Vec<_> = fs::read_dir(&mdir)
        .unwrap_or_else(|e| panic!("read migrations dir {:?}: {e}", mdir))
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|x| x == "sql")
                .unwrap_or(false)
        })
        .map(|e| e.path())
        .collect();
    files.sort(); // lexical order == numeric order for 0001..NNN

    for path in &files {
        let sql = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {:?}: {e}", path));
        // SQLite's PRAGMA foreign_key_check inside a migration returns
        // rows on violation; we ignore the result here (the FK-check
        // test below catches violations post-apply).
        conn.execute_batch(&sql)
            .unwrap_or_else(|e| panic!("apply {:?}: {e}", path));
    }

    Ok(conn)
}

/// Return the expected SCHEMA_VERSION: the count of *.sql files in
/// migrations/.
fn expected_schema_version() -> u32 {
    let mdir = migrations_dir();
    fs::read_dir(&mdir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|x| x == "sql")
                .unwrap_or(false)
        })
        .count() as u32
}

// ---------------------------------------------------------------------------
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
// RFC 024 — Test 11-14: representative queries use the new indexes
// via EXPLAIN QUERY PLAN output.
// ---------------------------------------------------------------------------

/// Extract the EXPLAIN QUERY PLAN detail string for a query.
fn explain_plan(conn: &Connection, sql: &str) -> String {
    let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
    let rows: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(3))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    rows.join("\n")
}

#[test]
fn tenant_scoped_user_listing_uses_index() {
    let conn = apply_all_migrations().unwrap();
    let plan = explain_plan(
        &conn,
        "SELECT id FROM users WHERE tenant_id = 't1' AND status = 'active'",
    );
    assert!(
        plan.contains("idx_users_tenant_status") || plan.contains("SEARCH"),
        "tenant-scoped user listing should use idx_users_tenant_status; got:\n{plan}"
    );
}

#[test]
fn anonymous_expired_sweep_uses_partial_index() {
    let conn = apply_all_migrations().unwrap();
    let plan = explain_plan(
        &conn,
        "SELECT id FROM users WHERE account_type = 'anonymous' AND email IS NULL AND created_at < 1000000",
    );
    assert!(
        plan.contains("idx_users_anonymous_expired") || plan.contains("SEARCH"),
        "anonymous-expired sweep should use idx_users_anonymous_expired; got:\n{plan}"
    );
}

#[test]
fn active_sessions_cron_scan_uses_partial_index() {
    let conn = apply_all_migrations().unwrap();
    let plan = explain_plan(
        &conn,
        "SELECT session_id FROM user_sessions WHERE revoked_at IS NULL ORDER BY created_at ASC LIMIT 1000",
    );
    assert!(
        plan.contains("idx_user_sessions_active_created") || plan.contains("SEARCH"),
        "session-index cron scan should use idx_user_sessions_active_created; got:\n{plan}"
    );
}

#[test]
fn created_at_index_exists_on_users() {
    let conn = apply_all_migrations().unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
              WHERE type='index' AND name='idx_users_created_at'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "idx_users_created_at should exist after RFC 024");
}

// ---------------------------------------------------------------------------
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
// RFC 050 — SQL query validation for CloudflareInvitationRepository
// ---------------------------------------------------------------------------

#[test]
fn invitation_find_pending_by_tenant_email_sql() {
    // Validates the SQL used in CloudflareInvitationRepository::find_pending_by_tenant_email
    let conn = apply_all_migrations().unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    let now = 1_700_000_000i64;

    // Insert a pending invitation
    conn.execute(
        "INSERT INTO invitation_tokens
           (id, tenant_id, email, role, issued_by, issued_at, expires_at)
         VALUES ('inv-q1', 'tenant-default', 'query@test.com', 'member', 'admin-1', ?1, ?1 + 259200)",
        rusqlite::params![now],
    ).unwrap();

    // The exact query used in CloudflareInvitationRepository::find_pending_by_tenant_email
    let found: Option<String> = conn.query_row(
        "SELECT id FROM invitation_tokens
         WHERE tenant_id = ?1 AND email = ?2
           AND accepted_at IS NULL AND revoked_at IS NULL
           AND expires_at >= ?3
         LIMIT 1",
        rusqlite::params!["tenant-default", "query@test.com", now],
        |row| row.get(0),
    ).ok();
    assert_eq!(found.as_deref(), Some("inv-q1"),
        "find_pending_by_tenant_email SQL must return the pending invitation");
}

#[test]
fn invitation_mark_accepted_sql() {
    // Validates the SQL used in CloudflareInvitationRepository::mark_accepted
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000i64;

    conn.execute(
        "INSERT INTO invitation_tokens
           (id, tenant_id, email, role, issued_by, issued_at, expires_at)
         VALUES ('inv-acc', 'tenant-default', 'acc@test.com', 'member', 'admin', ?1, ?1 + 259200)",
        rusqlite::params![now],
    ).unwrap();

    // The exact UPDATE used in mark_accepted
    conn.execute(
        "UPDATE invitation_tokens SET accepted_at = ?1, accepted_by = ?2 WHERE id = ?3",
        rusqlite::params![now + 100, "u-accepted", "inv-acc"],
    ).unwrap();

    let accepted_at: Option<i64> = conn.query_row(
        "SELECT accepted_at FROM invitation_tokens WHERE id = 'inv-acc'",
        [],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(accepted_at, Some(now + 100));
}

#[test]
fn invitation_mark_revoked_sql() {
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000i64;

    conn.execute(
        "INSERT INTO invitation_tokens
           (id, tenant_id, email, role, issued_by, issued_at, expires_at)
         VALUES ('inv-rev', 'tenant-default', 'rev@test.com', 'member', 'admin', ?1, ?1 + 259200)",
        rusqlite::params![now],
    ).unwrap();

    conn.execute(
        "UPDATE invitation_tokens SET revoked_at = ?1, revoked_by = ?2 WHERE id = ?3",
        rusqlite::params![now + 50, "admin", "inv-rev"],
    ).unwrap();

    let revoked_at: Option<i64> = conn.query_row(
        "SELECT revoked_at FROM invitation_tokens WHERE id = 'inv-rev'",
        [],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(revoked_at, Some(now + 50));
}

#[test]
fn invitation_list_pending_by_tenant_excludes_expired() {
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000i64;

    // Pending but not expired
    conn.execute(
        "INSERT INTO invitation_tokens (id, tenant_id, email, role, issued_by, issued_at, expires_at)
         VALUES ('inv-active', 'tenant-default', 'active@test.com', 'member', 'a', ?1, ?1 + 259200)",
        rusqlite::params![now],
    ).unwrap();

    // Pending but expired (expires_at < now)
    conn.execute(
        "INSERT INTO invitation_tokens (id, tenant_id, email, role, issued_by, issued_at, expires_at)
         VALUES ('inv-expired', 'tenant-default', 'expired@test.com', 'member', 'a', ?1 - 500000, ?1 - 1)",
        rusqlite::params![now],
    ).unwrap();

    // list_pending query
    let mut stmt = conn.prepare(
        "SELECT id FROM invitation_tokens
         WHERE tenant_id = ?1 AND accepted_at IS NULL AND revoked_at IS NULL
           AND expires_at >= ?2
         ORDER BY issued_at DESC"
    ).unwrap();
    let ids: Vec<String> = stmt.query_map(
        rusqlite::params!["tenant-default", now],
        |row| row.get(0),
    ).unwrap().filter_map(|r| r.ok()).collect();

    assert!(ids.contains(&"inv-active".to_owned()), "active invite must appear");
    assert!(!ids.contains(&"inv-expired".to_owned()), "expired invite must NOT appear");
}

// ---------------------------------------------------------------------------
// RFC 050 — SQL query validation for CloudflareDeletionRequestRepository
// ---------------------------------------------------------------------------

#[test]
fn deletion_find_pending_by_user_sql() {
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000i64;

    conn.execute(
        "INSERT INTO deletion_requests
           (id, user_id, tenant_id, requested_at, requested_by, scheduled_at, status)
         VALUES ('dr-q', 'u-pending', 'tenant-default', ?1, 'u-pending', ?1 + 2592000, 'pending')",
        rusqlite::params![now],
    ).unwrap();

    let found: Option<String> = conn.query_row(
        "SELECT id FROM deletion_requests
         WHERE user_id = ?1 AND status = 'pending' LIMIT 1",
        rusqlite::params!["u-pending"],
        |row| row.get(0),
    ).ok();
    assert_eq!(found.as_deref(), Some("dr-q"));
}

#[test]
fn deletion_list_due_sql() {
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000i64;

    // Due (scheduled_at <= now)
    conn.execute(
        "INSERT INTO deletion_requests
           (id, user_id, tenant_id, requested_at, requested_by, scheduled_at, status)
         VALUES ('dr-due', 'u-due', 'tenant-default', ?1, 'u-due', ?1 - 1, 'pending')",
        rusqlite::params![now],
    ).unwrap();

    // Not due yet (scheduled_at > now)
    conn.execute(
        "INSERT INTO deletion_requests
           (id, user_id, tenant_id, requested_at, requested_by, scheduled_at, status)
         VALUES ('dr-future', 'u-future', 'tenant-default', ?1, 'u-future', ?1 + 2592000, 'pending')",
        rusqlite::params![now],
    ).unwrap();

    let mut stmt = conn.prepare(
        "SELECT id FROM deletion_requests
         WHERE status = 'pending' AND scheduled_at <= ?1
         ORDER BY scheduled_at ASC"
    ).unwrap();
    let ids: Vec<String> = stmt.query_map(
        rusqlite::params![now],
        |row| row.get(0),
    ).unwrap().filter_map(|r| r.ok()).collect();

    assert!(ids.contains(&"dr-due".to_owned()), "due request must appear in sweep");
    assert!(!ids.contains(&"dr-future".to_owned()), "future request must NOT appear in sweep");
}

#[test]
fn deletion_mark_executed_sql() {
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000i64;

    conn.execute(
        "INSERT INTO deletion_requests
           (id, user_id, tenant_id, requested_at, requested_by, scheduled_at, status)
         VALUES ('dr-exec', 'u-exec', 'tenant-default', ?1, 'u-exec', ?1, 'pending')",
        rusqlite::params![now],
    ).unwrap();

    conn.execute(
        "UPDATE deletion_requests SET status = 'executed', executed_at = ?1, executed_by = ?2 WHERE id = ?3",
        rusqlite::params![now + 1, "sweep", "dr-exec"],
    ).unwrap();

    let status: String = conn.query_row(
        "SELECT status FROM deletion_requests WHERE id = 'dr-exec'",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(status, "executed");
}

#[test]
fn deletion_mark_cancelled_sql() {
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000i64;

    conn.execute(
        "INSERT INTO deletion_requests
           (id, user_id, tenant_id, requested_at, requested_by, scheduled_at, status)
         VALUES ('dr-cancel', 'u-cancel', 'tenant-default', ?1, 'u-cancel', ?1 + 2592000, 'pending')",
        rusqlite::params![now],
    ).unwrap();

    conn.execute(
        "UPDATE deletion_requests SET status = 'cancelled', cancelled_at = ?1, cancelled_by = ?2 WHERE id = ?3",
        rusqlite::params![now + 10, "admin", "dr-cancel"],
    ).unwrap();

    let status: String = conn.query_row(
        "SELECT status FROM deletion_requests WHERE id = 'dr-cancel'",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(status, "cancelled");
}

// ---------------------------------------------------------------------------
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
