//! Originally part of `crates/migrate-test/tests/migration_chain.rs`.
//! Split into a sibling file in v0.77.0 (test-file modularization track).

use rusqlite::Connection;
use super::common::*;

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
