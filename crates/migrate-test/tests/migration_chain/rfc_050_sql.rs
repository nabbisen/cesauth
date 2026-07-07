//! Originally part of `crates/migrate-test/tests/migration_chain.rs`.
//! Split into a sibling file in v0.77.0 (test-file modularization track).

use rusqlite::Connection;
use super::common::*;

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
