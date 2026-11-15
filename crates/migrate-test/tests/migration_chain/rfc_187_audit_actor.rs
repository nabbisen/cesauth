//! RFC 187 — 0021: `audit_events.actor` added.

use rusqlite::Connection;
use super::common::*;

// RFC 187 — 0021: audit_events.actor added
// ---------------------------------------------------------------------------

#[test]
fn audit_events_accepts_a_null_actor_after_0021() {
    // D2: NULL is the normal case for most rows (write_owned's default
    // is actor = subject, but a pre-0021 row, or any row written with
    // no principal at all, legitimately has NULL here).
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000i64;
    conn.execute(
        "INSERT INTO audit_events
           (id, ts, kind, subject, actor, payload, payload_hash, previous_hash, chain_hash, created_at)
         VALUES ('ev-187-null', ?1, 'test_event', 'user-1', NULL, '{}', 'h', 'p', 'c', ?1)",
        rusqlite::params![now],
    ).expect("actor must accept NULL after 0021");
}

#[test]
fn audit_events_accepts_a_non_null_actor_after_0021() {
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000i64;
    conn.execute(
        "INSERT INTO audit_events
           (id, ts, kind, subject, actor, payload, payload_hash, previous_hash, chain_hash, created_at)
         VALUES ('ev-187-actor', ?1, 'test_event', 'user-2', 'admin-1', '{}', 'h', 'p', 'c', ?1)",
        rusqlite::params![now],
    ).expect("actor must accept a value after 0021");

    let actor: Option<String> = conn.query_row(
        "SELECT actor FROM audit_events WHERE id = 'ev-187-actor'",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(actor, Some("admin-1".to_owned()));
}

#[test]
fn audit_events_actor_index_exists_after_0021() {
    let conn = apply_all_migrations().unwrap();
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master
         WHERE type='index' AND name='idx_audit_events_actor'",
        [], |row| row.get(0),
    ).unwrap();
    assert!(count > 0, "idx_audit_events_actor must exist after 0021");
}

#[test]
fn migration_0021_does_not_backfill_existing_rows() {
    // D2: no backfill, ever. RFC 187 round 2 F-3: the row this test
    // checks must actually have existed BEFORE 0021 ran — inserting
    // after `apply_all_migrations()` (every migration already applied)
    // never exercises a backfill step at all, since 0021 would already
    // be long done by the time the row appears. `apply_migrations_through`
    // stops at 0020, so the INSERT below genuinely predates 0021.
    let conn = apply_migrations_through("0020").unwrap();
    let now = 1_700_000_000i64;
    conn.execute(
        "INSERT INTO audit_events
           (id, ts, kind, subject, payload, payload_hash, previous_hash, chain_hash, created_at)
         VALUES ('ev-187-legacy', ?1, 'test_event', 'user-3', '{}', 'h', 'p', 'c', ?1)",
        rusqlite::params![now],
    ).unwrap();

    // Now apply 0021 itself (and nothing after it, since it is the last
    // migration as of this cut) over that pre-existing row.
    let sql = std::fs::read_to_string(migrations_dir().join("0021_audit_actor.sql")).unwrap();
    conn.execute_batch(&sql).unwrap();

    let actor: Option<String> = conn.query_row(
        "SELECT actor FROM audit_events WHERE id = 'ev-187-legacy'",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(actor, None, "a row that existed before 0021 must read back NULL after it, never a backfilled sentinel");
}
