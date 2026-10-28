//! RFC 148 — the `invitation_tokens.email` scrub on account deletion.
//!
//! `CloudflareInvitationRepository::scrub_email` is WASM-only (D1), so it
//! cannot run under a host test; this module runs the literal SQL it
//! issues against a real migration chain instead — the same idiom
//! `rfc_050_sql.rs` already uses for the rest of this repository.

use rusqlite::Connection;
use super::common::*;

const SCRUB_SQL: &str =
    "UPDATE invitation_tokens \
     SET email = 'deleted-' || ?1 || '-' || id || '@invalid' \
     WHERE email = ?2";

#[test]
fn scrub_replaces_email_and_preserves_the_administrative_columns() {
    // Validates the SQL used in CloudflareInvitationRepository::scrub_email.
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000i64;

    conn.execute(
        "INSERT INTO invitation_tokens
           (id, tenant_id, email, role, issued_by, issued_at, expires_at,
            accepted_at, accepted_by, revoked_at, revoked_by)
         VALUES ('inv-scrub-1', 'tenant-default', 'Alice@Example.com', 'tenant_member',
                 'admin-1', ?1, ?1 + 259200, ?1 + 10, 'pending-registration', NULL, NULL)",
        rusqlite::params![now],
    ).unwrap();

    conn.execute(SCRUB_SQL, rusqlite::params!["req-del-1", "alice@example.com"]).unwrap();

    let (email, issued_by, issued_at, role, accepted_at, accepted_by, revoked_at, revoked_by):
        (String, String, i64, String, Option<i64>, Option<String>, Option<i64>, Option<String>) = conn.query_row(
        "SELECT email, issued_by, issued_at, role, accepted_at, accepted_by, revoked_at, revoked_by
         FROM invitation_tokens WHERE id = 'inv-scrub-1'",
        [],
        |row| Ok((
            row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?,
            row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?,
        )),
    ).unwrap();

    assert_eq!(email, "deleted-req-del-1-inv-scrub-1@invalid");
    assert_eq!(issued_by, "admin-1", "the administrative record must survive the scrub");
    assert_eq!(issued_at, now);
    assert_eq!(role, "tenant_member");
    assert_eq!(accepted_at, Some(now + 10));
    assert_eq!(accepted_by.as_deref(), Some("pending-registration"));
    assert_eq!(revoked_at, None);
    assert_eq!(revoked_by, None);
}

#[test]
fn scrub_matches_case_insensitively_and_leaves_other_addresses_untouched() {
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000i64;

    conn.execute(
        "INSERT INTO invitation_tokens (id, tenant_id, email, role, issued_by, issued_at, expires_at)
         VALUES ('inv-scrub-target', 'tenant-default', 'Bob@Example.com', 'member', 'admin', ?1, ?1 + 259200)",
        rusqlite::params![now],
    ).unwrap();
    conn.execute(
        "INSERT INTO invitation_tokens (id, tenant_id, email, role, issued_by, issued_at, expires_at)
         VALUES ('inv-scrub-other', 'tenant-default', 'carol@example.com', 'member', 'admin', ?1, ?1 + 259200)",
        rusqlite::params![now],
    ).unwrap();

    conn.execute(SCRUB_SQL, rusqlite::params!["req-del-2", "bob@example.com"]).unwrap();

    let target_email: String = conn.query_row(
        "SELECT email FROM invitation_tokens WHERE id = 'inv-scrub-target'", [],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(target_email, "deleted-req-del-2-inv-scrub-target@invalid");

    let other_email: String = conn.query_row(
        "SELECT email FROM invitation_tokens WHERE id = 'inv-scrub-other'", [],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(other_email, "carol@example.com", "an unrelated address must not be touched");
}

/// RFC 148 §5's stated reason for per-row distinctness: two invitation
/// rows scrubbed to the *same* literal tombstone can collide under the
/// partial unique index at `0018:42-44`
/// (`WHERE accepted_at IS NULL AND revoked_at IS NULL`) when both are
/// still pending in the same tenant. This demonstrates the failure a
/// non-distinct tombstone would hit, then shows the real (request id +
/// row id) scrub avoids it on the identical data.
#[test]
fn a_shared_tombstone_collides_but_the_real_scrub_does_not() {
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000i64;

    // Two different users, two different original addresses, both still
    // pending in the same tenant — exactly the shape that must not collide.
    conn.execute(
        "INSERT INTO invitation_tokens (id, tenant_id, email, role, issued_by, issued_at, expires_at)
         VALUES ('inv-collide-1', 'tenant-default', 'dave@example.com', 'member', 'admin', ?1, ?1 + 259200)",
        rusqlite::params![now],
    ).unwrap();
    conn.execute(
        "INSERT INTO invitation_tokens (id, tenant_id, email, role, issued_by, issued_at, expires_at)
         VALUES ('inv-collide-2', 'tenant-default', 'erin@example.com', 'member', 'admin', ?1, ?1 + 259200)",
        rusqlite::params![now],
    ).unwrap();

    // Does-not-fire: a naive scrub that writes the identical literal
    // email for both rows hits the partial unique index.
    conn.execute(
        "UPDATE invitation_tokens SET email = 'deleted@invalid' WHERE id = 'inv-collide-1'",
        [],
    ).unwrap();
    let naive_second_write = conn.execute(
        "UPDATE invitation_tokens SET email = 'deleted@invalid' WHERE id = 'inv-collide-2'",
        [],
    );
    assert!(naive_second_write.is_err(),
        "a non-distinct tombstone must collide under the partial unique index — \
         if this starts passing, the index or the scrub's distinctness has regressed");

    // Fires: the real scrub, keyed by request id *and* row id, succeeds
    // on the identical data (fresh rows, so the first row's prior write
    // above is irrelevant to this assertion).
    conn.execute(
        "INSERT INTO invitation_tokens (id, tenant_id, email, role, issued_by, issued_at, expires_at)
         VALUES ('inv-collide-3', 'tenant-default', 'frank@example.com', 'member', 'admin', ?1, ?1 + 259200)",
        rusqlite::params![now],
    ).unwrap();
    conn.execute(SCRUB_SQL, rusqlite::params!["req-a", "frank@example.com"]).unwrap();
    conn.execute(
        "INSERT INTO invitation_tokens (id, tenant_id, email, role, issued_by, issued_at, expires_at)
         VALUES ('inv-collide-4', 'tenant-default', 'grace@example.com', 'member', 'admin', ?1, ?1 + 259200)",
        rusqlite::params![now],
    ).unwrap();
    let real_second_write = conn.execute(SCRUB_SQL, rusqlite::params!["req-b", "grace@example.com"]);
    assert!(real_second_write.is_ok(),
        "the real scrub's per-request, per-row tombstone must not collide: {real_second_write:?}");
}

/// The motivating shape from RFC 148 §5: one deleted user has *two*
/// invitation rows in the *same* tenant sharing the *same* original
/// address — one accepted (their actual registration), one a later
/// pending re-invite. A single `execute_deletion` scrubs both in one
/// call with one `request_id`; the row id still has to separate them,
/// or the pending row's post-scrub email is not guaranteed distinct
/// from the accepted row's.
#[test]
fn one_deletion_scrubbing_two_rows_in_the_same_tenant_still_gets_distinct_tombstones() {
    let conn = apply_all_migrations().unwrap();
    let now = 1_700_000_000i64;

    conn.execute(
        "INSERT INTO invitation_tokens
           (id, tenant_id, email, role, issued_by, issued_at, expires_at, accepted_at, accepted_by)
         VALUES ('inv-same-accepted', 'tenant-default', 'heidi@example.com', 'member',
                 'admin', ?1, ?1 + 259200, ?1 + 5, 'pending-registration')",
        rusqlite::params![now],
    ).unwrap();
    conn.execute(
        "INSERT INTO invitation_tokens (id, tenant_id, email, role, issued_by, issued_at, expires_at)
         VALUES ('inv-same-pending', 'tenant-default', 'heidi@example.com', 'member', 'admin', ?1, ?1 + 259200)",
        rusqlite::params![now],
    ).unwrap();

    conn.execute(SCRUB_SQL, rusqlite::params!["req-del-3", "heidi@example.com"]).unwrap();

    let accepted_email: String = conn.query_row(
        "SELECT email FROM invitation_tokens WHERE id = 'inv-same-accepted'", [],
        |row| row.get(0),
    ).unwrap();
    let pending_email: String = conn.query_row(
        "SELECT email FROM invitation_tokens WHERE id = 'inv-same-pending'", [],
        |row| row.get(0),
    ).unwrap();

    assert_ne!(accepted_email, pending_email,
        "both rows shared one original address and one request id — only the row id tells them apart");
    assert_eq!(accepted_email, "deleted-req-del-3-inv-same-accepted@invalid");
    assert_eq!(pending_email, "deleted-req-del-3-inv-same-pending@invalid");
}
