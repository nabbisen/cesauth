# RFC 024: D1 index restoration and tuning

**Status**: Implemented
**ROADMAP**: External data-structure review v0.52.1 — P2 finding on lost indexes after `0004` rebuild and missing partial indexes for cron scans
**ADR**: N/A — index tuning, not new design
**Severity**: **P2 — query plans currently fall back to full scans for tenant-scoped user listings, anonymous-expired sweep, and global active-session scan; cost / latency grows linearly with table size**
**Estimated scope**: Small — one migration adding indexes + ~15 LOC of EXPLAIN-plan assertions in tests
**Source**: External data-structure review attached to the v0.52.1 conversation

## Background

`migrations/0001_initial.sql` defined two indexes on
the original `users` table:

```sql
CREATE INDEX idx_users_status     ON users(status);
CREATE INDEX idx_users_created_at ON users(created_at);
```

`migrations/0004_user_tenancy_backfill.sql` rebuilds
`users` and explicitly recreates only the
email-unique constraint. The `status` and
`created_at` indexes are **silently lost** — the
0004 file's narrative comment mentions email
uniqueness but does not acknowledge the dropped
indexes.

`migrations/0009_user_session_index.sql` defines
`user_sessions` with one supporting index:

```sql
CREATE INDEX user_sessions_user_idx
    ON user_sessions(user_id, created_at DESC);
```

This serves the per-user list-sessions query well.
But the session-index audit cron pass
(`crates/worker/src/session_index_audit.rs`,
v0.40.0) and the audit-retention cron
(`audit_retention_cron.rs`, v0.48.0) issue queries
of the shape:

```sql
SELECT ... FROM user_sessions
 WHERE revoked_at IS NULL
 ORDER BY created_at ASC
 LIMIT ?
```

Existing indexes do not cover this — D1 falls back
to a full table scan and an in-memory sort. At
1k–10k active sessions this is fine; at 100k+ on
larger deployments the cron-tick latency budget
matters (Cloudflare's daily cron has a 30-second
runtime cap per invocation; we need every cron pass
to run in well under that).

The anonymous-user retention sweep
(`crates/worker/src/sweep.rs`) runs:

```sql
SELECT id FROM users
 WHERE account_type = 'anonymous'
   AND email IS NULL
   AND created_at < ?
 LIMIT ?
```

No index serves this either.

## Requirements

The fix must:

1. Restore the `created_at` / `status` indexes lost
   at `0004`, in shapes appropriate for current
   queries (tenant-scoped, not global).
2. Add a partial index supporting the global
   "active sessions, oldest first" cron scan.
3. Add a partial index supporting the anonymous
   expired-user sweep.
4. Migration tests assert that representative
   queries use the new indexes via SQLite's
   `EXPLAIN QUERY PLAN`.

## Decision / Plan

### Step 1 — Migration `0014_index_restoration.sql`

```sql
-- Restore status / created_at indexes lost at 0004 rebuild.
-- Use composite shapes that match current query patterns rather
-- than literally restoring the 0001 single-column ones.

-- Tenant-scoped user listing (admin console / tenant_admin user lists).
CREATE INDEX IF NOT EXISTS idx_users_tenant_status
    ON users(tenant_id, status);

-- General created_at queries (audit search by registration window,
-- admin reports). Single-column suffices because tenant scope is
-- usually applied via a join in those queries.
CREATE INDEX IF NOT EXISTS idx_users_created_at
    ON users(created_at);

-- Anonymous-expired sweep partial index.
-- Partial because the sweep filter is narrow (anonymous + email-null);
-- non-anonymous rows would bloat the index for a query that never
-- traverses them.
CREATE INDEX IF NOT EXISTS idx_users_anonymous_expired
    ON users(created_at)
    WHERE account_type = 'anonymous' AND email IS NULL;

-- user_sessions: global active-session scan partial index for the
-- session-index audit cron and the audit-retention cron's session-
-- specific predicates.
CREATE INDEX IF NOT EXISTS idx_user_sessions_active_created
    ON user_sessions(created_at)
    WHERE revoked_at IS NULL;

-- audit_events: kind+ts partial index already exists from 0008
-- but the retention cron's per-kind delete benefits from a covering
-- form. Add only if EXPLAIN shows the existing index is insufficient
-- (deferred to Step 4 measurement).

INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '14');
```

The choice of partial indexes for `revoked_at IS
NULL` and `account_type='anonymous' AND email IS
NULL` is deliberate: SQLite materialises only the
rows matching the partial predicate, so the index
size scales with active rather than total
population. For audit-retention sweeping a million
historical session-index rows, the active-only
index stays small.

### Step 2 — Repository contract for cron queries

The `SessionIndexRepo::list_active(limit)` port
(introduced in v0.40.0) and the
`AuditEventRepository::delete_below_seq` (v0.48.0)
gain inline SQL comments pointing at the new
indexes:

```rust
// SQL (D1 adapter):
//   SELECT ... FROM user_sessions
//    WHERE revoked_at IS NULL
//    ORDER BY created_at ASC
//    LIMIT ?
//
// Index used: idx_user_sessions_active_created (RFC 024).
// Do NOT add a tenant_id filter to this query without first
// adding a (tenant_id, created_at) WHERE revoked_at IS NULL
// partial index — otherwise the planner falls back to a scan.
```

The comment is a lightweight invariant; future
modifications that break the index assumption are
caught either at PR review or at the EXPLAIN
plan test in Step 4.

### Step 3 — In-memory adapter parity

`cesauth-adapter-test`'s in-memory adapters do not
need indexes (they're `BTreeMap`-backed), but their
documented Big-O behavior on the same operations
should be expressed in test fixtures so a future
refactor touching the trait surface doesn't change
the contract.

### Step 4 — `EXPLAIN QUERY PLAN` regression tests

In `cesauth-migrate-test`:

```rust
#[test]
fn session_index_active_scan_uses_partial_index() {
    let conn = fresh_sqlite_with_all_migrations();
    let plan: Vec<String> = conn
        .prepare("EXPLAIN QUERY PLAN
                  SELECT session_id FROM user_sessions
                   WHERE revoked_at IS NULL
                   ORDER BY created_at ASC LIMIT 1000")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(3))
        .unwrap()
        .map(Result::unwrap)
        .collect();

    let plan_text = plan.join(" | ");
    assert!(
        plan_text.contains("idx_user_sessions_active_created"),
        "expected partial index to be used; got {plan_text}"
    );
    assert!(
        !plan_text.contains("USE TEMP B-TREE FOR ORDER BY"),
        "expected partial index to satisfy ORDER BY; got {plan_text}"
    );
}

#[test]
fn anonymous_sweep_uses_partial_index() { ... }

#[test]
fn tenant_user_listing_uses_composite_index() { ... }
```

These tests pin the index choice. The sole
maintenance hazard is a future SQLite version
choosing a different plan, which is rare for
deterministic queries — but if it happens, the test
fails loudly at PR time and the team decides
whether the new plan is acceptable.

## Test plan

Per Step 4. Existing tests in `cesauth-adapter-test`
exercise functional correctness; the new tests
exercise plan stability.

## Security considerations

Indexes are operational, not security-relevant
themselves. Indirect benefit: the sweep paths run
faster, completing within the 30-second cron
budget; if the budget is exceeded the sweep is
truncated, which can cause anonymous-user retention
to fall behind, which is a privacy issue (data
not deleted on its scheduled cycle). This is the
mild data-protection link.

## Open questions

1. **Does v0.52.1 need a `(client_id, created_at)`
   index on `audit_events` for client-scoped
   audit queries?** Possibly. The existing kind-
   plus-ts partial index from `0008` covers
   per-kind queries. Client-scoped queries are
   not currently a hot path; defer to operator
   feedback.

2. **Should the migration include `ANALYZE`?**
   Yes — running `ANALYZE` after creating the
   new indexes lets the SQLite planner make
   informed cost decisions. Add a final
   `ANALYZE;` statement to the migration. (D1
   supports `ANALYZE` against the user database.)

## Implementation order

1. Land RFC 020 (clean migration chain).
2. Migration `0014_index_restoration.sql`.
3. `EXPLAIN` tests in `cesauth-migrate-test`.
4. Inline SQL comments referencing the indexes
   in the D1 adapter repository implementations.
5. Single PR.

## Notes for the implementer

- D1's planner sometimes prefers temporary
  indexes for specific queries; the EXPLAIN
  tests should be tolerant of `USING INDEX
  idx_…` vs `SEARCH … USING INDEX idx_…`
  wording differences across SQLite versions
  but strict on the index name.
- Partial indexes' WHERE clause must match the
  query's WHERE clause **exactly** in SQLite
  for the partial index to be used. The query
  shapes documented in the SQL comments are
  the contract; deviating from them in
  application code silently re-introduces the
  full scan.
- `idx_users_anonymous_expired` partial
  predicate `account_type = 'anonymous' AND
  email IS NULL` precisely matches the sweep
  filter. Do not add `LIMIT` or `ORDER BY` to
  the WHERE side of the partial — they belong
  on the query side.
