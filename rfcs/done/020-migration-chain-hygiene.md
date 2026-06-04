# RFC 020: Migration chain hygiene — fresh-DB construction, FK rebuild, case-insensitive email

**Status**: Implemented
**ROADMAP**: External data-structure review v0.52.1 — three P0 findings on the migration chain
**ADR**: N/A — these are corrections to existing migrations, not new design decisions
**Severity**: **P0 — fresh database construction is currently broken; existing deployments have orphaned FKs and lost case-insensitive email uniqueness**
**Estimated scope**: Medium — three migration edits + one new CI integration test crate target + ~80 LOC of test fixtures
**Source**: External data-structure review attached to the v0.52.1 conversation

## Background

The external data-structure review surfaced three
production-blocking defects in the migration chain.
Each is independently severe; together they make
the current `migrations/` directory unsafe to apply
to a fresh database and unsafe to ship as a
v1.0 candidate.

### Defect 1 — `0009_user_session_index.sql` writes to a never-created table

The migration's final statement is:

```sql
INSERT OR REPLACE INTO schema_meta (key, value)
    VALUES ('schema_version', '9');
```

Nothing in `migrations/` ever creates `schema_meta`.
A repository-wide grep finds no `CREATE TABLE …
schema_meta` statement. Applying the chain top-to-bottom
against an empty D1 database fails at `0009` with
`no such table: schema_meta`.

This is also internally inconsistent: only `0009`
attempts to update `schema_meta`. If `schema_meta` is
intended to be the canonical schema-version anchor, every
migration should write it; if it isn't, `0009` shouldn't
either. The write is dead code, but its dead-code-ness
itself causes a hard failure.

### Defect 2 — `0004_user_tenancy_backfill.sql` orphans existing FKs

`0004` rebuilds `users` via the SQLite "rename, recreate,
copy, drop" pattern:

```sql
PRAGMA foreign_keys = OFF;
ALTER TABLE users RENAME TO users_pre_0004;
CREATE TABLE users (...);
INSERT INTO users (...) SELECT ... FROM users_pre_0004;
DROP TABLE users_pre_0004;
PRAGMA foreign_keys = ON;
```

In SQLite (and therefore D1), this rebuild does NOT
update child tables' foreign-key references. After the
migration runs, `authenticators`, `consent`, and
`grants` — all created in `0001_initial.sql` with
`REFERENCES users(id)` — still hold FKs that point
at the dropped `users_pre_0004` name. New inserts
fail with `no such table: main.users_pre_0004`.

This breaks WebAuthn registration, OIDC consent storage,
and grant issuance — all core flows.

The supported SQLite recipe for table rebuild
(<https://www.sqlite.org/lang_altertable.html#otheralter>)
explicitly requires rebuilding child tables in the same
transaction.

### Defect 3 — `users.email` loses `COLLATE NOCASE` at `0004`

`0001_initial.sql` defined:

```sql
email TEXT UNIQUE COLLATE NOCASE
```

The `0004` rebuild produces:

```sql
email TEXT,
UNIQUE (tenant_id, email)
```

Two regressions are live as of v0.52.1:

- The column-level `COLLATE NOCASE` clause is gone.
- The new composite `UNIQUE (tenant_id, email)` does
  not specify a collation, so it compares
  byte-for-byte.

Meanwhile `cesauth_core::ports::repo::UserRepository`
(`crates/core/src/ports/repo.rs`) and the Cloudflare
adapter's `find_by_email`
(`crates/adapter-cloudflare/src/ports/repo/users.rs`)
still treat email lookup as case-insensitive — the
contract is documented in comments and exercised by the
in-memory adapter's tests.

Effect: within one tenant, both `Alice@example.com`
and `alice@example.com` can be inserted as distinct
rows. Magic Link will issue codes against whichever
row is hit first; OIDC `sub` for the "same" person
varies between sessions; the audit log loses subject
identity.

## Requirements

The fix must:

1. Make the migration chain apply cleanly against a
   fresh D1 (or in-memory SQLite shaped like D1).
2. After any subset of `0001..=N` applies, child-table
   foreign keys must reference a live table named
   `users` — verified by `PRAGMA foreign_key_check`.
3. After `0004` runs, an attempt to insert
   `(tenant_id=T, email='alice@example.com')` must
   fail when `(tenant_id=T, email='Alice@example.com')`
   already exists.
4. CI must run the migration chain against a fresh
   database on every PR and main-branch push, with
   the foreign-key invariants and email-uniqueness
   invariants pinned as automated tests.

## Decision / Plan

The project has not yet shipped a 1.0; the migration
chain is a development artifact, not a public contract.
**The cheapest correct fix is to repair the existing
migrations in place** rather than add `0011…0013`
patches on top.

The trade-off: any deployment that has already applied
`0001..0010` from a prior tarball will need the schema
checked and, if drifted, manually reconciled. That is
acceptable because:

- The user-facing surface for `cesauth-migrate
  refresh-staging` re-creates the schema from scratch
  on the destination, so prod→staging refresh paths
  self-heal on first use after the fix.
- The README's project status acknowledges the public
  surface (including schema) may change between minor
  versions.
- Operators with established prod data should run the
  upgrade procedure in §"Upgrade procedure" before
  deploying.

If a future minor release establishes a stable schema
contract, this RFC's repair must happen *before* that
release; making schema corrections post-1.0 would be
materially harder.

### Step 1 — Add `schema_meta` to `0001_initial.sql` and write to it consistently

Add to the top of `0001_initial.sql`:

```sql
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

At the end of `0001_initial.sql`:

```sql
INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '1');
```

Add the equivalent `INSERT OR REPLACE` at the end of
every existing migration `0002..=0010` with the
appropriate version number. The unconditional
`schema_meta` table existence makes the writes
non-failing across the chain.

Rationale: making every migration update the version
makes the version meaningful — operators querying
`schema_meta` get the actual applied version, not the
"highest known by 0009" snapshot.

### Step 2 — Rewrite `0004_user_tenancy_backfill.sql` to rebuild child tables

Inside the same `PRAGMA foreign_keys = OFF` block, do
the SQLite-recommended sequence:

```sql
PRAGMA foreign_keys = OFF;

-- Rebuild users (existing logic, plus COLLATE NOCASE restoration; see Step 3).

ALTER TABLE authenticators RENAME TO authenticators_pre_0004;
CREATE TABLE authenticators (...same columns... REFERENCES users(id));
INSERT INTO authenticators SELECT ... FROM authenticators_pre_0004;
DROP TABLE authenticators_pre_0004;

-- Same for consent and grants.

PRAGMA foreign_key_check;  -- aborts the migration if any FK is dangling.

PRAGMA foreign_keys = ON;
```

The `PRAGMA foreign_key_check` inside the migration is
defense in depth: if a future contributor adds a child
table without updating this migration, the rebuild
aborts immediately on a fresh apply rather than
shipping orphaned FKs to production.

### Step 3 — Restore case-insensitive email uniqueness

In the `0004` `users` recreation, change the column
definition and the unique constraint:

```sql
email TEXT COLLATE NOCASE,
...
UNIQUE (tenant_id, email)
```

Because the column carries `COLLATE NOCASE`, the unique
index inherits that collation per SQLite's docs
(<https://www.sqlite.org/datatype3.html#collation>).
No explicit `COLLATE` on the constraint is needed —
but for unambiguous reading, also add a separate
helper unique index:

```sql
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_email_ci
    ON users(tenant_id, email COLLATE NOCASE)
    WHERE email IS NOT NULL;
```

The `WHERE email IS NOT NULL` partial index lets
anonymous users (which carry `email IS NULL` per
ADR-004 §Q3) coexist without a unique conflict.

Also: update the `find_by_email` SQL in the
Cloudflare adapter to be explicit about its expectation:

```sql
WHERE tenant_id = ?1 AND email = ?2 COLLATE NOCASE
```

The explicit `COLLATE NOCASE` in the WHERE clause makes
the intent visible at the query site, so a future
schema change that drops the column collation produces
a logical bug rather than a silent misbehavior.

### Step 4 — Add a `cesauth-migrate-test` integration target

Create a new test target — either `crates/migrate/tests/`
integration tests or a `cesauth_test_migrations` crate
in the workspace — that, on a fresh in-memory SQLite
(via `rusqlite` with `feature = "bundled"`):

1. Reads every file in `migrations/` in lexical order
   and applies it.
2. After each migration, runs `PRAGMA foreign_key_check`
   and asserts the result is empty.
3. After the full chain, runs `PRAGMA
   foreign_key_list(authenticators)` and asserts no
   row references `users_pre_0004` (defensive against
   accidental re-introduction of the bug).
4. Asserts that `INSERT INTO users (..., email='Alice@example.com')`
   followed by `INSERT INTO users (..., email='alice@example.com')`
   in the same tenant fails on the second insert.
5. Asserts every permission name in
   `cesauth_core::authz::PermissionCatalog::ALL` is
   present in `permissions.name`. (This catches the
   RFC 022 gap.)
6. Asserts `schema_meta` final value matches the
   integer count of `migrations/*.sql` files.

The test runs on the host (not WASM); CI gates on
`cargo test -p cesauth-migrate-test`.

This crate is the strongest part of the RFC: every
future migration regression in this class is caught at
PR time without operator intervention.

### Step 5 — Document the upgrade procedure for existing deployments

`docs/src/deployment/data-migration.md` adds a
"v0.53.x migration repair" section with a runbook
fragment:

```sh
# 1. Take a D1 snapshot.
wrangler d1 export cesauth-prod --output=cesauth-pre-RFC020.sql

# 2. Run the diagnostics.
wrangler d1 execute cesauth-prod --command="PRAGMA foreign_key_check"
wrangler d1 execute cesauth-prod --command="PRAGMA foreign_key_list(authenticators)"

# 3. If foreign_key_list shows users_pre_0004 references, run the
#    repair script (provided as scripts/repair-0004.sql) inside a
#    single PRAGMA foreign_keys=OFF...ON block.

# 4. Verify case-insensitive uniqueness:
wrangler d1 execute cesauth-prod --command="
    SELECT tenant_id, LOWER(email), COUNT(*)
    FROM users
    WHERE email IS NOT NULL
    GROUP BY tenant_id, LOWER(email)
    HAVING COUNT(*) > 1;
"
# If any rows return, contact security: dual-account email collision.
```

`scripts/repair-0004.sql` ships in this RFC as a one-shot
recovery script that idempotently rebuilds the three
child tables.

## Test plan

- The new `cesauth-migrate-test` integration crate is the
  primary acceptance gate; CI fails the PR if any
  invariant breaks.
- Existing `cesauth-migrate` unit tests (`run_migrations`
  smoke test) should be re-run against the repaired
  migrations. A delta is expected only in
  `users_pre_0004` cleanup.
- Ad-hoc D1 verification on a real Cloudflare staging
  environment before merging — `wrangler d1 migrations
  apply` against a fresh remote database.

## Security considerations

The case-insensitive email regression has a real
authentication-equivalence implication: if two distinct
users register `Alice@example.com` and
`alice@example.com` in the same tenant, Magic Link
delivery + verify will resolve to whichever row was
created first, but the recipient mailbox is shared.
This is functionally a credential aliasing attack
surface, mitigated post-fix by the unique constraint.

Audit-log subject identity stability also depends on
this fix — RFC 010's mailer port uses the email as the
delivery handle, and a non-canonicalized email lookup
makes audit trails ambiguous.

## Open questions

1. **Should the `0004` patch include a one-shot
   normalization migration that lower-cases existing
   non-anonymous email addresses?** No. Email-address
   case can be semantically meaningful in the local
   part per RFC 5321; we only need *uniqueness up to
   case*, not a mutation of stored data. The repair
   runbook surfaces collisions for human resolution.

2. **Should `schema_meta` be the canonical version
   anchor, or replaced by the
   `cesauth-migrate`-managed manifest already used by
   the export tool?** Out of scope for this RFC.
   `schema_meta` exists in code; this RFC just makes
   it work. A subsequent RFC may unify it with the
   manifest, or remove it.

## Implementation order

1. Add the `cesauth-migrate-test` integration crate
   (will fail against current migrations — that's the
   point).
2. Repair `0001` to create `schema_meta`.
3. Repair `0004` to rebuild child tables and restore
   `COLLATE NOCASE`.
4. Repair `0009` to no longer be the only writer to
   `schema_meta`; add `schema_meta` writes to every
   migration.
5. Update the Cloudflare adapter's `find_by_email`
   query to be explicit about `COLLATE NOCASE`.
6. Run the test crate locally; confirm green.
7. Add the operator runbook to data-migration.md.
8. Land via single PR.

## Notes for the implementer

- D1's wrangler tooling silently ignores `PRAGMA
  foreign_key_check`'s output if it appears in a
  migration file (the pragma's reportable result is
  visible only via `wrangler d1 execute` interactive).
  The check in Step 2 of the rewrite is therefore
  best-effort defense — the integration test is the
  authoritative gate.
- The migration files are SQL, not Rust; all checks
  must run as part of the `cesauth-migrate-test` crate
  on the host. Do not attempt to embed Rust assertions
  in the SQL.
- The repair script for existing deployments must be
  idempotent. Operators may run it twice during an
  incident; the second run must be a no-op.
