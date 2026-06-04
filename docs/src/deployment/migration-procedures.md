# Migration Procedures

## Applying schema migrations

cesauth uses an ordered migration chain managed by `cesauth_core::migrate`.
Migrations run at worker startup (or via `wrangler d1 execute`).

### Fresh deployment

```bash
wrangler d1 execute cesauth-db --file migrations/0001_initial.sql
wrangler d1 execute cesauth-db --file migrations/0002_audit.sql
# … continue in numeric order …
wrangler d1 execute cesauth-db --file migrations/0020_authenticator_tenant_id.sql
```

Or run the bundled migration runner which applies all pending migrations:

```bash
wrangler dev  # migrations run automatically on first request
```

### Verifying the current schema version

```sql
SELECT value FROM schema_meta WHERE key = 'schema_version';
-- Expected: "20"
```

### Migration chain integrity

`cesauth-migrate-test` contains 31 integration tests that verify:
- Fresh SQLite database applies all 20 migrations cleanly.
- `PRAGMA foreign_key_check` passes after full migration.
- Key indexes exist and enforce uniqueness constraints.
- Partial-index correctness for invitation/deletion tables.

Run before deploying a new migration:

```bash
cargo test -p cesauth-migrate-test
```

---

## Upgrading from previous versions

### v0.56.0 → v0.57.0 (no migration)

RFC 045-048 added worker routes and service functions. No schema change.

### v0.57.0 → v0.58.0 (migrations 0018–0019)

```bash
wrangler d1 execute cesauth-db --file migrations/0018_invitation_tokens.sql
wrangler d1 execute cesauth-db --file migrations/0019_deletion_requests.sql
```

Both migrations are additive (new tables only). No data transformation required.

### v0.58.0 → v0.59.0 (migration 0020)

```bash
wrangler d1 execute cesauth-db --file migrations/0020_authenticator_tenant_id.sql
```

This migration:
1. Adds `tenant_id` column to `authenticators` (nullable initially).
2. Backfills from `users.tenant_id` (requires `users` rows to be intact).
3. Rebuilds the table with `NOT NULL` enforcement.
4. Adds `idx_authenticators_tenant` index.

**Pre-flight check**: Ensure no authenticator rows exist with a `user_id`
that has no corresponding `users` row. Orphaned authenticators would
receive the default `'tenant-default'` tenant_id.

```sql
-- Check for orphaned authenticators before migrating:
SELECT COUNT(*) FROM authenticators a
  LEFT JOIN users u ON u.id = a.user_id
  WHERE u.id IS NULL;
-- Expected: 0
```

---

## Rollback policy

cesauth migrations are intentionally **forward-only**. Each migration is
designed to be non-destructive (additive columns, new tables, or safe
rebuilds). In the event of a migration failure:

1. Restore from the most recent D1 backup (see `docs/deployment/backup-restore.md`).
2. Fix the migration script.
3. Re-apply from the last successful migration.

D1 does not support transactional DDL rollback. Always test migrations
in a staging environment before applying to production.

---

## Data export / import

Tenant-scoped data export and import is an operator capability. The
`cesauth_core::migrate::export` and `migrate::import` modules provide
the building blocks. A CLI tool wrapping these is planned for v0.7.x.

To export a single tenant's data today:

```sql
-- Export tenant + all child tables in dependency order
SELECT * FROM tenants WHERE id = :tenant_id;
SELECT * FROM users WHERE tenant_id = :tenant_id;
SELECT a.* FROM authenticators a JOIN users u ON u.id = a.user_id
  WHERE u.tenant_id = :tenant_id;
-- … (see data-model.md for the full relationship graph)
```
