# RFC 022: Permission catalog and built-in role seed sync

**Status**: Implemented
**ROADMAP**: External data-structure review v0.52.1 — P1 finding on permission catalog vs migration seed drift
**ADR**: N/A — alignment between code and seed data
**Severity**: **P1 — tenant-admin membership-management is documented as supported but not actually permitted under shipped seed roles**
**Estimated scope**: Small — one migration + seed-completeness invariant test + ~20 LOC catalog comparison
**Source**: External data-structure review attached to the v0.52.1 conversation

## Background

`cesauth_core::authz::PermissionCatalog::ALL`
(`crates/core/src/authz/types.rs:47, 87`) declares two
permissions that the application uses but the migration
seed does not include:

```rust
pub const TENANT_MEMBER_ADD:    &'static str = "tenant:member:add";
pub const TENANT_MEMBER_REMOVE: &'static str = "tenant:member:remove";
```

Worker code in the tenant-admin surface
(`/admin/t/<slug>/users/...`) calls
`check_permission(PermissionCatalog::TENANT_MEMBER_ADD, ...)`
when an admin tries to add a user to a tenant.

`migrations/0003_tenancy.sql:131-156` seeds the
`permissions` table with a finite list of `INSERT OR
IGNORE INTO permissions ...` statements; the two
`tenant:member:*` slugs are absent. The shipped
`tenant_admin` role's permission CSV
(`migrations/0003_tenancy.sql:184-198`) does not list
them either.

Live consequence on a fresh-seeded deployment as of
v0.52.1:

1. Operator promotes a user to `tenant_admin`.
2. The user opens `/admin/t/acme/users` and tries to
   add a member.
3. `check_permission` consults the role's permission
   set, which does not contain `tenant:member:add`.
4. The action is rejected with `403 Forbidden`.

There is no code path that adds the missing rows at
runtime — `0003` is the only writer to the
permissions catalog, and `tenant_admin` was never
granted the missing slugs.

## Requirements

The fix must:

1. The `permissions` table seed and the
   `PermissionCatalog::ALL` constant array stay in
   sync; adding a new permission must touch both, and
   CI must enforce the symmetry.
2. The shipped `tenant_admin` role's permission set
   includes everything a tenant admin is documented
   to be able to do — specifically including
   adding/removing tenant members.
3. The `system_admin` role's permission set is a
   strict superset of every built-in role's set.
4. Migration tests pin both invariants.

## Decision / Plan

### Step 1 — Migration `0012_permission_catalog_sync.sql`

A small additive migration. Per the project's
not-yet-1.0 convention (RFC 020 §"Decision / Plan"),
we could equivalently fix `0003` in place; for this
specific defect, **shipping a separate `0012` is
preferable** because the seed catalog is data, not
schema, and the application code already idempotently
re-asserts known data via `INSERT OR IGNORE`. A
new migration is the cleanest "add these two slugs
and grant them to the right roles" intent.

Migration body:

```sql
-- ----------------------------------------------------------------------------
-- 0012_permission_catalog_sync.sql
-- ----------------------------------------------------------------------------
-- Adds tenant:member:add and tenant:member:remove permissions, which were
-- declared in cesauth_core::authz::PermissionCatalog but missed from the
-- 0003 seed. Also extends the tenant_admin and system_admin role permission
-- CSVs to grant the new slugs. See RFC 022.

INSERT OR IGNORE INTO permissions (name, description, created_at) VALUES
    ('tenant:member:add',    'Add user to a tenant',      strftime('%s','now')),
    ('tenant:member:remove', 'Remove user from a tenant', strftime('%s','now'));

-- Update built-in roles. CSV append must be idempotent so re-running this
-- migration on a database that already received it is a no-op. We use the
-- "string append if not contained" trick that SQLite supports via instr().

UPDATE roles
SET permissions = permissions || ',tenant:member:add'
WHERE id = 'role-system-admin'
  AND instr(permissions, 'tenant:member:add') = 0;

UPDATE roles
SET permissions = permissions || ',tenant:member:remove'
WHERE id = 'role-system-admin'
  AND instr(permissions, 'tenant:member:remove') = 0;

UPDATE roles
SET permissions = permissions || ',tenant:member:add'
WHERE id = 'role-tenant-admin'
  AND instr(permissions, 'tenant:member:add') = 0;

UPDATE roles
SET permissions = permissions || ',tenant:member:remove'
WHERE id = 'role-tenant-admin'
  AND instr(permissions, 'tenant:member:remove') = 0;

-- Per RFC 020 step 1, every migration writes its version.
INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '12');
```

### Step 2 — Catalog-completeness invariant test

In the `cesauth-migrate-test` integration crate from
RFC 020:

```rust
#[test]
fn every_catalog_permission_is_seeded() {
    let conn = fresh_sqlite_with_all_migrations();
    let seeded: HashSet<String> = conn
        .prepare("SELECT name FROM permissions")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();

    for slug in cesauth_core::authz::PermissionCatalog::ALL {
        assert!(
            seeded.contains(*slug),
            "PermissionCatalog::ALL declares {slug:?} but no migration seeded it. \
             Add it to migrations/00NN_*.sql, or remove it from the catalog."
        );
    }
}

#[test]
fn system_admin_role_is_superset_of_tenant_admin() {
    let conn = fresh_sqlite_with_all_migrations();
    let perms = |role: &str| -> HashSet<String> {
        let csv: String = conn
            .query_row("SELECT permissions FROM roles WHERE id = ?", [role], |r| r.get(0))
            .unwrap();
        csv.split(',').map(str::to_owned).collect()
    };

    let sys = perms("role-system-admin");
    let tn  = perms("role-tenant-admin");
    assert!(tn.is_subset(&sys),
        "role-tenant-admin must be a subset of role-system-admin; missing: {:?}",
        tn.difference(&sys).collect::<Vec<_>>());
}

#[test]
fn tenant_admin_can_manage_members() {
    let conn = fresh_sqlite_with_all_migrations();
    let csv: String = conn
        .query_row("SELECT permissions FROM roles WHERE id = ?",
                   ["role-tenant-admin"], |r| r.get(0))
        .unwrap();
    let set: HashSet<&str> = csv.split(',').collect();
    assert!(set.contains("tenant:member:add"));
    assert!(set.contains("tenant:member:remove"));
}
```

These three tests are the primary acceptance gate.
The first one is the load-bearing invariant — adding a
new permission to `PermissionCatalog::ALL` without
seeding it becomes a CI failure.

### Step 3 — Documentation update

`docs/src/expert/tenancy.md`'s "Built-in roles"
section adds the two slugs to the `tenant_admin` row
(currently the table omits them). Cross-link to this
RFC.

`docs/src/expert/architecture.md` or the new ADR-016
(if one is opened for "permission catalog evolution
policy") should describe the rule: every change to
`PermissionCatalog::ALL` ships in the same release as
a migration that seeds the new slug and grants it to
the appropriate built-in roles.

## Test plan

- New tests in `cesauth-migrate-test` per Step 2.
- Existing tenancy-service tests in
  `cesauth-adapter-test::tenancy::tests` should be
  re-run; they construct in-memory permission sets
  manually and are not affected by the migration
  change, but they should explicitly include the new
  slugs in the test fixtures so the in-memory
  permission model also reflects the catalog.

## Security considerations

The current state is *fail-closed* —
`tenant:member:add` rejection means a tenant admin
can't actually add members, which is annoying but
not a security regression. The fix moves to
*correct* behavior, which slightly increases what
the tenant_admin role can do (by design). No
existing deployment grants tenant_admin to a user
who shouldn't be able to manage tenant members; the
expansion matches documented intent.

## Open questions

1. **Should the catalog and the seed be unified into
   a single source of truth (e.g., a build script
   that generates the seed SQL from
   `PermissionCatalog::ALL`)?** Considered and
   declined for this RFC. Code-generated SQL
   complicates `cargo test`'s dependency graph and
   makes migrations harder to review. The
   invariant test is the reasonable middle ground.

2. **What about per-tenant custom roles that grant
   these new permissions?** Tenant-defined roles
   are a future feature; today only the built-in
   roles exist (`tenant:read`, `tenant:update`,
   etc.). The fix is forward-compatible: a tenant
   defining a custom role can grant the new slugs
   from the moment they're seeded.

## Implementation order

1. Migration `0012_permission_catalog_sync.sql`.
2. Add the three invariant tests to
   `cesauth-migrate-test`.
3. Update `docs/src/expert/tenancy.md`.
4. Single PR.

## Notes for the implementer

- This RFC depends on RFC 020 — it sits on the
  repaired migration chain. Land RFC 020 first.
- Migration body uses `instr()` for idempotent
  append; SQLite supports `instr()` natively. Do
  NOT replace with regex or pattern functions —
  D1's SQLite build does not include the regex
  extension.
- The CSV permissions storage in `roles.permissions`
  is documented in `0003`'s comments as a
  simplification (no JSON1, comma-delimited TEXT).
  This RFC preserves that representation; do not
  switch to a join table within this RFC.
