# RFC 023: Tenant boundary integrity — composite indexes and service-layer cross-tenant validation

**Status**: Implemented
**ROADMAP**: External data-structure review v0.52.1 — P1 finding on weak tenant integrity for organizations and groups
**ADR**: This RFC produces ADR-016 establishing tenant-boundary as a first-class invariant; cross-tenant integrity matters enough to deserve a recorded decision rather than a buried code comment
**Severity**: **P1 — application bugs or admin-API misuse can produce cross-tenant organizational structures; tenant boundary is part of cesauth's security boundary in multi-tenant deployments**
**Estimated scope**: Medium — one schema migration adding composite UNIQUE indexes + service-layer validator + ~40 LOC of integration tests
**Source**: External data-structure review attached to the v0.52.1 conversation

## Background

cesauth's data model embeds tenant scope on
`organizations` and `groups`:

```text
organizations.tenant_id
groups.tenant_id
groups.organization_id
groups.parent_group_id
```

The data-structure review observes that the schema
does not enforce three structural invariants:

1. An organization's parent (when one exists) must
   belong to the same tenant.
2. A group's `organization_id`, when set, must point
   at an organization in the same tenant.
3. A group's `parent_group_id`, when set, must point
   at a group in the same tenant.

The schema currently expresses each FK separately:

```sql
CREATE TABLE groups (
    ...
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    organization_id TEXT REFERENCES organizations(id),
    parent_group_id TEXT REFERENCES groups(id),
    ...
);
```

A `groups` row in tenant `T1` with
`organization_id` pointing at an organization in
tenant `T2` is rejected by neither the FK (because
`organizations(id)` matches), nor the UNIQUE
constraints (because there are no composite ones), nor
a CHECK (because none exists).

The `cesauth_core::tenancy::service::create_group`
function does not perform a cross-tenant validation
either — it forwards the input to the repository.

In a single-tenant deployment this is a non-issue. In
the multi-tenant deployments cesauth aspires to
support (and which already exist per the
`/admin/tenancy/*` console), tenant boundary is
expected to be a security boundary: a misbehaving
admin API caller, an application logic bug, or a
malicious tenant-admin should NOT be able to produce
a structure that links one tenant's group to another
tenant's organization.

`role_assignments` has a similar weakness — its
`scope_type` / `scope_id` pair is documented to
point at a row in some scope-typed table, but the
relationship is by convention not by FK. This RFC
addresses organizations and groups; role
assignments are tracked as a follow-up (see Open
question 2).

## Requirements

The fix must:

1. After this RFC ships, the schema rejects insertion
   of a `groups` row whose `(tenant_id,
   organization_id)` pair is not a real organization
   row, AND whose `(tenant_id, parent_group_id)`
   pair is not a real group row in the same tenant.
2. The service layer (`cesauth_core::tenancy::service`)
   validates the same invariants before calling the
   repository, so application errors surface as
   structured `CoreError` rather than opaque D1
   constraint failures.
3. Existing data passes the new constraints (verified
   by a one-shot scan in the migration; bad data, if
   any, fails the migration loud rather than
   silently).
4. The integration test suite from RFC 020 / 021 is
   extended with a cross-tenant rejection test.

## Decision / Plan

The composite-FK approach is the safest because it
moves the invariant into the storage layer, where it
cannot be bypassed by a future repository
implementation that forgets to enforce it.

### Step 1 — Migration `0013_tenant_composite_keys.sql`

Add composite UNIQUE indexes on `organizations` and
`groups` to provide multi-column targets for FKs:

```sql
CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_tenant_id_id
    ON organizations(tenant_id, id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_tenant_id_id
    ON groups(tenant_id, id);
```

Then rebuild `groups` via the SQLite "rebuild" recipe
(same pattern as RFC 020 / 021) to add composite FKs:

```sql
PRAGMA foreign_keys = OFF;

ALTER TABLE groups RENAME TO groups_pre_0013;

CREATE TABLE groups (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    -- Composite FK to (tenant_id, id) of organizations: when
    -- organization_id is non-NULL, the (tenant_id, organization_id)
    -- pair must exist. Cross-tenant linkage is rejected by SQLite.
    organization_id TEXT,
    -- Composite FK to (tenant_id, id) of groups itself: same shape
    -- for parent groups.
    parent_group_id TEXT,
    ...other columns...
    FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organizations(tenant_id, id)
        ON DELETE SET NULL,
    FOREIGN KEY (tenant_id, parent_group_id)
        REFERENCES groups(tenant_id, id)
        ON DELETE SET NULL
);

INSERT INTO groups SELECT * FROM groups_pre_0013;
DROP TABLE groups_pre_0013;

PRAGMA foreign_key_check;
PRAGMA foreign_keys = ON;
```

The composite FK in SQLite requires the referenced
columns to be unique — that's what the composite
UNIQUE indexes above provide. If any existing row
violates the new constraint, `PRAGMA
foreign_key_check` fails the migration; the
migration's failure mode is loud rather than silent
data corruption.

`organizations.parent_organization_id` (if the
deployment has hierarchical organizations) would get
the same treatment; v0.52.1 does not appear to model
hierarchical orgs, so this RFC scopes out of that.

### Step 2 — Service-layer validator

Add `cesauth_core::tenancy::service::validate_group_input`:

```rust
pub fn validate_group_input(input: &CreateGroupInput) -> Result<(), CoreError> {
    // Cross-tenant guard: caller MUST provide tenant_id, and any
    // referenced organization_id / parent_group_id must be looked
    // up by (tenant_id, ?) before being accepted.
    //
    // This is a data-shape check; the caller (admin handler) has
    // already done the actual repo lookups and can pass the
    // resolved tenant ids in for cross-check.
    if let Some(org_tid) = input.organization_tenant_id {
        if org_tid != input.tenant_id {
            return Err(CoreError::CrossTenantReference {
                kind: "organization",
                expected: input.tenant_id.clone(),
                actual:   org_tid,
            });
        }
    }
    if let Some(pg_tid) = input.parent_group_tenant_id {
        if pg_tid != input.tenant_id {
            return Err(CoreError::CrossTenantReference {
                kind: "group",
                expected: input.tenant_id.clone(),
                actual:   pg_tid,
            });
        }
    }
    Ok(())
}
```

`CreateGroupInput` gets two additional optional
fields (`organization_tenant_id`,
`parent_group_tenant_id`) that the admin handler
populates from a fresh repository read of the parent
records. This is *defense in depth* — the schema
constraint will catch the bad row at INSERT time
either way; the service-layer check produces a
typed error usable for nice admin-UI messaging,
without leaking that the inputs *would* have been
rejected by D1.

`CoreError::CrossTenantReference` is a new variant.
Its wire form to admin handlers is a 422-ish "input
referenced an organization that does not belong to
the target tenant"; the audit log records the
attempt with both tenant ids for forensic value.

### Step 3 — Repository / D1 adapter validation

The Cloudflare D1 adapter's `create_group` becomes:

1. Read `organizations` by `(tenant_id, id)` if
   `organization_id` is present.
2. Read `groups` by `(tenant_id, id)` if
   `parent_group_id` is present.
3. Pass the resolved `organization_tenant_id` /
   `parent_group_tenant_id` into the service-layer
   validator.
4. INSERT.

The schema FK is the ground truth; the lookups exist
to surface a typed error and to fail before doing the
INSERT under contention.

### Step 4 — Audit emission for rejections

A new audit kind `EventKind::CrossTenantReferenceRejected`
is emitted by the worker handler when it catches
`CoreError::CrossTenantReference`. Payload includes
the actor's user id, the target tenant id, the
referenced (wrong-tenant) id, and the surface
("create_group" / "update_group" / etc.). A spike
in this event indicates either a UI bug, an
admin-script bug, or a probing attacker; the
event-class signal is operational.

### Step 5 — Tests

- `cesauth-migrate-test` integration test inserts
  two tenants, two organizations (one per tenant),
  and attempts to create a group in tenant T1
  referencing T2's organization. Asserts
  `PRAGMA foreign_key_check` rejects.
- `cesauth-adapter-test::tenancy::tests` adds a
  test that calls `create_group` with a
  cross-tenant `organization_id` and asserts
  `CoreError::CrossTenantReference` is returned
  before any INSERT runs.
- ADR-016 records the boundary decision.

## Test plan

Per Step 5 above. The migration's
`PRAGMA foreign_key_check` is itself the
acceptance gate for existing-data soundness — if
the migration applies cleanly, no existing data
violates the invariant.

## Security considerations

Tenant boundary in cesauth is documented as part of
the security model — an OIDC client owned by tenant
T1 must not be able to receive consent from a user
in tenant T2, a tenant_admin in T1 must not be able
to manage T2's resources. RFC 023 makes the
storage-layer enforcement of that boundary
unconditional rather than convention-dependent.

The migration is loud-fail on bad existing data: if
v0.52.1 deployments accumulated any cross-tenant
groups (likely zero in practice, but the deployment
operator should confirm), the migration aborts with
a `foreign_key_check` failure naming the offending
rows, which the operator must reconcile manually
before retrying. Documenting this in the deployment
runbook (Step 6 of RFC 020's structure):

```sh
wrangler d1 execute cesauth-prod --command="
  SELECT g.id AS group_id, g.tenant_id AS group_tenant,
         o.tenant_id AS org_tenant
  FROM groups g
  LEFT JOIN organizations o ON o.id = g.organization_id
  WHERE g.organization_id IS NOT NULL
    AND o.tenant_id != g.tenant_id;
"
```

A non-empty result indicates pre-existing
cross-tenant rows that need cleanup before
migration `0013` can run.

## Open questions

1. **Should `organizations` also gain a self-referential
   composite FK if hierarchical orgs are introduced
   later?** Yes, this RFC's pattern extends naturally.
   Out of scope for the RFC itself.

2. **What about `role_assignments.(scope_type, scope_id)`?**
   `role_assignments` lacks any FK at all on
   `(scope_type, scope_id)` — the convention is
   that `scope_id` points at a row in the table
   named by `scope_type`, but no schema-level
   integrity enforces this. Adding composite FKs
   would require a UNIQUE index on every
   scope-typed table's `(scope_type-implied,
   scope_id)`, which is awkward. A future RFC may
   model role assignments as multiple tables (one
   per scope type) with proper FKs. For now this
   gap is documented in
   `docs/src/expert/tenancy.md` and tracked.

3. **Should the migration accept a `--strict` vs
   `--lenient` mode for handling pre-existing
   cross-tenant rows?** No — silent reconciliation
   in a migration is the wrong shape. The runbook
   surfaces the rows for human resolution.

## Implementation order

1. Migration `0013_tenant_composite_keys.sql`,
   including the diagnostic query in the deployment
   runbook.
2. Service-layer validator + `CoreError::CrossTenantReference`.
3. Cloudflare adapter's `create_group` /
   `update_group` validation hookup.
4. New audit kind.
5. ADR-016 written.
6. Tests.
7. Single PR; coordinate with operator deployment
   timing because the migration may surface
   pre-existing data issues.

## Notes for the implementer

- This RFC depends on RFC 020, and lands cleanly
  alongside RFC 021. Sequence: 020 → 021 → 022 → 023.
- Composite FKs in SQLite require the referenced
  composite to be UNIQUE. The composite UNIQUE
  indexes in Step 1 are load-bearing — do not drop
  them.
- D1's wrangler tooling reports `PRAGMA
  foreign_key_check` failures with structured
  output. Capture stderr in the deployment
  pipeline so operators get actionable rows.
- `ON DELETE SET NULL` on the composite FK is the
  least-surprising behavior for the optional
  organization / parent-group references; if the
  parent is deleted, the child group becomes
  unparented rather than disappearing. Tenant
  admins discover the unparented state in the UI
  and decide what to do.
