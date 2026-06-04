# RFC 021: User-scoped FK and cascade alignment

**Status**: Implemented
**ROADMAP**: External data-structure review v0.52.1 — P1 finding on FK cascade vs code expectation drift
**ADR**: N/A — alignment between schema and code, not a new design
**Severity**: **P1 — orphan rows can accumulate after user deletion; existing code comments and sweep paths assume cascade behavior the schema does not provide**
**Estimated scope**: Medium — six FK additions across two migrations + repository contract sweep + ~30 LOC of test fixtures
**Source**: External data-structure review attached to the v0.52.1 conversation

## Background

`UserRepository::delete_by_id` and the anonymous-user
retention sweep (`crates/worker/src/sweep.rs`) both
operate on the assumption that deleting a row in
`users` cascades to user-scoped child tables. That
assumption is documented inline in code comments
("FK ON DELETE CASCADE handles cleanup") but *not*
encoded in the schema for most of those tables.

The data-structure review enumerates the gap:

| Table | `user_id` column | FK to `users(id)` | Behavior on delete |
|---|---|---|---|
| `user_tenant_memberships` | yes | **missing** | row orphaned |
| `user_organization_memberships` | yes | **missing** | row orphaned |
| `user_group_memberships` | yes | **missing** | row orphaned |
| `role_assignments` | yes (when `scope_type='user'`) | **missing** | row orphaned |
| `totp_authenticators` | yes | **missing** | encrypted secret remains |
| `totp_recovery_codes` | yes | **missing** | recovery hash remains |
| `user_sessions` | yes | **missing** | mirror row remains |
| `anonymous_sessions` | yes | **present** (`ON DELETE CASCADE`) | correct |
| `authenticators` | yes | present (RFC 020 restores it) | correct after RFC 020 |
| `consent` | yes | present (RFC 020 restores it) | correct after RFC 020 |
| `grants` | yes | present (RFC 020 restores it) | correct after RFC 020 |

Two failure modes are live as of v0.52.1:

1. **Encrypted-secret retention.** Calling
   `UserRepository::delete_by_id(uid)` leaves
   `totp_authenticators` rows behind. Their
   `secret_encrypted` column carries the AES-GCM
   ciphertext. The deployment's `TOTP_ENCRYPTION_KEY`
   can decrypt them. The user is "deleted" but their
   TOTP material lives on indefinitely. This violates
   the §"data minimisation" expectation of GDPR-style
   right-to-be-forgotten requests.

2. **Authorization-residue.** A `role_assignments`
   row with `scope_type='user'` granting
   `user-deleted-uuid` a role survives the user. If
   the same UUID were later reused (it shouldn't be —
   user IDs are UUIDv4 — but defense in depth), the
   reused account inherits the orphaned grant.

`anonymous_sessions` is the lone counter-example
where the FK with cascade is explicitly present and
correctly aligned with the sweep's expectations.

## Requirements

The fix must:

1. After `UserRepository::delete_by_id(uid)`, no row
   with `user_id = uid` may remain in any user-scoped
   table.
2. The relationship between code (sweep, delete,
   anonymisation paths) and schema must be auditable
   in one place — either both rely on cascade or both
   rely on explicit cleanup, but not split.
3. `role_assignments` is treated specially: deleting
   the *user* row deletes the user's grants, but
   deleting a role does *not* cascade to assignments
   (that's a separate concern; not addressed here).
4. Existing migration tests (RFC 020) must extend to
   pin user-deletion → empty child tables.

## Decision / Plan

The repository contract is "delete the user and
everything user-scoped goes with them". Two
implementation choices satisfy that contract:

- **Case A — schema-side cascade.** Add `REFERENCES
  users(id) ON DELETE CASCADE` to every user-scoped
  table. SQLite enforces it on delete; the
  application code becomes a single-statement DELETE.
- **Case B — application-side cleanup.** Keep schema
  as-is; rewrite `delete_by_id` to enumerate every
  child table and delete in dependency order.

This RFC chooses **Case A for credentials and
sessions, Case B for role assignments**, with the
asymmetry documented.

| Table | Choice | Rationale |
|---|---|---|
| `user_tenant_memberships` | A — cascade | Memberships are pure linkage; no audit value once user is gone |
| `user_organization_memberships` | A — cascade | Same |
| `user_group_memberships` | A — cascade | Same |
| `totp_authenticators` | A — cascade | Encrypted material must NOT outlive the user |
| `totp_recovery_codes` | A — cascade | Hashed material; same |
| `user_sessions` | A — cascade | D1 mirror; DO is authoritative truth |
| `role_assignments` | **B — explicit cleanup, audited** | Role grants are an authorization decision worth preserving in the audit chain when the user is removed; cascading would make the deletion silent |

For Case B, the existing `cesauth_core` audit-event
catalog gains `EventKind::RoleAssignmentRevokedByUserDeletion`,
emitted once per deleted assignment as part of
`delete_by_id`. The existing
`SessionRevokedByAdmin` analog covers the model.

### Step 1 — Migration `0011_user_fk_cascade.sql`

A single new migration that adds the missing FK
clauses. SQLite cannot `ALTER TABLE … ADD CONSTRAINT
FOREIGN KEY`, so the recipe is the same
"rebuild" pattern from RFC 020:

```sql
PRAGMA foreign_keys = OFF;

-- Repeat for each Case-A table:
ALTER TABLE user_tenant_memberships RENAME TO user_tenant_memberships_pre_0011;
CREATE TABLE user_tenant_memberships (
    ...same columns...
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    ...
);
INSERT INTO user_tenant_memberships SELECT * FROM user_tenant_memberships_pre_0011;
DROP TABLE user_tenant_memberships_pre_0011;

-- ... and so on for the six other Case-A tables ...

PRAGMA foreign_key_check;
PRAGMA foreign_keys = ON;
```

`role_assignments` is **not** modified by this
migration — application code stays in charge.

### Step 2 — Repository contract update

`cesauth_core::ports::repo::UserRepository::delete_by_id`
gains an explicit doc comment:

```rust
/// Delete a user and all user-scoped data.
///
/// Guarantees after a successful return:
///
/// - The `users` row with `id = uid` is gone.
/// - Child tables in the cascade-FK set
///   (memberships, TOTP authenticators, TOTP
///   recovery codes, user_sessions mirror) carry
///   no row with `user_id = uid` (enforced by
///   schema-level `ON DELETE CASCADE`).
/// - Any `role_assignments` row with
///   `subject_type = 'user' AND subject_id = uid`
///   has been deleted by an explicit DELETE inside
///   this method, AND a
///   `RoleAssignmentRevokedByUserDeletion` audit
///   event was emitted for each.
/// - DO-side state (`ActiveSession`,
///   `AuthChallenge`) is **not** touched by this
///   call. DO retention is a separate concern;
///   per ADR-012 the DO is authoritative for
///   live-session state and a deleted user's
///   in-flight session must be revoked through the
///   normal `revoke_all_for_user` path before
///   `delete_by_id` is called.
async fn delete_by_id(&self, uid: &UserId) -> PortResult<()>;
```

The contract makes it explicit that
`delete_by_id` is the data-cleanup half;
session-revocation is a separate caller
responsibility. The CLI / admin-console "delete
user" action is the integration point that calls
both in order.

### Step 3 — `delete_by_id` implementation update

Cloudflare D1 adapter pseudocode:

```rust
async fn delete_by_id(&self, uid: &UserId) -> PortResult<()> {
    // Step 1: enumerate role_assignments for the audit emit.
    let rows = sql!("SELECT id, role_id, scope_type, scope_id
                     FROM role_assignments
                     WHERE subject_type = 'user' AND subject_id = ?", uid)
               .all().await?;

    for row in rows {
        emit_audit(EventKind::RoleAssignmentRevokedByUserDeletion, &row);
    }

    // Step 2: best-effort delete role_assignments.
    sql!("DELETE FROM role_assignments
          WHERE subject_type = 'user' AND subject_id = ?", uid).run().await?;

    // Step 3: cascade delete users — ON DELETE CASCADE handles the rest.
    sql!("DELETE FROM users WHERE id = ?", uid).run().await?;

    Ok(())
}
```

The ordering matters: audit events emit *before*
the destructive write; if the user-row delete
fails, the audit log records an attempt that may
have rolled back, which is acceptable (audit is
forensic, not transactional).

### Step 4 — In-memory adapter parity

`cesauth-adapter-test`'s in-memory `UserRepository`
must mirror the cascade behavior — it does not
have schema FKs, so the in-memory code does an
explicit cleanup for the Case-A tables to match
the D1 behavior. New tests pin every child-table
emptiness check.

### Step 5 — Sweep path simplification

`crates/worker/src/sweep.rs`'s anonymous-user sweep
currently does an explicit per-table cleanup loop
for tables it expects to need cleanup; with FK
cascade in place, the loop reduces to a single
`DELETE FROM users WHERE …` and the inline
cleanup comments referencing "FK ON DELETE CASCADE
handles cleanup" become accurate rather than
aspirational.

### Step 6 — Integration tests in `cesauth-migrate-test`

Extend the RFC-020 integration crate:

- Insert a user, two memberships, a TOTP
  authenticator, two recovery codes, a session
  index row, and a role assignment.
- `DELETE FROM users WHERE id = ?`.
- Assert each of the Case-A tables has zero rows
  for that user_id.
- Assert `role_assignments` *does* still have the
  row (because application code is responsible for
  that, not the schema).

A second test exercises the application path:
calls the in-memory `UserRepository::delete_by_id`,
asserts `role_assignments` is now also empty AND a
`RoleAssignmentRevokedByUserDeletion` event landed
in the in-memory audit sink.

## Test plan

- New tests in `cesauth-migrate-test` per Step 6.
- New tests in `cesauth-adapter-test` for the in-
  memory `UserRepository::delete_by_id` matching
  the documented contract.
- Existing TOTP-related tests must continue to
  pass — the cascade addition is additive to
  inserts.

## Security considerations

The encrypted-TOTP-secret retention is the most
operationally consequential of the gaps. A user
removed from the system today (v0.52.1) leaves a
ciphertext blob that the deployment's encryption
key can decrypt; an admin with audit-log access
inspecting historical `totp_authenticators` rows
may see content the user has the right to expect
is gone. RFC 021 closes this.

## Open questions

1. **Should the migrate tool's redaction profile
   strip orphaned rows when exporting a deployment
   that was upgraded across this RFC's boundary?**
   Yes — the existing `prod-to-staging` profile
   should be extended to drop orphaned user-scoped
   rows defensively. Tracked as a follow-up under
   RFC 023's invariant work.

2. **What about `audit_events` carrying
   `subject_type='user' AND subject_id=uid`?**
   Audit events are append-only and intentionally
   survive user deletion — operator queries against
   audit history must work regardless of subject
   liveness. No change.

## Implementation order

1. Migration `0011_user_fk_cascade.sql`.
2. Update `UserRepository` doc and impl.
3. Update sweep.
4. Wire `RoleAssignmentRevokedByUserDeletion` into the
   audit catalog.
5. Extend `cesauth-migrate-test` and `cesauth-adapter-test`.
6. Single PR.

## Notes for the implementer

- This RFC depends on RFC 020 — it adds `0011`
  on top of a clean migration chain. Do RFC 020
  first.
- DO-side session revocation (the
  `ActiveSessionStore::revoke_all_for_user` call)
  is a *caller* responsibility, not part of
  `delete_by_id`. The admin-console handler that
  exposes user deletion is the integration point.
  The doc comment in Step 2 must be honored by
  every new caller of `delete_by_id`.
- The 0011 migration's `INSERT … SELECT …` with
  `*` is intentional shorthand; for production
  safety, list every column explicitly so a
  future schema-add doesn't silently miss a
  column on rebuild.
