# RFC 119 — Tenant boundary and scoped repository APIs

**Status.** Proposed
**Tier.** P1 · Category B (implement soon; widest refactor)
**Size.** Large
**Tracks.** Strategy §5.4, §8 (RFC theme 4); audit G2.
**Touches.** `crates/core/src/ports/repo.rs`, adapters,
`core::tenancy`, `core::authz` context construction, all callers.
**Depends on.** RFC 116 (`TenantId`, `UserId`).

## 1. Summary

Make tenant context a type-level requirement of tenant-scoped
repository operations. Lookups like `UserRepository::find_by_id(&str)`
and `find_by_email(&str)` become tenant-scoped
(`find_by_id(&TenantId, &UserId)`); operations that are legitimately
system-wide move to an explicit, separately-named system-scope surface.
Add cross-tenant denial property/integration tests.

## 2. Motivation

The schema enforces tenant lineage (composite FKs), and routes pass
tenant scope to `check_permission` — but the repository layer between
them accepts un-scoped lookups. Today every call site happens to be
correct by convention; the spec's hardest requirement ("a subject in
tenant A must not access tenant B resources") deserves to be a property
of the port types so that an *omitted filter cannot be expressed*.
Spec §7.1 and Forbidden Pattern "blurring the tenant boundary" are the
authority.

## 3. Background

Email uniqueness is per-tenant since migration 0004, yet
`find_by_email(email)` has no tenant parameter — it is correct only
while callers pre-resolve tenant context out-of-band. Retention sweeps,
chain verification, and system-operator console queries are genuinely
cross-tenant and must remain expressible — explicitly.

## 4. Target code areas

- `core/src/ports/repo.rs` — `UserRepository`,
  `AuthenticatorRepository` (`list_by_user`), `GrantRepository`
  (`list_active_for_user`), invitation/membership/role-assignment
  repositories.
- New `core/src/ports/repo/system_scope.rs` — explicit system-wide
  surface (`SystemScope` capability token parameter).
- `crates/adapter-cloudflare` SQL: scoped methods gain
  `AND tenant_id = ?` predicates (most queries already filter; this
  makes the remainder uniform).
- `crates/adapter-test` + conformance tests.
- New integration tests: cross-tenant denial matrix.

## 5. Security properties / invariants

1. A tenant-scoped read/write cannot be *written* without a `TenantId`.
2. Two distinct tenants observing the same query parameters receive
   disjoint result sets (property-tested over the in-memory adapter).
3. System-wide access is only reachable through `SystemScope`, whose
   construction sites are enumerable (`pub(crate)` constructor; minted
   only by cron entrypoints and system-operator routes after
   `check_permission` at system scope).
4. Membership removal invalidates effective privilege: covered by an
   integration test (remove membership → `check_permission` denies →
   tenant-scoped lookups for that subject return nothing they
   shouldn't).

## 6. Non-goals

- No `TenantScoped<T>` generic wrapper for *return values* in this RFC.
  The strategy lists it as a candidate; the audit found the scoping
  gap is in *query inputs*, where a parameter is cheaper and clearer.
  A wrapper can be revisited if mixed-tenant aggregation bugs ever
  appear.
- No row-level-security emulation in D1, no schema change.
- No change to the scope lattice or `check_permission` (RFC 120).

## 7. Proposed design

### 7.1 Scoped trait shape

```rust
pub trait UserRepository {
    async fn find_by_id(&self, tenant: &TenantId, id: &UserId)
        -> PortResult<Option<User>>;
    async fn find_by_email(&self, tenant: &TenantId, email: &str)
        -> PortResult<Option<User>>;
    async fn create(&self, tenant: &TenantId, user: &User) -> PortResult<()>;
    // …
}
```

Adapters must apply the tenant predicate in SQL, not post-filter in
Rust — keeping D1 the enforcement point and avoiding cross-tenant rows
ever entering worker memory.

### 7.2 System scope

```rust
pub struct SystemScope(());                 // zero-size capability token
impl SystemScope { pub(crate) fn assert() -> Self { Self(()) } }

pub trait UserRepositorySystem {
    async fn find_by_id_any_tenant(&self, _s: &SystemScope, id: &UserId)
        -> PortResult<Option<User>>;
    async fn list_anonymous_expired(&self, _s: &SystemScope, …) -> …;
}
```

`grep -rn "SystemScope::assert"` enumerates every cross-tenant access
point in the codebase — a one-command audit, which is the point.

### 7.3 Cross-tenant denial test matrix

For each scoped repository method: seed two tenants with colliding
natural keys (same email, same credential id where schema permits),
assert tenant-A queries never return tenant-B rows. Implemented as a
generic conformance suite in adapter-test plus a proptest that
generates interleaved multi-tenant populations.

## 8. Data model impact

None (predicates only; indexes from migration 0013 already lead with
`tenant_id`).

## 9. API impact

None on the wire. Port traits change shape (internal breaking, single
release).

## 10. Testing strategy

§7.3 matrix; property test invariant 2; membership-removal integration
test (invariant 4); full existing suite green. Adapter SQL changes are
covered by the conformance suite running identically against in-memory
and (when env permits) miniflare D1.

## 11. Migration strategy

Module-by-module behind compiling phases, mirroring RFC 116's order:
repo traits → adapters → tenancy/service callers → backend glue. The
system-scope surface lands first so cron callers have a target before
the scoped methods lose their old signatures.

## 12. Rollout plan

One minor release after RFC 116 (and ideally after 117/118 to avoid
rebasing their call sites twice). CHANGELOG: internal hardening; a
note for self-hosters with custom adapters that port traits changed.

## 13. Risks and mitigations

- **Hot-path regression** (extra predicate) → predicates hit existing
  composite indexes; introspect/token hot paths are already
  tenant-resolved; verify with the RFC 026 hot-path tests.
- **Hidden cross-tenant assumptions** in admin console queries →
  the compile errors themselves are the discovery tool; each gets an
  explicit `SystemScope` or a tenant parameter, reviewed individually.
- **Default-tenant legacy rows** → `DEFAULT_TENANT_ID` is a valid
  `TenantId`; fixtures pin it.

## 14. Acceptance criteria

1. No tenant-scoped repository method without a `TenantId` parameter.
2. `SystemScope::assert()` call sites ≤ documented list in this RFC's
   closing note (cron entrypoints + system-operator routes).
3. Cross-tenant denial matrix green; multi-tenant proptest green.
4. Full suite + wasm32 check green; hot-path tests show no regression.

## 15. Open questions

- Should `SessionIndexRepo` adopt tenant scoping now? Sessions are
  user-keyed and users are tenant-resolved upstream; deferred with a
  note, revisit if session queries ever take raw user ids from input.
