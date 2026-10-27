# RFC 120 — Authorization decision core: sealing and property tests

**Status.** Proposed
**Tier.** P0 (tests) / P1 (sealing) · Category A/B
**Size.** Medium
**Tracks.** Strategy §5.5, §8 (RFC theme 5); audit G5.
**Touches.** `crates/core/src/authz/{types,service}.rs`, catalog seed
sync (RFC 022 machinery), new `authz/proptests.rs`.
**Depends on.** RFC 116 (`UserId`, `TenantId`, `RoleId`).

## 1. Summary

Seal the `Permission` type (private field, catalog-checked construction
for cesauth-defined permissions, explicit `custom()` escape hatch for
operator-defined rows), change `check_permission` to accept
`&Permission` instead of `&str`, and add property tests pinning
deny-by-default, scope-lattice soundness, and grant monotonicity.

## 2. Motivation

`Permission(pub String)` plus `From<&str>` means a typo'd permission
string compiles, flows into `check_permission`, matches nothing, and
denies — fail-closed, but silently wrong, and the dual hazard exists:
a route checking a *weaker* permission than intended is undetectable.
The decision core is exactly the "small pure authorization core" the
strategy asks for; it deserves the strongest invariants in the
codebase, stated as executable properties.

## 3. Background

`check_permission` is already the single entry point (spec §10.2),
performs one indexed lookup, filters expired assignments, applies
`scope_covers`, then matches role grants. `scope_covers` has 14 unit
tests. What's missing: sealed permission construction, lattice
*property* tests (transitivity/antisymmetry over generated scopes), and
monotonicity properties over generated assignment sets.

## 4. Target code areas

- `authz/types.rs` — `Permission` sealing; `ScopeRef` unchanged.
- `authz/service.rs` — signature takes `&Permission`; logic unchanged.
- New `authz/proptests.rs` (+ strategy helpers for scopes, roles,
  assignment sets).
- Call sites in `crates/backend` routes — mechanical
  `PermissionCatalog::X` adoption (most already reference catalog
  constants; stragglers converted).

## 5. Security properties / invariants

Property-tested over generated `(assignments, roles, scope, permission)`:

1. **Deny by default.** Empty assignments ⇒ `Denied(NoAssignments)`;
   no generated input with zero covering grants ever yields `Allowed`.
2. **Allowed implies witness.** Every `Allowed` outcome carries a
   specific live, covering assignment whose role grants the permission
   (the check re-verified independently by the test, not trusted from
   the outcome).
3. **Grant monotonicity.** Adding an assignment never converts an
   `Allowed` into `Denied`; removing one never converts `Denied` into
   `Allowed`.
4. **No unrelated amplification.** Adding a role granting permission P
   never changes the outcome for any query about permission Q ≠ P at
   any scope.
5. **Expiry strictness.** An assignment with `expires_at <= now`
   contributes nothing (outcome equals the outcome with it removed).
6. **Lattice soundness.** `scope_covers` is reflexive and transitive
   over generated scope chains; tenant containment is respected
   (no grant in tenant A covers a target in tenant B — the
   tenant-before-role ordering invariant from strategy §5.5).
7. **Dangling-role neutrality.** Assignments referencing missing roles
   are skipped, never erroring into an allow.

## 6. Non-goals

- No policy-engine adoption (Category D — strategy explicitly defers).
- No change to the scope lattice semantics, deny reasons, or the wire.
- No permission-namespace redesign; catalog categories stay as-is.

## 7. Proposed design

### 7.1 Sealed `Permission`

```rust
pub struct Permission(String);              // field now private

impl Permission {
    /// Catalog-checked; the normal path. Compile-time const refs
    /// remain available as PermissionCatalog::TENANT_DELETE etc.
    pub fn catalog(name: &str) -> Result<Self, UnknownPermission>;
    /// Operator-defined permission rows (documented feature) —
    /// explicit, greppable, validated for shape.
    pub fn custom(name: &str) -> Result<Self, InvalidPermissionName>;
    pub fn as_str(&self) -> &str;
}
```

`From<&str>` is removed. `PermissionCatalog` constants become
`pub const fn` returning `Permission` (or `&'static Permission` via
statics — following the project's established const-promotability
pattern). RFC 022's seed-sync test extends to assert catalog constants
↔ `permissions` table rows stay in bijection.

### 7.2 `check_permission(…, permission: &Permission, …)`

Logic byte-identical; only the parameter type changes. The batch
variant follows.

**Noted 2026-10-28, during RFC 000 §22's back-fill:** there are **two**
decision implementations, and this RFC will have to change both.
`check_permission` is the request-time enforcement path
(`backend/.../tenant_admin/gate.rs` → `check_action` → `check_read`);
`check_permissions_batch` is the affordances path that decides which controls
the tenant-admin UI offers. **It reimplements the same two filters** — the
`expires_at` test and `scope_covers` — in its own loop rather than delegating.

By inspection they are equivalent today: same two filters, same
`Allowed`/`Denied(PermissionMissing)` outcomes. **Nothing asserts that they
stay equivalent**, and the two have asymmetric coverage — 20 test call sites
for the single version (including all six of RFC 052's hardening suite) against
7 for the batch. If they drift, the symptom is a UI offering a control the
enforcement path refuses, or hiding one it would allow: the owner's *"users not
to be confused"* clause, reached through an authorization bug.

**This RFC's property tests should run against both**, or the batch should
delegate. Either closes it; recording it here because §7.2 already commits to
touching both.

### 7.3 Property tests

Strategies generate: scope trees (1–3 tenants, 0–3 orgs each, 0–3
groups, users), role sets (0–8 roles × 0–6 permissions), assignment
sets (0–16, mixed scopes/expiries), then assert invariants 1–7.
`Allowed`-witness checking (invariant 2) re-implements the decision in
~15 lines inside the test as an independent oracle — small enough that
oracle/implementation co-drift is review-detectable.

## 8. Data model impact

None (seed-sync test tightening only).

## 9. API impact

None on the wire.

## 10. Testing strategy

§7.3; plus named example tests for each invariant; plus a negative
compile doc-test showing `Permission` is unconstructible from a bare
string literal without `catalog()`/`custom()`. Existing 14
`scope_covers` tests retained untouched.

## 11. Migration strategy

Two phases: (1) property tests against the *current* code — any
counterexample found is a security fix shipped first; (2) sealing +
mechanical call-site conversion.

## 12. Rollout plan

Phase 1 may ship with RFC 118's release (it is test-only). Phase 2 in
the following minor release. CHANGELOG notes both.

## 13. Risks and mitigations

- **Operator custom permissions break** → `custom()` preserves the
  documented capability; release note shows the one-line change.
- **Const-promotion friction** with `&'static` catalog refs → known
  project pattern (module-level statics); follow it.

## 14. Acceptance criteria

1. `Permission` field private; `From<&str>` gone; all call sites use
   catalog constants or `custom()`.
2. Invariants 1–7 green at ≥ 256 cases each.
3. Phase-1 run against pre-sealing code documented in the RFC closing
   note (counterexamples found: expected none; if any, linked fix).
4. Full suite green.

## 15. Open questions

- Should `DenyReason` become part of the public audit payload taxonomy?
  Touches RFC 123; deferred there.
