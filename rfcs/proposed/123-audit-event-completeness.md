# RFC 123 — Audit event completeness for privileged operations

**Status.** Proposed
**Tier.** P1 · Category B
**Size.** Medium
**Tracks.** Strategy §5.7, §8 (RFC theme 8); audit G3 (redaction), G8.
**Touches.** `crates/core/src/audit*`, `core::admin::service`,
mutating route surfaces in `crates/backend`, new
`core/src/audit/audited.rs`, new coverage test.
**Depends on.** RFC 116 (`RedactedSecret`, redacting Debug).

## 1. Summary

Make "every privileged operation emits a complete audit event" a
mechanically checked property instead of a convention: (1) an
`Audited<T>` result wrapper that privileged service functions must
return, statically coupling the state change to its event; (2) a
route↔EventKind coverage test that fails when a mutating route exists
without a mapped event; (3) a redaction property test asserting no
event payload can carry raw secret material.

## 2. Motivation

Spec §2.1 makes auditability non-negotiable and Forbidden Patterns
list "omitting an audit event for a privileged operation". Today the
guarantee is enforced by review. The hash chain proves *recorded*
events are untampered; nothing proves an event was recorded at all.
The miss risk concentrates exactly where incidents do: newly added
admin routes.

## 3. Background

`audit::write_owned` is the established writer; events carry actor /
subject / scope / kind / result / correlation_id / before / after,
hash-chained (ADR-010, RFC 008). RFC 008 already eliminated OTP
material from events — this RFC generalises that one-off into a typed
property.

## 4. Target code areas

- New `core/src/audit/audited.rs` — wrapper + builder.
- `core::admin::service::*`, `core::tenancy::service`, invitation,
  role-assignment, subscription, revocation services — return-type
  adoption.
- New `crates/core/tests/audit_coverage.rs` (or backend-side
  equivalent) — route↔event mapping check against the route catalog
  (RFC 102/108 centralised route paths make this enumerable).
- `audit/proptests.rs` — redaction property.

## 5. Security properties / invariants

1. **Completeness.** Every mutating privileged service function's
   success path produces exactly one primary audit event whose kind is
   declared in a static catalog mapping; the coverage test enumerates
   the route catalog's mutating entries and fails on unmapped ones.
2. **Attribution.** Events carry actor, scope, result, timestamp, and
   correlation_id; `before`/`after` present for mutations of
   pre-existing rows (asserted per-kind in the mapping table).
3. **Redaction.** No payload serialisation of any event can contain
   raw secret material: payload construction accepts only types whose
   `Debug`/`Serialize` are redaction-safe (RFC 116 types), and a
   property test serialises generated events containing planted
   `RawSecret`-derived values and asserts the plant never appears.
4. **Failure is loud.** If the audit write fails on a path the mapping
   marks `atomic`, the state change must not commit (D1 batch);
   non-atomic paths must emit a fallback anomaly event — silent skip
   is unrepresentable in the wrapper API.

## 6. Non-goals

- No two-phase-commit across D1 and DOs (platform doesn't offer it);
  DO-side changes use the documented compensating-event pattern, and
  the mapping records which paths are atomic vs compensating.
- No change to chain hashing, retention, or the viewer (RFC 109).
- No audit of read-only operations (existing policy stands).

## 7. Proposed design

### 7.1 `Audited<T>`

```rust
pub struct Audited<T> { value: T, event: AuditEvent }   // fields private

impl<T> Audited<T> {
    pub fn new(value: T, event: AuditEventDraft) -> Self;   // draft forces
    // actor/scope/kind/result fields at compile time (builder with
    // required-field typestate, small: 3 stages)
}

/// The only function that unwraps an Audited<T> — writes the event
/// (honouring the atomicity mode), then releases the value.
pub async fn commit_audited<T>(repo: &dyn AuditEventRepository,
                               a: Audited<T>) -> PortResult<T>;
```

A privileged service function returning `Audited<T>` cannot have its
result used by the route layer without passing `commit_audited` — the
value is unreachable otherwise. This is the strategy's
"operation result wrappers requiring audit event generation",
implemented with the smallest possible surface.

### 7.2 Coverage test

The route catalog (centralised by RFC 102/108) is iterated; every
mutating route must appear in
`audit::catalog::ROUTE_EVENT_MAP: &[(RoutePath, EventKind, Atomicity)]`.
New mutating route without a mapping row ⇒ test failure with a message
telling the developer exactly what to add. (Chosen over a proc-macro
attribute: zero magic, greppable, and the project prefers explicit
tables — cf. PermissionCatalog.)

### 7.3 Redaction property

`proptest` generates events whose `before`/`after` JSON embeds values
derived from a sentinel secret; serialisation to the storage form must
never contain the sentinel. Combined with RFC 116's type-level
redaction this gives belt and braces.

## 8. Data model impact

None (no schema change; event shape unchanged).

## 9. API impact

None on the wire. Internal service signatures change to `Audited<T>`
returns (mechanical; same release).

## 10. Testing strategy

Coverage test (§7.2); redaction proptest (§7.3); per-service unit
tests asserting the draft fields; an atomicity test per `atomic` path
using a failing audit repo stub (state must not commit). Full suite
green.

## 11. Migration strategy

Adopt service-by-service in dependency order: tenancy → roles →
subscriptions → invitations → revocations → admin console misc. The
coverage test lands first in *warning* mode (allowlist of not-yet-
migrated routes that must only shrink), flipped to hard-fail when the
allowlist empties.

## 12. Rollout plan

Two minor releases: (1) wrapper + coverage-in-warning + first services;
(2) remainder + hard-fail flip. CHANGELOG flags the guarantee level
change.

## 13. Risks and mitigations

- **Ceremony creep on simple CRUD** (strategy §9 warning) → the draft
  builder is 3 required fields; measured against the existing manual
  `write_owned` call sites it is net-neutral lines.
- **Allowlist becoming permanent** → CI check that the allowlist file
  only ever shrinks (byte-count compare committed in the test).

## 14. Acceptance criteria

1. All privileged mutating services return `Audited<T>`;
   `write_owned` direct calls remain only inside `commit_audited` and
   the anomaly path.
2. Coverage test hard-fails on unmapped mutating routes; allowlist
   empty.
3. Redaction property green; atomicity stub tests green.
4. Full suite green.

## 15. Open questions

- Should `DenyReason` (RFC 120) be recorded on denied privileged
  attempts as first-class events? Proposed yes for admin surfaces,
  decided during implementation with audit-volume measurement against
  the plan-level retention budget.
