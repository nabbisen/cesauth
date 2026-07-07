# RFC 118 — Refresh token rotation and reuse-detection assurance

**Status.** Proposed
**Tier.** P0 · Category A
**Size.** Medium
**Tracks.** Strategy §5.2, §8 (RFC theme 3); audit G6 (refresh half).
**Touches.** `crates/core/src/ports/store.rs`
(`FamilyState`/`RotateOutcome` docs + one model module),
`crates/adapter-test` (conformance additions), new
`core/src/ports/store/family_model.rs` + proptests.
**Depends on.** RFC 116 (`FamilyId`, `Jti`).

## 1. Summary

Specify the refresh-token family lifecycle as an explicit pure
reference model (`Active → Rotated* → Revoked`, with the retired-jti
forensic ring), then drive both the model and every
`RefreshTokenFamilyStore` implementation with the **same** generated
state-machine property tests. The DO implementation's behaviour under
adversarial sequences (reuse, double-rotate, revoke-then-rotate,
unknown-jti probing) becomes a pinned executable specification.

## 2. Motivation

ADR-011's reuse-hardening is the project's strongest security response
path, and its correctness currently rests on hand-written sequences.
The dangerous bugs in rotation schemes are *sequence* bugs: a jti
accepted twice under interleaving, a revoked family resurrected by a
late rotate, version moving backward. Generated sequences find these;
examples don't. This is the strategy's flagship `proptest` target.

## 3. Background

`RefreshTokenFamilyStore` exposes `init / rotate / revoke / peek`;
`RotateOutcome` distinguishes `Rotated`, `AlreadyRevoked`, and
`ReusedAndRevoked { reused_jti, was_retired }`. The Cloudflare adapter
relies on DO single-threaded execution for atomicity; the in-memory
adapter mirrors it. The conformance suite (133 tests) checks examples,
not sequences.

## 4. Target code areas

- New `core/src/ports/store/family_model.rs` — pure model, no I/O.
- New proptest module `family_model/proptests.rs` (model self-test) and
  an adapter-test generic harness
  `conformance::refresh_family_state_machine` applied to the in-memory
  store (and runnable against any future store).
- Documentation: the model module becomes the normative description
  referenced from `oidc-tokens.md`.

## 5. Security properties / invariants

For any operation sequence applied to a family:

1. **Single live jti.** At most one jti is accepted by `rotate` at any
   point; it is exactly the most recently issued one.
2. **Rotation kills the predecessor.** After
   `rotate(old → new) = Rotated`, presenting `old` yields
   `ReusedAndRevoked` and the family is revoked.
3. **Revocation is irreversible and absorbing.** After any revocation
   (explicit or reuse-triggered), every subsequent `rotate` yields
   `AlreadyRevoked`; no operation returns the family to active.
4. **Version monotonicity.** The rotation counter never decreases and
   increases by exactly 1 per successful rotation.
5. **Forensic fidelity.** `was_retired == true` iff the presented jti
   was previously a live jti of this family; unknown jtis report
   `was_retired == false`. Presenting unknown jtis must revoke the
   family (shotgun-attack response) — matching current documented
   behaviour.
6. **Expiry.** Past family expiry, no jti is accepted.
7. **Init uniqueness.** `init` on an existing id is `Conflict`; it
   never resets state.

## 6. Non-goals

- No change to DO storage layout, token TTL policy, or the audit events
  emitted on reuse (`RefreshTokenReuseDetected`).
- No cross-family invariants (families are independent by design).
- No typestate wrapper around the store handle: the lifecycle authority
  lives inside the DO; a host-side typestate would assert state the
  host cannot know. The pure model + generated tests are the right tool
  here (strategy §5.2 lists typestate as *optional*).
- TLA+ modelling is RFC 124's pilot, not part of this RFC.

## 7. Proposed design

### 7.1 Pure reference model

```rust
// family_model.rs — std-only, no async, no ports
pub struct FamilyModel { /* current_jti, retired ring, version,
                            revoked_at, expires_at … */ }
pub enum Op { Init(Jti), Rotate { presented: Jti, new: Jti },
              Revoke, AdvanceClock(u32) }

impl FamilyModel {
    pub fn apply(&mut self, op: Op, now: i64) -> ModelOutcome;
}
```

`ModelOutcome` mirrors `RotateOutcome` plus init/revoke results. The
model is small enough to review line-by-line and doubles as the input
for the RFC 124 Kani/TLA+ pilot.

### 7.2 Generated conformance harness

```rust
// adapter-test: generic over S: RefreshTokenFamilyStore
proptest! {
    fn store_matches_model(ops in op_sequence_strategy(1..64)) {
        // run ops against (FamilyModel, S) in lockstep;
        // assert outcome equality and post-state equality via peek()
    }
}
```

The strategy biases toward adversarial shapes: replaying retired jtis,
rotating after revoke, random unknown jtis, clock jumps across expiry.
Concurrency note: DO execution is sequential, so *interleaving* reduces
to sequence permutation — which is exactly what the generator produces.
This is documented in the harness header so nobody later assumes the
tests prove parallel-memory-model properties they don't.

### 7.3 Regression seeds

Failing cases discovered during development are committed as
`proptest-regressions/` seeds (project already gitignores nothing
there; verify and keep them in-tree).

## 8. Data model impact

None.

## 9. API impact

None. (`RotateOutcome` doc-comments tightened to normative language.)

## 10. Testing strategy

The RFC *is* a testing strategy; additionally: model unit tests for
each invariant 1–7 as named example tests, so a failure message points
at the violated invariant before anyone reads a 60-op shrunk sequence.

## 11. Migration strategy

Purely additive.

## 12. Rollout plan

One minor release after RFC 117 (shares the op-sequence utilities).
If the harness finds a real divergence in the in-memory or DO adapter,
the fix ships in the same release and is called out in CHANGELOG under
security fixes.

## 13. Risks and mitigations

- **Model/implementation co-drift** (both wrong the same way) → the
  model is reviewed against ADR-011 prose and RFC 9700 §4.14.2
  independently of the code; invariants 1–7 are written from the spec,
  not from the implementation.
- **Slow CI** → cap cases (`PROPTEST_CASES=256` default, more in
  nightly), sequences ≤ 64 ops.

## 14. Acceptance criteria

1. Model module + named invariant tests green.
2. Lockstep harness green against the in-memory store at ≥ 256 cases.
3. Any divergence found is fixed or documented as intended with the
   model updated — zero unexplained mismatches.
4. `docs/src/expert/oidc-tokens.md` links the model as normative.

## 15. Open questions

- Should the harness also run against the Cloudflare DO adapter under
  `wrangler dev` (miniflare)? Desirable; blocked on the env-blocked
  wasm verification track (same blocker as RFC 110a/112). Recorded as
  a deferred acceptance item, not a blocker.
