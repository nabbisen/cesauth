# RFC 118 — Refresh token rotation and reuse-detection assurance

**Status.** Accepted — approved by the owner 2026-09-22, with the §16 corrections. Handoff dispatched.
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

## 16. Premise corrections, measured 2026-09-22

RFC 118 was written before RFC 137, 139, 140 and 117 changed this exact path.
Four of its premises no longer hold, and two of them describe properties the
code cannot have. The corrections below are rulings; the rest of the RFC stands.

### 16.1 There is no version counter — invariant 4 must be restated

§5.4 asserts "the rotation counter never decreases and increases by exactly 1
per successful rotation". **`FamilyState` has no such field**: it carries
`current_jti`, `retired_jtis`, `created_at`, `last_rotated_at`, `revoked_at`,
the v0.34.0 reuse fields and RFC 139's `expired`. §8 says "Data model impact:
none", so adding a counter would contradict the RFC's own scope, and a counter
whose only consumer is its own test earns nothing.

**Ruling:** state the invariant in terms of what exists — `last_rotated_at` is
non-decreasing and equals the `now` of the most recent successful rotation, and
each successful rotation appends exactly one jti to the retired ring (subject to
16.2). **No new field.**

### 16.2 The retired ring is capped at 16 — invariant 5 is false as written

§5.5 asserts `was_retired == true` **iff** the presented jti was previously a
live jti of this family. `RETIRED_RING_SIZE = 16` in both implementations, and
the oldest entry is dropped on overflow, so the 17th-oldest rotated-out jti
reports `was_retired == false`.

**Ruling:** the invariant is about the **retained** ring: `was_retired == true`
iff the presented jti is among the last 16 rotated-out jtis; an older one is
reported as unknown. **The security response is unchanged** — both cases revoke
the family — so this is a forensic-label boundary, not a weakening. The model
must implement the cap, and the generator must produce sequences long enough to
cross it, or the property will never see the case.

### 16.3 Expiry now exists, and the outcome set has grown

§5.6's one-line "past family expiry, no jti is accepted" predates RFC 139. The
rule is now two deadlines — absolute (`created_at + cap`) and idle
(`last_rotated_at + window`, `0` disabling it) — evaluated **against the policy
passed to `rotate`**, with the store revoking and recording which deadline ended
the family. `RotateOutcome` has a fourth variant, `Expired(LifetimeExpiry)`.

**Ruling:** the model carries both deadlines, the `expired` field and the
check order RFC 139 §10.2 fixed (revoked → absolute → idle → jti), and
`ModelOutcome` mirrors all four variants. The policy is an input to each
`Rotate` op, not model state, because lowering it must shorten a live family.

### 16.4 The module layout §4 names does not exist; RFC 117's does

There is no `conformance` module in `cesauth-adapter-test`. RFC 117 landed the
first store state-machine harness as
`crates/adapter-test/src/store/auth_challenge_proptests.rs` — a model, a lockstep
runner, an op strategy and a **coverage test that fails when a category goes
rare**.

**Ruling:** mirror that file as `store/refresh_family_proptests.rs`, including
the coverage test. §12's "shares the op-sequence utilities" is satisfied by
following the shape; do not refactor RFC 117's harness into a shared abstraction
for two users.

### 16.5 Regression seeds — §7.3 needs a boundary

`proptest-regressions/` is **not** in `.gitignore`, so §7.3's "keep them
in-tree" would work. But RFC 117's cycle produced seed files from *mutation*
runs — failures against deliberately broken code — and removing them was right:
committed, they would have invented a regression history for defects that never
shipped.

**Ruling:** commit a seed only when it reproduces a divergence in **shipped**
code, with a comment naming the divergence. Seeds from mutation or fires runs
are deleted, and the package says so.

### 16.6 Stale figure

§3's "conformance suite (133 tests)" is stale. `crates/adapter-test/src/store/tests.rs`
holds **30** `#[test]`/`#[tokio::test]` items today
(`grep -rc '#\[test\]\|#\[tokio::test\]'`). The handoff will state the
baseline as a command and its output rather than carry a number forward.

### 16.7 Still true

§6's non-goals hold, including "no typestate wrapper around the store handle":
the lifecycle authority is inside the Durable Object, and RFC 117's typestate
governs the host-side *exchange*, which is a different thing. §15's open
question — running the harness against the real Durable Object — remains
deferred and remains not a blocker.

**Authorized by the owner on 2026-09-22**, with these corrections. The rest of
this line is superseded.

## 17. First divergence, ruled (2026-09-24)

The harness found a divergence on its first run, and the cycle stopped before
fixing it, as the handoff §7 requires.

**`InMemoryRefreshTokenFamilyStore::init` hard-coded `auth_time: 0`** instead of
storing `FamilyInit.auth_time`. The contract states the clause twice
(`FamilyInit.auth_time`, `FamilyState.auth_time`), the Durable Object implements
it (`adapter-cloudflare/src/refresh_token_family.rs:103`), and `cesauth-core`'s
own `StubFamilies` implements it — so three of four implementations agreed with
the contract and the fourth was the only one no test ever read.

**Ruling: the store is wrong; the double is fixed** (`auth_time: init.auth_time`).
It is the third instance of this project's recurring defect class — a test double
that quietly simplifies the contract (RFC 137 §4.1, RFC 140 T3) — and the first
one caught by a machine rather than by a reviewer.

**Not a security fix.** `cesauth-adapter-test` is `publish = false` and reaches
no shipped path; all six existing `FamilyInit` constructions pass `auth_time: 0`,
so no current test could observe the drop and none changes. RFC 118's CHANGELOG
entry says the harness found it, and says plainly that no shipped behaviour was
affected.

**Two silences in the contract, closed with it:**

- `rotate` / `revoke` on a family that was never initialised is `NotFound`. Both
  stores did this; nothing said so. Documented on the port and pinned by a model
  test and a contract test — not by the generator, which would have to represent
  an absent family for a case two examples cover.
- An explicit `revoke` of a family that is expired but not yet detected as
  expired wins, leaving `expired` as `None`. This follows from invariant 3
  (revocation is absorbing, first writer wins) and is now explicit in
  `FamilyState.expired`'s doc.

**A measurement rule, from the same cycle.** Coverage thresholds are set from a
measured sample at roughly half its value, and are **not** tightened to the
measured numbers: a threshold exists to catch a generator regression, not to
ratify today's figures.
