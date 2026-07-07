# RFC 121 — Security state-machine testing with proptest

**Status.** Proposed
**Tier.** P1 · Category B
**Size.** Medium
**Tracks.** Strategy §5.3, §8 (RFC theme 6); audit G6 (session half).
**Touches.** `crates/adapter-test/src/conformance/` (new
`state_machine/` module), `core::ports::store` session/challenge
contracts (docs), `core::session_index`.
**Depends on.** RFC 117/118 (reuses their op-sequence utilities).

## 1. Summary

Generalise the lockstep model-vs-implementation harness built in
RFCs 117/118 into a small shared framework, and apply it to the two
remaining security lifecycles: **active sessions**
(start/touch/revoke/idle-expiry/absolute-expiry) and the **challenge
store across all challenge kinds** (including the TOTP-gate park/resume
and Magic Link attempt counting). Add a sequence test for tenant
membership change vs. access outcome.

## 2. Motivation

Session expiry is two interacting clocks (idle 30 min, absolute 8 h —
NIST 800-63B §4.1.3) plus explicit revocation, with four distinct
terminal statuses that drive different audit events. The status a
caller observes depends on operation order and clock advancement —
classic state-machine territory. Hand-written tests cover the obvious
paths; generated sequences cover the boundary collisions (touch exactly
at idle limit, revoke racing absolute expiry, etc.).

## 3. Background

`SessionStatus` already encodes
`NotStarted / Active / Revoked / IdleExpired / AbsoluteExpired` with
documented atomic populate-then-return semantics in the store. The
session index (D1) is reconciled against the DO by audit/repair crons —
the index's convergence is also sequence-dependent.

## 4. Target code areas

- New `adapter-test/src/conformance/state_machine/mod.rs` — shared
  `Model`/`Op`/lockstep-runner traits (extracted from 117/118).
- `state_machine/session.rs` — session model + harness.
- `state_machine/challenge.rs` — challenge model covering all
  `Challenge` variants' kind-specific rules (one-shot codes;
  Magic Link `bump_magic_link_attempts` cap; TOTP-gate single resume).
- `state_machine/membership_access.rs` — membership-change vs
  `check_permission` outcome sequences (bridges to RFC 120 properties).

## 5. Security properties / invariants

Session model, for any generated sequence of
`{Start, Touch(Δt), Revoke, AdvanceClock(Δt), Status}`:

1. A revoked session never returns `Active` afterwards (revocation is
   absorbing).
2. `last_seen_at + IDLE_TTL <= now` ⇒ status ∈
   {IdleExpired, Revoked, AbsoluteExpired}; never `Active`.
3. `created_at + ABSOLUTE_TTL <= now` ⇒ never `Active`, regardless of
   touch frequency (touching cannot extend the absolute bound).
4. Expiry statuses are sticky and mutually exclusive in the order the
   store documents (explicit revoke wins over later auto-expiry
   classification).
5. `touch` on a non-Active session never reactivates it.

Challenge model:

6. Per-handle: at most one successful `take` ever (all kinds).
7. Magic Link: attempts counter is monotonic; once past the cap the
   verify path must see a rate-limit outcome (model mirrors the
   documented cap).
8. TOTP gate: a parked `PendingTotp` resumes at most once; its `ar_*`
   payload round-trips intact (no field mixing across park/resume).

Membership/access:

9. After membership removal at scope S, a permission query that was
   `Allowed` solely via S becomes `Denied` (with the in-memory repos as
   the system under test).

## 6. Non-goals

- No new lifecycle semantics — the models codify documented behaviour.
- No DO-level concurrency simulation (single-threaded by platform;
  sequence permutation is the faithful adversary, as in RFC 118).
- No UI/e2e coverage (Playwright track is separate).
- WebAuthn ceremony *cryptographic* verification (covered by existing
  unit tests + RFC 122 fuzzing of parsers).

## 7. Proposed design

A minimal trait pair keeps the framework honest and small:

```rust
pub trait LockstepModel {
    type Op; type Outcome: PartialEq + Debug;
    fn apply(&mut self, op: &Self::Op, now: i64) -> Self::Outcome;
}
pub trait LockstepSubject<M: LockstepModel> {
    async fn apply(&mut self, op: &M::Op, now: i64) -> M::Outcome;
}
// runner: generate ops, advance a virtual clock, compare outcomes,
// shrink to minimal divergent sequence.
```

The virtual clock is explicit in ops (`AdvanceClock`) — stores already
take `now_unix` parameters throughout, so no time mocking is needed;
this is a design dividend of the existing port shapes and should be
noted as a constraint on future port design.

## 8. Data model impact

None.

## 9. API impact

None.

## 10. Testing strategy

Self-describing. CI budget: ≤ 256 cases per harness default, sequences
≤ 64 ops; a `make test-deep` target raises to 4096 for pre-release.

## 11. Migration strategy

Additive. Extraction of shared utilities from 117/118 is an internal
test-crate refactor.

## 12. Rollout plan

One minor release after RFC 118. Divergences found = security fixes,
same-release, CHANGELOG-flagged.

## 13. Risks and mitigations

- **Framework gold-plating** → hard cap: the shared module stays under
  ~300 ELOC (project split threshold); if it wants to grow past that,
  it's doing too much.
- **Flaky time arithmetic at boundaries** → boundary values (`== TTL`)
  are explicitly generated, and the model defines the closed/open
  interval convention normatively, taken from current store docs.

## 14. Acceptance criteria

1. Session, challenge, and membership harnesses green at default
   budget; `test-deep` green pre-release.
2. Invariants 1–9 also exist as named example tests.
3. Shared framework ≤ 300 ELOC; no production-crate changes required.
4. Full suite green.

## 15. Open questions

- Session-index (D1) convergence harness: include here or as a
  follow-up once the cron logic is port-isolated enough to run
  host-side? **Default: follow-up note in ROADMAP**, since the repair
  cron currently has worker-glue entanglement.
