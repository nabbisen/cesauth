# Developer Handoff — RFC 118, refresh rotation and reuse-detection assurance (P0)

**Governing RFC.** [`rfcs/accepted/118-refresh-rotation-assurance.md`](../../accepted/118-refresh-rotation-assurance.md) — read **§16 first**. It corrects four premises of the original text, and those corrections are rulings.
**Target release.** The next one. **Level: patch** — a model, tests and doc
comments. No behaviour changes unless the harness finds a real divergence, in
which case §7 applies.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. 0.84.1 is tagged; no cut is pending.

---

## 1. Purpose

After this, the refresh-family lifecycle has a written reference model, and
generated adversarial sequences — replayed jtis, rotate-after-revoke, invented
jtis, clock jumps across both deadlines — are run against the real store in
lockstep with that model, with every outcome and the post-state compared.

## 2. Why this matters

Reuse detection is the project's strongest response to a stolen refresh token:
present a rotated-out jti and the whole family dies. Its correctness rests on
hand-written examples today. The bugs that matter in rotation schemes are
*sequence* bugs — a jti accepted twice, a revoked family resurrected by a late
rotate, an expired family rotating because the checks ran in the wrong order.
Examples do not find those; generated sequences do.

## 3. Resolved decisions — do not re-open

All in RFC §16, with the measurements behind them.

| Decision | Ruling |
|---|---|
| **No version counter** | §16.1. `FamilyState` has none, and §8 says no data-model change. Invariant 4 becomes: `last_rotated_at` is non-decreasing and equals the `now` of the last successful rotation, and each rotation appends exactly one jti to the retired ring (subject to the cap) |
| **The retired ring is capped at 16** | §16.2. `was_retired == true` **iff the presented jti is among the last 16 rotated-out jtis**; an older one reports `false`. Both still revoke, so this is a forensic label, not a weakening. The model implements the cap; the generator must cross it |
| **Expiry and the fourth outcome** | §16.3. The model carries both deadlines and `expired`, and mirrors `Expired(LifetimeExpiry)`. The **policy is an input to each `Rotate` op**, never model state: lowering it must shorten a live family (RFC 139 §9.2) |
| **Check order** | revoked → absolute → idle → jti (RFC 139 §10.2). An expired family presented with a retired jti is `Expired`, not reuse: the reuse fields stay `None` |
| **Module layout** | §16.4. Mirror RFC 117's harness as `crates/adapter-test/src/store/refresh_family_proptests.rs`. **Do not** build a shared abstraction over the two harnesses, and do not create the `conformance` module §4 names — it does not exist |
| **Regression seeds** | §16.5. Commit a seed only for a divergence in **shipped** code, with a comment naming it. Seeds from mutation or fires runs are deleted, and the package says so |
| **No typestate for the store** | RFC §6. The authority is inside the Durable Object |

## 4. Facts already measured — do not re-derive

| Fact | Where |
|---|---|
| Port: `init`, `rotate(family_id, presented_jti, new_jti, now_unix, lifetime)`, `revoke(family_id, now_unix)`, `peek` | `core/src/ports/store.rs`, `trait RefreshTokenFamilyStore`; the `rotate` doc already states RFC 139's four-step order |
| `RotateOutcome` has **four** variants: `Rotated`, `AlreadyRevoked`, `ReusedAndRevoked { reused_jti, was_retired }`, `Expired(LifetimeExpiry)` | same file |
| `FamilyState` fields, including `#[serde(default)] expired: Option<LifetimeExpiry>` and the v0.34.0 reuse forensics | same file |
| `RETIRED_RING_SIZE = 16`, in **both** implementations | `adapter-cloudflare/src/refresh_token_family.rs:59`, `adapter-test/src/store/refresh_token_family.rs:12` |
| Oracle rotate, already in RFC 139's order | `adapter-test/src/store/refresh_token_family.rs:46-90` |
| The lifetime decision function the model must mirror, not re-implement | `core/src/refresh_lifetime.rs` — `FamilyState::lifetime(now, &RefreshLifetime)`, absolute before idle, expired iff `now >= deadline` |
| **The harness to mirror** | `adapter-test/src/store/auth_challenge_proptests.rs` (275 lines): module doc stating each asserted clause, `Op` enum, `op_strategy`/`ops_strategy`, a `run(&ops) -> Result<Stats, String>` lockstep runner, `proptest!` with `ProptestConfig::with_cases(512)`, and a **coverage test** that draws a seeded sample and asserts each category's share |
| `proptest` is already a dev-dependency of both crates | `adapter-test/Cargo.toml:31`, `core/Cargo.toml:80` |
| Baseline | 1,486 host tests at `0.84.1`; state yours as the command and its summed `test result` lines |

*If any of this fails to reproduce, that is a finding. Report it.*

## 5. Change scope

| # | Task | Files |
|---|---|---|
| T1 | **The pure model.** `FamilyModel` with `current_jti`, the capped retired ring, `created_at`, `last_rotated_at`, `revoked_at`, `expired`; `Op::{Init, Rotate, Revoke, Advance}`; `ModelOutcome` mirroring all four `RotateOutcome` variants plus init/revoke results. std-only, no async, no ports. **Named example tests, one per invariant**, so a failure names the invariant before anyone reads a shrunk 60-op sequence | new `core/src/ports/store/family_model.rs` (+ its tests) |
| T2 | **The lockstep harness**, mirroring RFC 117's file: generated sequences applied to the model and to `InMemoryRefreshTokenFamilyStore`, comparing **the outcome of every op** and the **post-state via `peek`** (current jti, retired ring contents, `revoked_at`, `expired`, `last_rotated_at`) | new `adapter-test/src/store/refresh_family_proptests.rs`; `store.rs` module line |
| T3 | **The coverage test**, same shape as RFC 117's: fails when a category goes rare. Categories in §6 | same file |
| T4 | **Normative doc comments.** `RotateOutcome`'s variants and `FamilyState`'s reuse fields state the invariants in normative language, pointing at the model. `docs/src/expert/oidc-tokens.md` links the model as the normative description (RFC §14 criterion 4) | `ports/store.rs`, `oidc-tokens.md` |

**Order: T1 → T2 → T3 → T4.** The model and its named tests come first: if the
model is wrong, every lockstep failure is noise.

## 6. The generator must reach these, and T3 must prove it

Each needs a measured share, with a threshold that fails when it goes rare:

- a **successful rotation** (the happy path);
- a **replayed retired jti** that is still in the ring → `ReusedAndRevoked { was_retired: true }`;
- a **jti evicted past the 16-entry cap**, or never issued → `was_retired: false`. §16.2 exists because of this case, so generate sequences of **more than 16 rotations**;
- a **rotate after explicit revoke** → `AlreadyRevoked`;
- a **rotate past the absolute cap** → `Expired(Absolute)`;
- a **rotate past the idle window** → `Expired(Idle)`, including a family kept alive by rotations and then left idle;
- an **`init` on an existing id** → `Conflict`, state unchanged.

State the proportions, as RFC 117's coverage test prints them.

## 7. If the harness finds a divergence

**Stop and report before fixing.** Say which invariant, the shrunk sequence, and
which side you believe is wrong — the model or the store. A divergence in shipped
code is a security finding, and whether it is a bug or an intended behaviour the
model got wrong is my call, not a detail to settle inside the cycle. If it is a
real bug, its fix ships in the same release and is called out in the CHANGELOG.

## 8. The traps

**8.1 A model that mirrors the implementation.** Write the model from the
contract and RFC 9700 §4.14.2, not by reading `refresh_token_family.rs`. A model
derived from the code agrees with the code and proves nothing. Where the contract
is silent, the model follows **RFC 139's documented order** — and if something is
genuinely undefined, report it rather than picking a side quietly.

**8.2 Re-implementing the deadline arithmetic.** The model calls
`FamilyState::lifetime` / `deadline`, like the DO, the oracle and introspection
do. A second copy is a place they can disagree (RFC 139 §9.2).

**8.3 Comparing outcomes but not state.** Two stores can return the same
`RotateOutcome` and leave different `retired_jtis`. Compare the post-state too.

**8.4 A generator that never crosses the cap.** With short sequences,
`was_retired` is always `true` and §16.2's boundary is never tested. T3 is what
catches this.

**8.5 Threads.** "Any interleaving" is any **order**, single-threaded; the
Durable Object is not host-testable. Say so in the module doc, as RFC 117's
harness does.

**8.6 Committing mutation seeds.** §16.5.

## 9. Mechanical assertions

```sh
# the model does not re-implement the deadline arithmetic
grep -nE 'created_at *\+|last_rotated_at *\+|saturating_add' crates/core/src/ports/store/family_model.rs || echo "clean"

# the model calls the one decision function
grep -n '\.lifetime(\|\.deadline(' crates/core/src/ports/store/family_model.rs

# the cap is honoured in the model
grep -n '16\|RETIRED' crates/core/src/ports/store/family_model.rs

# no seeds from mutation runs
find . -name 'proptest-regressions' -not -path './target/*'

# the harness compares post-state, not just outcomes
grep -n 'peek' crates/adapter-test/src/store/refresh_family_proptests.rs
```

## 10. Required evidence

- The model's named invariant tests, listed by name.
- The lockstep property at **≥ 512 cases** (RFC §14 criterion 2 says ≥ 256;
  RFC 117's harness runs 512, so match it).
- T3's measured proportions, with the thresholds.
- **A fires pair:** break the in-memory store's reuse detection (accept a retired
  jti as current) and show the property red with its shrunk sequence; restore
  byte-identically and show it green. A second pair on the cap — make the ring
  unbounded — showing which category changes.
- Host tests (baseline 1,486 plus yours), `migration_chain`, clippy over six
  crates, the wasm32 and csr checks, `mdbook build docs`, `drift-scan --verbose`.
  **The wrangler-driven gates are not needed** — nothing here touches that path —
  but say which you skipped, as C1-139's package did.

I re-run the model tests, the lockstep property and one fires half myself.

## 11. What must NOT be claimed

- **Not that the Durable Object is verified.** The harness runs against the
  in-memory store; the DO is not host-testable, and §15's miniflare question is
  deferred.
- **Not that concurrency is proven.** Sequences, one thread.
- **Not that reuse detection is newly correct** — it is newly *pinned*.
- Not that CI has run it; not that it works on Cloudflare.

## 12. Prohibited shortcuts

- No `#[ignore]`, no lowering `ProptestConfig::with_cases` below 512 to make a
  run finish, no `cargo fmt`.
- No weakening a threshold in T3 to make it pass — if a category is rare, fix the
  generator.
- No editing an existing test. No changes to `RotateOutcome`'s variants or to the
  stores' behaviour (§7 governs the one exception).

## 13. Acceptance criteria

RFC 118 §14 as corrected by §16. Checked hardest: **criterion 3** (zero
unexplained mismatches), the **cap boundary** reached and asserted, and the
**model written from the contract** rather than from the store.

## 14. Review request

To `.git-exclude/review-request/`: implementation summary, changed files, the
§9 assertions, the model's invariant tests, the property and coverage output,
both fires pairs, any divergence with its §7 report, the gates you ran and those
you did not, and what remains unverified (§11).

**Do not cut a release, bump a version, or create a tag.**

Report the path only.
