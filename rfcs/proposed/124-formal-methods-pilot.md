# RFC 124 — Lightweight model-checking pilot (TLA+ on the refresh-token family lifecycle)

**Status.** Proposed. **Narrowed to TLA+ only, 2026-11-14 — see §0.**
**Tier.** P2 · Category C (pilot only; time-boxed; may be rejected)
**Size.** Small (by mandate)
**Tracks.** [ADR-020 §1](../../docs/src/expert/adr/020-security-assurance-posture.md)
(Category C) and §5 (the §5.2 lifecycle invariants); formerly cited as
"strategy §5.5/§5.2, §8 (RFC theme 9)", which was unresolvable from inside
this repository until ADR-020 landed.
**Touches.** New `verification/` directory (out-of-workspace, like
`fuzz/`); no production code changes permitted by this RFC.
**Depends on.** RFC 118 (`FamilyModel`) — **shipped, so this RFC is no longer
blocked.**

## 0. Narrowed to TLA+ only, 2026-11-14 (architect)

This RFC proposed **two tools on two targets in one 10-working-day box**. That
shape is no longer permitted, and the dependency structure says where to cut.

**Why it changed.** [ADR-019 §5](../../docs/src/expert/adr/019-formal-verification-position.md)
now requires **one named target at a time**, derived from RFC 183's shape — the
pilot that actually worked — and the owner's instruction of 2026-11-10 is
explicit: *"Too wide range will cost insanely. It should start from minimal and
be optimized every time."* A two-tool pilot is the thing both rules forbid.

**Where the cut falls is not a preference — it is this RFC's own dependency
seam.** Its `Depends on` line bundled two tools' prerequisites:

| half | target | needs | status |
|---|---|---|---|
| **TLA+** | the refresh-token family lifecycle, via RFC 118's `FamilyModel` | **RFC 118** | **shipped** |
| **Kani** | `scope_covers` and friends — RFC 120 invariant 6 | **RFC 120** | **not shipped** |

So the blocker that held this whole RFC belonged to only one half of it.

**The resolution:**

1. **This RFC is TLA+ only**, on the refresh-token family lifecycle. One target,
   one tool, dependency **RFC 118 alone — which shipped, so it is unblocked.**
   The time box halves with the scope.
2. **Kani leaves this RFC.** It is owned by the Kani-trial row in `ROADMAP.md`,
   at RFC 183's own two TOTP-truncation obligations — a target that needs
   neither RFC 118 nor RFC 120, and whose scope the owner fixed as minimal.
3. **The Kani targets below are preserved as future candidates**, not deleted:
   `scope_covers`, `pkce::verify`'s comparison path and `FamilyModel::apply`,
   still dependent on RFC 120, and **explicitly after the trial row reports** —
   because that trial decides whether Kani is adopted at all. Running it on four
   authorization functions before knowing that is the "too wide range" the
   owner warned against.
4. **One of those targets should be dropped when it is revisited.**
   `util::constant_time_eq_bytes` is listed in §5.2 below with its own
   admission that *"timing is out of scope for Kani"*. Its entire purpose **is**
   timing, so proving functional equality certifies the one property nobody
   doubts — exactly the mistake ADR-019 §5 records RFC 183 for avoiding when it
   declined the same function as a Verus target.

**Not changed:** the Category C verdict obligation (adopt narrowly / defer /
reject, per ADR-020 §1), the no-production-code rule, and Flux staying
de-scoped per §3.

## 1. Summary

A strictly time-boxed evaluation of **TLA+** on the refresh-token family
lifecycle, modelling the client/attacker/store interaction that the Rust
`FamilyModel` cannot express (multiple concurrent clients holding copies of
jtis).

**§0 narrowed this.** The Kani half — `scope_covers`, `pkce::verify`'s
comparison path, `util::constant_time_eq_bytes`, `FamilyModel::apply` — moved
out on 2026-11-14 and is preserved there as a future candidate set. The original
box was 10 working days for both tools; TLA+ alone takes its half.

Deliverable is a written recommendation per tool: **adopt narrowly /
defer / reject**, with reproducible artifacts either way.

## 2. Motivation

The strategy classifies Kani, TLA+, and Flux as Category C: potentially
valuable, unproven for this team. RFC 118's pure `FamilyModel` and
RFC 120's sealed pure authz core are deliberately the ideal substrate —
small, side-effect-free, security-critical. If formal methods pay off
anywhere in cesauth, it is exactly there; if they don't pay off there,
that is a clean, evidence-based rejection.

## 3. Background

Broad Verus adoption and whole-application verification are Category D
(rejected for now) per the strategy's final direction; Flux is "keep
under consideration". This pilot deliberately excludes Flux: its value
overlaps with the newtype/smart-constructor work already landed by
RFC 116, so its marginal benefit should be re-assessed only after this
pilot reports. (Recorded so the de-scoping is a decision, not an
omission.)

## 4. Target code areas

- `verification/kani/` — proof harnesses, referencing core via path
  dependency, excluded from the stable workspace.
- `verification/tla/refresh_family.tla` + model-check configs.
- `docs/src/expert/formal-pilot-report.md` — the recommendation.

## 5. Security properties / invariants

Kani harnesses (bounded):

1. `scope_covers` reflexivity, transitivity over bounded scope values,
   and tenant non-crossing (RFC 120 invariant 6, now exhaustively
   within bounds rather than sampled).
2. `constant_time_eq_bytes(a, b) == (a == b)` for all inputs up to the
   bound (functional correctness; timing is out of scope for Kani and
   stated as such).
3. `FamilyModel::apply` preserves RFC 118 invariants 1–4 for all
   op sequences up to depth 6.

TLA+ model:

4. Under N concurrent clients each holding arbitrary subsets of
   previously issued jtis, the store's transition rules guarantee:
   no two `Rotated` outcomes for the same presented jti; once
   `Revoked`, always `Revoked`; an attacker holding only retired jtis
   can never obtain a `Rotated` outcome — checked by TLC over a small
   finite configuration (e.g. 3 clients, 5 rotations).

## 6. Non-goals

- No production code modified to please a verifier (if a proof needs a
  refactor, that is a *finding*, recorded, not silently applied).
- No CI integration during the pilot.
- No Verus, no Flux, no whole-module proofs, no UI anything.
- The pilot's failure to prove something is a result, not a blocker:
  nothing downstream depends on this RFC.

## 7. Proposed design

Time-box: 5 days Kani, 5 days TLA+, executed by one developer, calendar
bounded. Each day's outcome logged. Evaluation rubric fixed up front:

| Criterion | Question |
|---|---|
| Reach | Did it check something proptest plausibly couldn't? |
| Friction | Setup + harness cost in hours; nightly/toolchain burden |
| Maintainability | Can a normal Rust developer rerun and extend it? |
| Findings | Any real divergence/bug discovered? |
| Verdict | adopt narrowly / defer / reject — per tool |

"Adopt narrowly" means: harnesses kept green by a `make verify`
target run before releases, scope frozen to the listed functions, any
expansion requiring a new RFC.

## 8. Data model impact

None.

## 9. API impact

None.

## 10. Testing strategy

Not applicable in the usual sense; the artifacts are themselves
checkers. Reproducibility requirement: a fresh-checkout
`make verify-pilot` reruns everything (Kani via cargo-kani pinned
version; TLC via a pinned jar checked into `verification/tla/bin/` or
fetched by script — decided by repo-size budget).

## 11. Migration strategy

None.

## 12. Rollout plan

After RFC 120 ships. The report lands regardless of verdict; harnesses
land only on "adopt narrowly".

## 13. Risks and mitigations

- **Time-box bleed** → hard stop; partial results are valid results.
- **Tool enthusiasm overriding the rubric** → verdict must cite the
  rubric rows; the "normal Rust developers must be able to maintain
  it" non-objective from the strategy is the tie-breaker.
- **Kani bound too small to mean anything** → bounds stated in the
  report next to each claim; over-claiming ("proved") is forbidden
  wording — "checked up to bound" is the required phrasing.

## 14. Acceptance criteria

1. Report published with per-tool verdicts and rubric scores.
2. All claims reproducible via `make verify-pilot` from clean checkout.
3. Any real finding has a linked fix or tracked issue.
4. ROADMAP updated with the adopt/defer/reject outcome.

## 15. Open questions

- None at proposal time; the open questions are what the pilot exists
  to answer.
