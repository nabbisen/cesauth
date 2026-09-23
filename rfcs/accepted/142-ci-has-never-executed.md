# RFC 142 — CI runs, and four of its gates are red

> **Retitled 2026-09-25.** The original title, "No CI workflow has ever run",
> was false. See §9.

**Status.** Accepted — approved by the owner 2026-09-24.
**Tier.** P1 · Category B — every gate this project has built is unproven where
it is supposed to run.
**Size.** Small to start, unknown to finish — the first run is a measurement.
**Touches.** `.github/workflows/`, possibly any gate that fails there.
**Found by.** The 2026-09-24 state review; the condition has been recorded in
every release note since 0.83.0.

## 1. Summary

**Corrected 2026-09-25 by measurement — see §9 for what this said before and why
it was wrong.**

cesauth has **13** workflows. They have run **~1,650 times since 2026-04-23**,
on every push to `main` and on schedule. What had *never* run was the
`pull_request` trigger, and `fuzz`, which is path-filtered to pull requests.

The real gap is narrower and worse than "CI has never run": **CI runs, four
gates are red, and nothing is required.** `main` has **no branch protection**,
so every failure has been advisory since April.

## 2. What is established

Measured 2026-09-24 against the GitHub API, and re-verified by the architect:

- **`main` is unprotected.** `gh api …/branches/main/protection` → `404 Branch
  not protected`. **This part was always true**, and it is the whole of the
  enforcement gap.
- **13 workflows, all active; ~1,650 runs**, all `push` or `schedule`.
  **Zero `pull_request` runs** until RFC 142's own measurement, and `fuzz` had
  never run at all.
- **Nine gates are green** on both triggers; **four are red**: `fuzz`,
  `Worker bundle size budget`, `Worker build`'s `runtime-smoke` job, and
  `Browser tests`.
- **`Worker bundle size budget` has never once passed** — 149 of 149 runs
  failed — so the 2.5 MiB gzip budget it exists to enforce **has never been
  evaluated**.
- Three releases (0.84.0–0.84.2) carry "not that any CI gate is enforced". That
  sentence is still true, for the reason above rather than the one first given.

## 3. Why it matters

The project's quality rests on gates: 188 route contracts, a drift scan, a
runtime smoke check, a browser suite, six-crate clippy, deny, audit, migration
chain. **"We have gates" and "the gates hold" are different claims**, and only
the second protects anything. Today a change could be merged that breaks every
one of them.

It is also the cheapest large gap in the project: the work is to run what
already exists and fix what it reveals.

## 4. Proposed approach

**M1 — run them, and report before fixing.** Open a pull request that touches
enough paths to trigger every workflow, and record, per workflow: did it start,
did it pass, and if not, what failed.

**Expect failures, and expect them to be environmental.** Named in advance so
nobody treats them as surprises:

- toolchain and tool installs that have only ever run locally (Trunk, Binaryen
  fetch, `worker-build`, mdbook, Playwright browsers);
- `npm ci` and the pinned wrangler on a clean runner;
- anything needing configuration that exists only in `.dev.vars` — the runtime
  smoke check and the browser suite start `wrangler dev`, and **CI has no
  secrets**;
- the four `wrangler`-driven gates, which have never run anywhere but here.

**The standing rule, and it is the point of the RFC:** **do not weaken a gate to
make CI green.** If a gate cannot run in CI, report it and say what it would
need; a gate that passes by being made lenient is worse than one that does not
run, because it then lies in every future run.

**Then the owner enables branch protection** and adds the required checks. That
is a repository setting nothing in the tree can do; this RFC names it as the
acceptance step.

## 5. Non-goals

- Not adding gates. Nothing new is introduced until what exists runs.
- Not SHA-pinning Actions (RFC 138 decided that).
- Not a deployment. RFC 142 stops at CI.

## 6. Acceptance criteria

1. Every workflow has executed at least once, with its result recorded.
2. Each failure is either fixed, or recorded with the reason and what it needs.
3. **The owner has added the required status checks**, and a release note can
   say a gate is enforced without qualification for the first time.
4. `contributing.md`'s gate table states, per gate, whether CI enforces it —
   replacing "has not yet executed in CI", which appears three times today.

## 7. Level

**Patch.** Gates that were supposed to run start running; no product behaviour
changes. If a workflow fix changes a gate's meaning, that is a finding to report
first.

## 8. Risk

The first run may reveal that several gates cannot work in CI without secrets or
significant setup. That is information the project does not have, and is the
reason M1 reports before anyone fixes anything.

## 9. Premise corrected (2026-09-25)

This RFC was written on a false claim of mine: *"No CI workflow has ever run …
the workflow YAML has never been parsed by anything."* The measurement it
commissioned disproved it in its first paragraph.

**What was true:** `main` has no branch protection, so no check is required, and
the browser suite's "blocking" is prose. That is the gap, and it is real.

**How the false part got in.** Earlier packages recorded that `worker-build.yml`
"has never executed in CI" — which was a compressed form of something true:
before RFC 131 C1-R5 installed Trunk, those jobs **failed at their first step**
and had never *succeeded*. "Never passed" decayed into "never ran" as it was
copied forward into three release notes, `contributing.md`'s gate table, and
then this RFC, where I generalised it from one workflow to all of them.

**My own error on top of that.** I verified branch protection with `gh api` and
never ran `gh run list` — the adjacent query, with the same tool, in the same
session. I checked the claim I doubted and assumed the one I had inherited.

**The lesson, and it is the same one this project keeps relearning:** a claim
repeated across documents is not evidence, and the cheapest check is the one
nobody runs because everybody already believes the answer.

## 10. Cycle 1 — the four red gates are green (2026-09-25)

`1142ef8` … `6e2c360`, each fix with its own CI run, verified by the reviewer.

- **`fuzz`** — `fuzz/` was never in the workspace's `exclude`, so `cargo fuzz`
  could not build it. Excluded; the target now runs: **11,727,426 executions in
  61 s**. Its first run in the project's history.
- **`bundle`** — two defects. The gate never built the frontend, so
  `[assets] directory` did not exist; and once it did run, it measured
  **`shim.js`, 10,698 bytes, 1.3% of the artifact**, and reported `Usage: 0%`.
  A green gate that measures the loader is a gate that cannot fail. It now sums
  every uploaded module and **fails if no `.wasm` is present**, so it cannot
  regress to the loader. **The 2.5 MiB budget has been evaluated for the first
  time in 149 runs: 811,575 B gzip, 30%.**
- **`runtime-smoke` and `browser-tests`** — both died at their readiness
  deadline during a **214 s / 219 s cold Worker compile**. Both now build the
  Worker in their own step; **warm startup is ~10 s** against unchanged 60 s and
  180 s deadlines. Raising a deadline would have needed ~4× the real startup
  time and would have measured nothing.
- **Secrets, the RFC's original prediction, answered:** `wrangler dev` serves
  the public unauthenticated surface on a clean runner **with no `.dev.vars`**.
  Routes that sign or verify were not exercised and are not claimed.

**Thirteen job-level checks are green** at `3a88c20`. `fuzz` stays outside any
required set: its `paths:` filter means a required check would never report on
most pull requests (§2.3 of the M1 ruling).

**Still outstanding — the owner's:** branch protection. Nothing is enforced
until the checks are required, and the four fixed checks are proven on `push`
but not yet on `pull_request`; one throwaway draft PR should confirm them before
enforcement.

**Follow-ups, recorded not scheduled:** `fuzz/` has no committed `Cargo.lock`,
so its dependencies float per run; `cargo install trunk` costs ~5 minutes in
each of four jobs and is an obvious caching candidate.
