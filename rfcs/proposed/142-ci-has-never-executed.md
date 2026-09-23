# RFC 142 — No CI workflow has ever run

**Status.** Proposed
**Tier.** P1 · Category B — every gate this project has built is unproven where
it is supposed to run.
**Size.** Small to start, unknown to finish — the first run is a measurement.
**Touches.** `.github/workflows/`, possibly any gate that fails there.
**Found by.** The 2026-09-24 state review; the condition has been recorded in
every release note since 0.83.0.

## 1. Summary

cesauth has eleven workflows and a documented gate set. **None has ever
executed**, and `main` has **no branch protection**, so no check is required.
Every gate is proven only by hand, on one machine.

## 2. What is established

- `gh api repos/{owner}/{repo}/branches/main/protection` → **`404 Branch not
  protected`**, verified 2026-09-22 and unchanged.
- Three releases (0.84.0, 0.84.1, 0.84.2) carry "not that any CI gate is
  enforced" in their notes, and RFC 131 R5f's "blocking" browser suite is
  blocking only in the workflow's own prose.
- **The workflow YAML has never been parsed by anything**: no validator is
  installed locally, and GitHub has never read the files.
- `worker-build.yml`'s jobs and `docs.yml` have never started.

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
