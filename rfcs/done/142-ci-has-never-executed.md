# RFC 142 — CI runs, and four of its gates are red

> **Retitled 2026-09-25.** The original title, "No CI workflow has ever run",
> was false. See §9.

**Status.** Implemented (v0.84.3). **Criterion 3 amended and closed as a deliberate non-goal, 2026-10-24** — §14: enforcing the gates requires a pull-request workflow this project does not want, and the attempt cost commit signatures.
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

## 11. Enforcement confirmation (2026-10-24)

Draft PR #9 off the `0.84.3` tag, closed unmerged with its branch deleted.
**Fourteen checks reported on the `pull_request` trigger and all fourteen were
green** — the thirteen required candidates plus `jwt_parse (libFuzzer, 60s)`.
Verified by the reviewer, together with each workflow's `on:` block read
directly: **12 workflows fire on both `push` and `pull_request`**, one of them
(`worker-build.yml`) contributing two jobs, which is where the thirteen come
from; **`fuzz` fires only on `pull_request` and `workflow_dispatch`.**

**The thirteen to require:** `test`, `clippy`, `deny`, `cargo audit`,
`csr-check`, `route-contracts`, `stale-phrase check`, `mdbook`,
`trunk-release-build`, `worker-build`, `runtime-smoke`, `browser-tests`,
`bundle`. **Never `jwt_parse (libFuzzer, 60s)`**: its `paths:` filter means a
required check would never report on a pull request that touches neither
`crates/core/src/jwt/**` nor `fuzz/**`, leaving it blocked indefinitely.

**This RFC remains open.** Criterion 3 is the owner's repository setting, and
until it exists no gate is enforced — the sentence four consecutive releases
have had to carry.

## 12. A correction to how "unprotected" was verified (2026-10-24)

Every "`main` is unprotected" claim in this RFC, in the M1 report and in four
release notes was evidenced by:

```
gh api repos/{owner}/{repo}/branches/main/protection   → 404 Branch not protected
```

**That endpoint reports only *classic* branch protection.** GitHub's current and
recommended mechanism is **repository rulesets**, which that endpoint does not
see: a repository fully governed by a ruleset still answers `404 Branch not
protected`. The check could not have distinguished "nothing is enforced" from
"enforced by the modern mechanism", and it was cited as though it could.

**Re-verified with checks that see both**, 2026-10-24:

```
gh api repos/{owner}/{repo}/rulesets              → (empty)
gh api repos/{owner}/{repo}/rules/branches/main   → []  no rules in effect
```

**The conclusion held** — nothing is enforced — but it held by luck, not by
method. `…/rules/branches/{branch}` is the authoritative check, because it
returns the rules **in effect** for a branch from every source (classic
protection, repository rulesets, and organization rulesets). That is the command
this RFC and any future readiness report should use.

This is the same defect class the RFC itself documents in §9: a check that
quietly answers a narrower question than the one being asked. It was mine both
times.

## 13. Enforced (2026-10-24) — criterion 3 met, and the RFC closes

Applied by the architect on the owner's instruction, with `gh api`, and verified
by reading the configuration back.

**Branch ruleset `main`** (id 25763711), target `~DEFAULT_BRANCH`, enforcement
**active**, **zero bypass actors**:

| Rule | Configuration |
|---|---|
| `required_status_checks` | the **thirteen** job names, `strict_required_status_checks_policy: true` |
| `pull_request` | `required_approving_review_count: 0`, `require_last_push_approval: false`, `allowed_merge_methods: [squash, rebase]` |
| `required_linear_history` | — |
| `deletion`, `non_fast_forward` | — |

**Tag ruleset "release tags are immutable"** (id 25763743), target all tags,
enforcement active, zero bypass actors: `deletion`, `non_fast_forward`,
`update`. The documented invariant — versions are never reused, a bad release is
superseded rather than re-tagged — is now enforced.

**Zero required approvals, stated as a decision rather than an oversight.** A
single-actor repository cannot self-approve; requiring one approval would
deadlock every pull request and force a bypass actor, which would hollow out the
arrangement exactly as §2.3 warns. The quality bar here is the thirteen checks
plus the architect/implementer review cycle, not a GitHub approval.

### 13.1 What could not be enforced, measured not assumed

**Metadata restriction rules are unavailable on this repository.**
`tag_name_pattern` was rejected in four shapes (`regex` and `starts_with`, with
and without a display name), and `commit_message_pattern` was rejected the same
way on a branch target:

```
422 Validation Failed — Invalid rule 'tag_name_pattern'
```

So **"tags are bare `X.Y.Z`, no `v` prefix" cannot be enforced by a ruleset
here**, though all 121 existing tags match it. It remains a convention.

**Follow-up worth having:** a tag-triggered workflow that asserts the tag name
matches `^[0-9]+\.[0-9]+\.[0-9]+$` and fails loudly otherwise. It is a few
lines, it needs no plan features, and it converts the last unenforced release
invariant into a check. Recorded, not scheduled.

### 13.2 What this changes about how work lands

`main` no longer accepts direct pushes — not from the architect, not from the
implementer. Every change is a branch and a pull request, merged with `--rebase`
(preserving a cycle's individual commits, which are often themselves the
evidence) or `--squash`. **The release process is unchanged in substance**: the
version bump and CHANGELOG arrive as a pull request, and the signed tag is
created on `main` after the merge.

One consequence to record honestly: a rebase or squash merge produces commits
created by GitHub, so **commits on `main` are signed by GitHub's key rather than
by the owner's**, where previously every commit carried the owner's signature.
Tags are still signed by the owner, so the release record's provenance is
unchanged. `required_signatures` was deliberately **not** enabled: GitHub
reports current commits as `verified=true, reason=valid`, so it would be
satisfiable, but it should be tested against a real merge before being required,
and that test is the first pull request under this regime.

## 14. Criterion 3 reversed — enforcement is a non-goal here (2026-10-24)

**The owner ruled, the same day it was enabled, that this project should share
`main`:** they relay between architect and implementer and never run them
concurrently, so a branch normally coordinates nothing. Branches are not
forbidden — they are allowed where they genuinely earn their cost — but they are
not the default, and nothing about CI enforcement justified one. The branch ruleset's
`pull_request` and `required_status_checks` rules are therefore removed; the
protective rules stay.

**The structural reason this was a trade, not a free win.** A required status
check can only pass on a commit that already exists, so requiring checks on
`main` *necessarily* forces every change through a pull request. There is no
configuration in which GitHub enforces these gates and the project keeps
pushing to `main`. Enforcement and this workflow are mutually exclusive.

**What the attempt cost, measured.** One pull request was opened and merged
(#10). Its rebase merge produced `c0037a1`, **`verified=false, reason=unsigned`**,
where the preceding direct push `c5761d3` was `verified=true, reason=valid`
(§13.3). **One unsigned commit is now in `main`'s history**, and it will stay
there: rewriting history to remove it would be worse than the blemish. Every
commit after the reversal is signed again, because a direct push preserves the
signature a rebase merge discards.

**So criterion 3 is amended rather than met.** Its original wording — *"the
owner has added the required status checks, and a release note can say a gate is
enforced without qualification for the first time"* — assumed the
GitHub-conventional answer was the right one for this repository. It is not. The
amended criterion:

> **CI runs every described gate on every push and reports the result.** No
> check blocks, by design. Release notes continue to say so, and that sentence
> is now a statement of the chosen design rather than an admission of a gap.

**What the RFC did achieve, and it is most of its value:** the four gates that
had never passed now pass, the Worker's size budget is evaluated for the first
time in 149 runs, fuzzing runs at all, and the project knows — measured — what
CI does and does not do. Only the enforcement half is withdrawn.

**What still protects `main` and the release record** (no branch required):
restrict deletions and block force pushes on `main`, require linear history,
and a tag ruleset blocking deletion, update and force-push on every tag. The
last one makes "versions are never reused" enforced for the first time.

**My error, for the record.** I reached for the conventional answer — required
checks, therefore pull requests — without asking whether a repository with no
concurrency wants them, and I was two decisions deep before the cost surfaced.

**And I mis-attributed the cost.** A pull request by itself does not lose a
signature: a **merge commit** would have preserved it. The loss came from
combining the pull-request requirement with `required_linear_history`, which
forbids merge commits and so left only rebase and squash — the two methods that
rewrite commits without re-signing them. The owner made this correction; my
first telling blamed pull requests for what my own rule combination caused.
The owner's correction is in `docs/src/expert/contributing.md`'s *How a change
reaches `main`*, which until today had never been written down at all.
