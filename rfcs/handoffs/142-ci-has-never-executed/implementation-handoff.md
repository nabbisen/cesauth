# Developer Handoff — RFC 142, no CI workflow has ever run

**Governing RFC.** [`rfcs/accepted/142-ci-has-never-executed.md`](../../accepted/142-ci-has-never-executed.md)
**Target release.** 0.84.3, alongside RFC 133 half A. **Level: patch** — gates
that were supposed to run start running.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing you own. **The last step is the owner's** (§3).
**Runs in parallel with RFC 133 half A**: that touches `Makefile` and
`BUNDLE_SIZE_BUDGET.md`, this touches `.github/workflows/`. If you find yourself
editing the other's files, stop and report.

---

## 1. Purpose

Eleven workflows exist. **None has ever executed.** After this, each one has run
at least once, every failure is either fixed or recorded with what it would
need, and the repository can require them.

## 2. This is a measurement first

**M1 — run them and report before fixing anything.** Open a pull request that
touches enough paths to trigger every workflow, and record per workflow: did it
start, did it pass, and if not, what failed and at which step.

**Report before you fix.** The point is to learn what CI does with this
repository, and a package that arrives with eleven workflows already edited
tells me nothing about what was wrong.

## 3. What is not yours

**The owner adds the required status checks in branch protection.** `main` is
currently unprotected (`gh api …/branches/main/protection` → `404 Branch not
protected`), so nothing in the tree can make a check required. Your package
reports which checks are ready to be required; the setting is theirs.

**Do not claim any gate is enforced.** Three releases have had to qualify that
sentence; do not add a fourth by overstating this one.

## 4. Expect these, and do not paper over them

Named in advance so they read as measurements rather than surprises:

- **Tool installs that have only ever run here**: Trunk, the Binaryen fetch,
  `worker-build`, mdbook, Playwright's browsers.
- **`npm ci` and the pinned wrangler** on a clean runner.
- **Configuration that exists only in `.dev.vars`.** The runtime smoke check and
  the browser suite start `wrangler dev`; **CI has no secrets**. If a job needs
  `JWT_SIGNING_KEY` or similar to get past startup, that is a finding: report
  what it needs, and do **not** invent a secret in the workflow file or commit a
  test key.
- **The four wrangler-driven gates**, which have never run anywhere but this
  machine.
- **Workflow YAML that has never been parsed.** A syntax error is possible and
  would surface as "workflow did not start".

## 5. The rule that matters most

**Do not weaken a gate to make CI green.**

- No `continue-on-error`. No `|| true`. No narrowing a check's scope, lowering a
  threshold, dropping a crate from a command, or adding `#[ignore]`.
- If a gate cannot run in CI as written, **report it with what it would need**.
  A gate that passes by being made lenient is worse than one that does not run,
  because from then on it lies in every run.
- If a gate fails because it found something **real**, that is the RFC working.
  Report it; the fix may not belong to this cycle.

## 6. Change scope

| # | Task |
|---|---|
| T1 | **M1**: trigger every workflow; record start/pass/fail and the failing step. **Report and stop.** |
| T2 | After my ruling: fix what can be fixed without weakening anything, one workflow at a time, each with its CI run as evidence |
| T3 | Record per gate, in `docs/src/expert/contributing.md`'s gate table, whether CI runs it — replacing "**Has not yet executed in CI**", which appears three times today |
| T4 | List, for the owner, exactly which checks are ready to be required, by their check name as GitHub shows it |

## 7. Non-goals

- **No new gates.** Nothing is added until what exists runs.
- No SHA-pinning of Actions (RFC 138 settled that), no Node version pin
  (RFC 138 §11.9), no deployment — RFC 142 stops at CI.
- Not RFC 133's files.

## 8. Evidence

- **Per workflow**: a link or run id, the result, and for a failure the step and
  the error, quoted.
- **A table of the eleven**, so "every workflow has run at least once" is
  checkable rather than asserted.
- For anything unfixable: what it needs, in one line, and whether it is a
  repository setting, a secret, or a code change.
- Local gates are **not** the evidence here — the whole point is what happens in
  CI. Do not substitute a local run for a CI run anywhere in the package.

## 9. What must NOT be claimed

- Not that any gate is enforced (§3).
- Not that a workflow "should" work because it works locally.
- Not that the YAML is valid because CI accepted one file — say which ones ran.

## 10. Acceptance criteria

RFC 142 §6. Checked hardest: **every workflow has a recorded result**, and
**nothing was weakened to obtain a green run** — I will read the diff for that
specifically.

## 11. Review request

To `.git-exclude/review-request/`: M1's table first, then anything you fixed
after my ruling, T3's gate table, T4's list for the owner, and §9's list.

**Do not cut a release, bump a version, or create a tag.**

Report the path only.
