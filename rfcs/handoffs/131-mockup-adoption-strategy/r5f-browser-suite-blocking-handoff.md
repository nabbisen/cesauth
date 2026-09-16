# Developer Handoff — RFC 131 R5f, the browser suite becomes blocking

**Governing RFC.** [`rfcs/accepted/131-mockup-adoption-strategy.md`](../../accepted/131-mockup-adoption-strategy.md) — R5, and the acceptance criterion *"Playwright suite in CI, blocking, demonstrated to fire."*
**Target release.** 0.84.0, alongside RFC 140 and RFC 139 (+C1-139). **Level:
minor**, decided by RFC 139's idle window; this slice alone would be a patch.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing you own. **One step is the owner's** — see §3.

---

## 1. Purpose

The browser suite has been non-blocking for one release, by design
(`browser-tests.yml:1, :13-36`). 0.84.0 is where that window closes. After this,
the 20 Playwright tests over `/` and `/login` are a gate: a change that breaks
the only browser-level verification cesauth has stops the merge.

## 2. Why this matters

`.github/workflows/browser-tests.yml:36` states the reason better than I can:
**"an indefinitely non-blocking gate is decoration."** The suite already
exists, already runs, and already passes 20 tests. Everything that remains is
making its verdict count, and saying so honestly in the places that currently
promise it does not.

## 3. The owner's step, and what it means for you

The workflow is non-blocking **by not being a required status check** in branch
protection (`browser-tests.yml:19-22`), not by anything in the file. **Only the
owner can add `browser-tests` to the required checks**; it is a GitHub
repository setting.

So:

- **You cannot make it blocking, and you must not claim you did.**
- **Do not** add `continue-on-error: true` or remove one. The file's own comment
  (`:22`) explains why that would be worse than useless: the job would report
  success while failing.
- Your work is everything around it: the file's header, the documentation, and
  the evidence that the suite actually fails when the product is broken.
- The release readiness report will carry the owner's step. Flag in your package
  that it is outstanding.

## 4. Change scope

| # | Task |
|---|---|
| T1 | **`browser-tests.yml`**: the workflow `name:` drops "(non-blocking until 0.84.0)". Replace the `:13-36` comment block with a short note: blocking as of 0.84.0, enforced by branch protection's required checks, and the standing rule that a flake is fixed or the test deleted, never made non-blocking again. Keep the explanation of why `continue-on-error` is not how this is done |
| T2 | **Every other place that calls it non-blocking.** Find them; `docs/src/expert/contributing.md`'s gate table is one. Give the command you used and a disposition per hit, as C1-138 did for `npx wrangler` |
| T3 | **Demonstrate it fires** (§5) |

## 5. Required evidence

**Fires / does-not-fire, the criterion RFC 131 names.** Break the product, not
the test:

- Make `/login` fail to mount — for example by breaking the mount target in the
  shell, the way RFC 135's defect did. Run `(cd e2e && npx playwright test)`
  against `node_modules/.bin/wrangler dev`, and capture a **non-zero exit** with
  the failing test names.
- Restore, `cmp` byte-identical, and capture **20 passed**.

Do not simulate the failure by editing a spec, and do not use a
never-existed-URL trick: the point is that a broken *page* fails the suite.

**Gate set.** The full set as usual, since T1 touches a workflow: host tests
(baseline **1,453**, stated with its command), `migration_chain`, wasm32 and csr
checks, clippy over six crates, deny, audit, route-contracts, drift-scan
`--verbose`, mdbook, `make build-frontend` with `du -b`, gzip and `sha256sum`,
`make build-backend`, runtime smoke, and the browser suite — each wrangler gate
showing 4.131.2.

I re-run the browser suite and the fires pair myself.

## 6. Explicit non-change scope

- **No new browser tests**, no change to the 20 that exist, no screenshot
  baselines (RFC 131 R5 rejected them, with reasons).
- No `continue-on-error`, anywhere.
- Not RFC 140, RFC 139 or C1-139. Not the browser suite's own dependencies or
  Playwright's version.
- No route strings. No `cargo fmt`.

## 7. What must NOT be claimed

- **Not that the suite is blocking.** Until the owner adds the required check,
  it is not. The honest wording is: the workflow is ready to be required, and
  the repository setting is outstanding.
- **Not that it has ever run in CI as a gate.** It has not.
- Not that the frontend is verified beyond 20 tests on one unauthenticated,
  unstyled page.

## 8. Acceptance criteria

RFC 131 R5's *"Playwright suite in CI, blocking, demonstrated to fire"*, with
the blocking half explicitly split: **demonstrated to fire** is yours and is
checked hardest; **blocking** is the owner's setting, recorded as outstanding.

## 9. Review request

To `.git-exclude/review-request/`: implementation summary, changed files, T2's
command and per-hit dispositions, the fires pair with its logs, the gate set,
and what remains unverified (§7).

**Do not cut a release, bump a version, or create a tag.**

Report the path only.
