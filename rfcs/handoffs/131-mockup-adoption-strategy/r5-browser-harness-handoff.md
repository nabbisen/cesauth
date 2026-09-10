# Developer Handoff — RFC 131 R5b–e, browser harness

**Governing RFC.** [`rfcs/accepted/131-mockup-adoption-strategy.md`](../../accepted/131-mockup-adoption-strategy.md) §5 R5
**Scope.** **R5b, R5c, R5d, R5e only.** R2b, R3, R4 are not in this unit.
**Companion.** [`implementation-handoff.md`](./implementation-handoff.md) —
R2a + M1, both complete. That document is the record of what was dispatched
then; this one supersedes its R5 sections.
**Target release.** 0.83.0 — **and why that level:** **minor.** A CI-gated
browser suite is capability this project has never had, and it changes what
"green" means for every future contributor. Nothing here is a fix.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. M1's three blockers are cleared (§3).

---

## 1. Purpose

cesauth has never been verified in a browser. After this, something opens a
page, waits for the application to render, and fails if it does not.

## 2. Why this matters, and what it is *not* duplicating

`scripts/runtime-smoke-check.sh` already asserts, via `curl`: `/` and `/login`
return 200 HTML with a CSP header, the three `detail.json` routes reach their
handlers, an unregistered route 404s, every asset the shell references resolves,
and no panic appears. **Do not re-implement any of that in Playwright.**

R5's job is the layer `curl` structurally cannot reach:

- Does the WASM bundle **instantiate**?
- Does Leptos **mount** — is `<div id="root">` non-empty after load?
- Are there **console errors** or unhandled rejections?
- Does the rendered page satisfy the accessibility, duplicate-id, focus and
  viewport properties the mockup's specs already encode?

Every gate in this project's history has measured one layer above the thing that
mattered. This is the layer below the current bottom.

## 3. M1 is resolved — the three blockers, and what fixed each

| Blocker | Fixed by |
|---|---|
| `worker-build` floated to 0.8.5, whose `--force-enable-abort-handler` fails on wasm-bindgen ≥0.2.126 | RFC 131 C1-131 — pinned `0.8.4`, wasm-bindgen family → 0.2.128 |
| `/` served `dist/index.html` by Static Assets, shadowing the Worker | RFC 131 C2-131 — `make build-frontend` deletes it |
| `worker`'s router panicked on construction, so **no** route resolved | RFC 134 — three `:param.json` patterns reshaped; `worker` pinned `=0.8.3` |
| The shell's own assets 404'd, so `init()` never ran | RFC 134 C1-134 — output nested under `dist/assets/` |

`wrangler dev` now serves pages with no credentials, no `.dev.vars` and no D1
migrations — measured, not assumed (C1-131 §6). Playwright can point at
**`http://localhost:8787`**.

## 4. Facts already measured — do not re-derive

Mockup at `~/Desktop/cesauth/cesauth-mockup-git`, pinned `df3d9d0` (v0.14.0).
Its `e2e/` holds **7 specs**, `@playwright/test ^1.49.0`, `axe-playwright ^2.0.0`,
`baseURL http://127.0.0.1:3000`.

| Spec | Disposition |
|---|---|
| `accessibility`, `duplicate-ids`, `focus-trap`, `mobile-layout` | **Portable** — adapt (R5b) |
| `route-smoke` | **Rewrite.** Its route list is the *mockup's*: of 9 sampled, 5 do not exist in cesauth and `/magic-link/request` is `POST`-only |
| `hydration-smoke` | **Drop (R5c).** "Verifies SSR output hydrates" — cesauth has no SSR and no hydration; it is CSR-only |
| `devpanel-absent` | **Invert (R5d).** Assert no `data-workbench-only` element reaches cesauth's output — it becomes an import-safety check |

*If any of this fails to reproduce, that is a finding — report it.*

## 5. Report-and-stop: the first render

**Before adapting any spec**, do the minimum thing: open `/login` in Playwright,
wait for the application to render, and report what you see.

`/login` alone answers the central question, because it loads the same bundle
through the same mount path as every other CSR surface.

Three outcomes, **all of them fine**:

1. **It mounts.** `<div id="root">` is populated. Proceed to §6.
2. **It does not mount.** Root stays empty, or the console carries an error.
   **Stop and report, with the console output.** This is the thing five
   releases of reviews have said was unverified. It is a finding of the first
   order, it is not yours to fix, and it changes the programme's sequencing.
3. **It mounts but renders something wrong.** Report what, and stop.

Do not debug outcome 2 or 3. Re-scoping is mine.

## 6. Change scope

| # | Task |
|---|---|
| M2 | Open `/login`, report the render. **Stop.** (§5) |
| R5b | Adapt `accessibility`, `duplicate-ids`, `focus-trap`, `mobile-layout`; rewrite `route-smoke` against cesauth's real public routes |
| R5c | Drop `hydration-smoke`. Say so in the review — do not adapt it into something vacuous |
| R5d | Invert `devpanel-absent` into a `data-workbench-only` absence check |
| R5e | CI job — **non-blocking for one release**, see §8 |

Order: **M2 → report → R5b → R5c → R5d → R5e.** The gate lands last.

## 7. Public pages only. Do not authenticate

Every assertion runs unauthenticated. `/`, `/login`, and any terminal error page
that renders without a session.

A gate that needs a session is a gate that gets disabled the first time session
handling changes — the same reasoning that kept `runtime-smoke-check.sh` to 401
assertions rather than logging in. `/me/security` and the console screens are
**out of scope for R5**; they arrive with R3, when there is something to test.

## 8. The one deliberate deviation from house rule, and its bound

Every gate in this project lands blocking. **R5e lands non-blocking for one
release**, then flips.

A browser suite's first contact produces flakes indistinguishable from findings
— timing, fonts, viewport, animation. Landing blocking means the first flake
either stops the project or gets silenced, and this project has a rule against
silencing.

**The bound, not optional:**
- **Not** `continue-on-error: true`. A separate non-required job, so results are
  visible and recorded, never swallowed.
- A dated comment in the workflow naming the release that flips it.
- **Flipping it to blocking is an acceptance criterion of 0.84.0**, and I will
  check. A non-blocking gate that stays non-blocking is decoration.

If your flake data says it should land blocking immediately, say so in the
review — I would rather be argued out of this with evidence.

## 9. Supply chain

This brings Playwright's browser downloads into CI. C1-130 checksum-verifies the
Binaryen download and C1-131 pinned `worker-build` for the same reason: pin
`@playwright/test` and `axe-playwright` to exact versions, commit the lockfile,
and use Playwright's own pinned browser revisions — never "latest". If verifying
the browser download needs more than that, **report it**; an unverified binary
download in CI is a decision, not a detail.

## 10. Explicit non-change scope

- **No mock fixtures committed, at any step.** The owner's standing instruction:
  *"Don't take the actual security risk into the production codebase."*
- No R2b (the locale mechanism — deferred with RFC 132 §13 q1), no R3, no R4.
- No `format!` template deletions; pre-auth templates are **kept**.
- Do not touch `/` or `/login`'s rendering mode — RFC 132 §8's three gaps are
  R3's, and R3 needs §13 q1 answered.
- Do not duplicate `runtime-smoke-check.sh` (§2).
- Nothing under `crates/` unless a finding requires it — and then report first.
- No `cargo fmt`, no route-string changes.

## 11. Required tests and evidence

The full gate set as in the RFC 129 handoff §9, **plus**:

```sh
bash scripts/runtime-smoke-check.sh > evidence/runtime-smoke.log 2>&1
cd e2e && npx playwright test        > ../evidence/playwright.log 2>&1; cd ..
```

Expected: **1,233 passed, 0 failed**; route contracts **188**; runtime smoke all
10; everything else exit 0.

Plus:

- **M2's result first**, with the console output, before anything else.
- **R5e fires:** break one spec's expectation → the non-required job reports red
  and is visible in the run; restore → green. A non-blocking gate still has to
  be shown to detect something.
- The specs dropped or inverted, each with its reason.

**Counts in prose are measurements** — attach the command for every number.

## 12. What must NOT be claimed

- **Not that the frontend works.** After this, some public pages have browser
  coverage on the engines Playwright runs. That is enormously more than none,
  and it is not the same as verified.
- **Not that authenticated screens render.** None are tested (§7).
- **Not that it works on Cloudflare.** Miniflare only; nobody has deployed this
  tree.

## 13. Prohibited shortcuts

- No `continue-on-error: true` — §8's non-blocking job is a *visible*
  non-required job, a different thing.
- No authenticating.
- No committed fixtures, transiently or otherwise.
- No weakening an assertion to make a flake pass. §8 exists for that.
- No `cargo fmt`.

## 14. Acceptance criteria

RFC 131 §9 **item 5** only — Playwright suite in CI, demonstrated to fire —
amended by §8: non-blocking for one release, with the flip as 0.84.0's
criterion. Item 7, full gate set green.

**Expected unmet, declared in advance:** items 3, 4, 6 and 8 belong to R3/R4.
And nothing here proves an authenticated screen works.

## 15. Known risks

| Risk | Mitigation |
|---|---|
| M2 finds the app does not mount | §5 outcome 2 — stop and report. The most valuable thing this slice could produce |
| Playwright flake reads as a defect | §8's bounded observation window |
| The non-blocking gate stays non-blocking | 0.84.0's acceptance criterion |
| CI cannot run browsers | Report — do not weaken assertions to fit |

**If the work turns out materially larger than scoped, stop and report.**

## 16. Review request

Write the package to `.git-exclude/review-request/`. M2's result first, then:
implementation summary · changed files · deviations from §6 · every log from
§11 · R5e's fires/does-not-fire pair · specs dropped or inverted with reasons ·
what remains unverified (§12) · requested review focus.

**Do not cut a release, bump a version, or create a tag.** Implementation only;
0.83.0 is cut separately and the tag is the owner's alone.

Report the path only.
