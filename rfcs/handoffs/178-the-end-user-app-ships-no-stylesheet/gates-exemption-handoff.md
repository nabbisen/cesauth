# Developer Handoff — RFC 178 §4b: stop the two gates blocking every cut, without stopping them reporting

**Governing RFC.** [`rfcs/accepted/178-the-end-user-app-ships-no-stylesheet.md`](../../accepted/178-the-end-user-app-ships-no-stylesheet.md)
— **read §0 first**, added at review: the finding was already on record in
RFC 135 §4 and RFC 131, and this RFC's contribution is the gates.
**Review.** `.git-exclude/reviewed/178-gates-review.md` — **§4 is the decision
this cycle implements.**
**Builds on.** `dd64ee2` on `main`. **Nothing is reverted; both gates stay.**

**Target release.** **Patch — the next cut.** **The cut is blocked until this
lands**: `Browser tests` and `Trunk release build` are both failing on `main`.
**Trigger: none** — gate policy.
**Tier.** **P1**, for the red gates rather than for the gap.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-07.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. The decision you handed back, and why it went this way

You were right to hand it back. Red-until-fixed is not available: the gap is
**RFC 131 R3's presentation wiring**, an unbuilt slice of an accepted
programme, so two red release gates would freeze every cut indefinitely —
worse than the state before the gates existed. Removing them is not available
either: that returns the project to documented-and-ungated, which RFC 135 §4
proves can persist for months.

**Your report asked "what would the exemption entry even name?" It names the
routes and the owning RFC.** That is the answer, and it is the
`E6_BEARER_LEGACY_EXEMPT` pattern, which this project already runs with 18
known-bad rows.

## 2. The Playwright gate — a named exemption that cannot outlive the defect

In `e2e/specs/stylesheet-presence.spec.ts`:

- **An exemption list**, one entry per route that is known to ship no
  stylesheet — today `/` and `/login`, which is every public route. Dated
  **2026-11-07**, citing **RFC 135 §4** and **RFC 131 R3** as the reason, under
  a comment saying the entry **must be deleted the day any author stylesheet
  appears**.
- **Three outcomes, not two:**
  1. route **not** in the list and has rules → **pass**;
  2. route in the list and has **zero** rules → **pass**, and print an `ℹ️` line
     naming the exemption and the owning RFC, so every run reports the gap;
  3. route in the list and **has** rules → **fail**, with a message saying the
     exemption is stale and must be removed so the gate can enforce.
- **(3) is the whole point.** It makes the exemption self-liquidating: the day
  R3 lands a stylesheet the build goes red until someone deletes the entry, and
  from then on the gate enforces permanently. Same discipline as RFC 165 §3,
  where an entry that stops matching is a hard failure.

**Do not reduce this to "skip when no CSS".** A skip is silent; outcome (2)
must print, and outcome (3) must fail.

## 3. The trunk step — reported, not enforced

`.github/workflows/trunk-release-build.yml`'s new step cannot remember a
previous state, so it cannot carry the staleness property. Make it **report and
exit 0**, keeping the message it already prints and adding the owning RFC, under
the precedent `contributing.md` already records for `wrangler build` and
`runtime-smoke-check` (RFC 142): *runs, reports, not enforced*.

**Leave one line that flips it to enforcing**, with a comment saying when —
when a `.css` lands, the `exit 0` becomes `exit 1` and the step is a real gate.
**Do not make it clever.** A shell step that tries to infer regression is worse
than one that reports honestly.

## 4. The ruling book, because this is the part that gets rediscovered

Add **both** gates to `contributing.md`'s gate table — the one with the
"Difference" column that already distinguishes enforced from reported. Each row
says which it is, and the exempted one says it is exempted, dated, and why.

**A gate whose enforcement status lives only in a spec file is the next thing to
be rediscovered**, which is the exact failure RFC 178 §0 is about. The table is
where a reader looks.

## 5. Do not

- **Do not write a stylesheet.** That is R3, and the owner has the queue
  decision.
- **Do not touch `crates/frontend/src/pages/`** or any template.
- **Do not weaken the assertion itself.** The rule count stays `> 0`; only the
  *policy* around it changes.
- **Do not remove either gate.**

## 6. Stop conditions

- **The staleness outcome (3) cannot be expressed** in the spec without
  duplicating the route list — report it; a duplicated list is the defect this
  pattern exists to avoid.
- **Any route turns out to have author rules today** — then the premise is
  wrong and I want to know before the exemption is written.
- **`contributing.md`'s gate table has no honest row shape** for an exempted
  gate — report what you would add rather than inventing a column.
- Making either gate green requires changing what it asserts.

## 7. Baselines at `dd64ee2`, each with its command

- host tests, `cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend -p cesauth-backend -p cesauth-adapter-cloudflare --features cesauth-frontend/csr` → **1,675 passed, 0 failed, 4 ignored, 12 lines**;
- `cargo test -p cesauth-migrate-test --test migration_chain` → **35**;
- `bash scripts/route-contracts-check.sh` → 192 routes, **E7 `156 = 8 + 31 + 117`**;
- `bash scripts/drift-scan.sh` → clean, `colour contrast: 22 = 19 + 3 + 0`;
- `mdbook build docs` → clean, 82 pages;
- `npx playwright test` in `e2e/` → **20 passed, 2 failed** today. **22 passed is this cycle's deliverable**, with the two reporting lines visible in the output;
- `bash scripts/runtime-smoke-check.sh` → passed;
- bundles **unchanged**: Worker **888,994 B**, frontend asset **317,718 B**, gzip 1.15 default. **Expect both unchanged** — this cycle touches a spec, a workflow and the ruling book.

**Keep the report short.** `CHANGELOG.md` has under 1 KB of headroom before
RFC 028's guard and the entry is mine to write at the cut.
