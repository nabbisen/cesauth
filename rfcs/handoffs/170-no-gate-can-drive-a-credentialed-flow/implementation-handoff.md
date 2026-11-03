# Developer Handoff — RFC 170: one CI job that can drive a credentialed flow

**Governing RFC.** [`rfcs/accepted/170-no-gate-can-drive-a-credentialed-flow.md`](../../accepted/170-no-gate-can-drive-a-credentialed-flow.md)
— **§4 is the specification and §5 is in scope too.** The owner accepted the
whole RFC, so both halves land: the credentialed job **and** RFC 147's sweep
refactor.
**Builds on.** `4432f48` on `main`. Tag `0.92.1` is `00b5ee0`, **13/13 CI
green**.

**Target release.** **Patch — the next cut after 0.92.1.** Number assigned at
the cut, not reserved here.
**Trigger: none, and here is the argument rather than the default.** No route,
no migration, no MSRV move, and nothing in the shipped Worker changes: the
product is byte-identical. What changes is what CI can *observe*. 0.91.1 and
0.91.2 are the precedent — gate work, shipped as patches.
**Tier.** **P2.** Nothing is broken. Two established findings cannot be closed
to `exercised`, and both were found by hand because no gate could find them.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-03.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. What this is for, in one paragraph

Every gate this project has runs without a credential. So two findings sit at
`observed` — driven once by hand, with a commit — and cannot reach `exercised`,
which needs a gate that fails when the behaviour stops working. **RFC 147's
deletion sweep** was driven by hand at `b0208ab`. **RFC 152 half A's admin
cookie attributes** have no witness on a live response, and **29 rows rest on
`SameSite=Strict`.** One job with migrated D1 and one seeded credential closes
both.

## 2. Half one — the job (§4)

1. **Apply migrations to a local D1**: `wrangler d1 migrations apply --local`,
   through the **pinned** wrangler at `node_modules/.bin/wrangler` — never a
   bare `wrangler`, which resolves whatever is on `PATH` (RFC 138).
2. **Seed one admin token row** and only the fixtures the two assertions need.
3. **Two assertions, as captures:**
   - **The deletion sweep.** Insert a due pending deletion request, trigger
     `/__scheduled?cron=0+4+*+*+*` against `wrangler dev --test-scheduled`, and
     assert: the user row is **gone**; the request reads `executed`/`sweep`; and
     the audit chain carries **`deletion_executed`** with `subject` = the
     deleted user. RFC 148's email scrub comes free in the same row's `reason`.
   - **The admin cookie on the wire.** Walk the **real two-step** `/admin/login`
     flow — `GET` with a bearer renders the confirmation page, `POST` verifies
     CSRF and then sets the cookie — and assert the `set-cookie` string carries
     `__Host-`, `SameSite=Strict`, `Secure`, `HttpOnly`, `Path=/`. It must fail
     loudly if any attribute is ever relaxed.

**Assert content and attributes, never status alone.** `contributing.md`'s
live-probe ruling was refined at the 0.92.1 cut for exactly this reason: where
two outcomes share a status code, the status is not evidence. A 200 from
`/admin/login` says nothing about the cookie.

## 3. The credential: how to seed one without ever holding a secret

- **Generate the token inside the job**, random, per run. **Never** commit one,
  never put one in the manifest, never `echo` it, and never write it to an
  artifact. Only its **sha256** goes into `admin_tokens.token_hash` — that is
  the only form the resolver reads (`admin/principal_resolver.rs:103`).
- Pass dev variables with `--var`. **Do not create or read a secrets file.**
- The job's own log must not contain the token. If a debug line needs to prove a
  request was authenticated, print the **status** and the principal's `name`,
  never the bearer.

## 4. The trap this job will hit, named in advance

**A cold `wrangler dev` outlasts its own readiness deadline.** `browser-tests.yml`
builds the Worker in a **separate, earlier step** for exactly this reason
(RFC 142 M1: a cold compile took ~3.5 minutes against a 180-second deadline and
the gate failed on every run). **Do the same**: build first, in its own step, so
that step is where a slow or broken build fails. **Do not raise the deadline** —
a longer wait hides a slow build.

**And warm it before asserting.** Stage 1b's Playwright run failed 16 of 20 on a
just-rebuilt worker at 24s per request, and I hit the same thing at the 0.92.1
cut. One throwaway request to `/login` before the real assertions costs nothing.

## 5. The manifest and the count — this gate fails on arrival otherwise

Adding a workflow moves numbers that three different things assert:

- **`.github/release-gate-manifest.json`**: add the new workflow's path to the
  **`release`** array. `release-gate-manifest-check.sh` derives its required set
  from that array, so an unlisted new workflow fails the check on the release
  commit — **and a listed-but-missing one fails too.** The release set becomes
  **14**, with the one `not_on_release_path` entry unchanged, so **15 workflow
  files**.
- **`docs/src/expert/contributing.md`** says *"thirteen workflows on every push
  … a fourteenth"* at **line 109**, repeats *"thirteen names are the `release`
  entries"* at **112**, and *"all thirteen checks"* at **189**. All three go
  false. Update them, and add the new job to the gate table in the same section.
- **Then make it unable to rot again.** `grep -n "thirteen" scripts/drift-scan.sh`
  returns nothing — the count is unguarded prose, which is this project's
  signature failure. **Add a stale-phrase pattern** for the superseded wording
  so the next workflow change cannot leave those sentences stale.

**Accepted RFCs that say "thirteen gates" (166, 168, 172) are historical
statements and stay as written** — they describe the tree at their own date.
Only the ruling book is required to be current.

## 6. Half two — RFC 147's sweep refactor (§5)

**Also in scope**, because the acceptance was of the whole RFC: lift
`sweep_pending_deletions`'s decision core into a **pure function over the
repository port** — the shape `execute_deletion` already has — and gate it on
the host.

It closes RFC 147 **without** a runtime, which is the better fix for that
finding specifically. It does **not** replace half one: no refactor makes a
`set-cookie` header observable without a response. **Separate commits.**

## 7. Scope fence — what this must not become

**Not a general e2e suite with fixtures everyone extends.** Two assertions,
each closing a named written finding. **A third arrives when a third finding
needs it, and the job's README says so in writing.** If you find yourself adding
a helper "for later", that is the line.

## 8. Evidence this cycle moves

- **RFC 147's deletion sweep: `observed` → `exercised`.** State it in the report
  with the job name, because RFC 000 §22's terms are only worth having if the
  transition is recorded.
- **RFC 152 half A's cookie witness: restored**, and 29 rows stop resting on an
  unwitnessed attribute.
- The job itself is a **capability**, not a finding — do not claim it closes
  RFC 171 §3 Q2, which needs it but is its own work.

## 9. Stop conditions

- **`wrangler dev --test-scheduled` cannot be driven in CI** — report what it
  does instead of working, with the output. Do not substitute a host test for
  the sweep assertion; that is the refactor in §6 and it is already in scope
  separately.
- **Seeding the admin token requires holding a secret anywhere but memory** —
  stop and report. There is no version of this worth a committed credential.
- **The readiness deadline cannot be met even with a separate build step** —
  report the timings; do not raise the deadline.
- **The manifest check fails for a reason §5 did not predict** — report it
  rather than editing the manifest until it passes.
- Either assertion can only be made by asserting a bare status code.

## 10. Baselines at `4432f48`, each with its command

- host tests, `cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend -p cesauth-backend -p cesauth-adapter-cloudflare --features cesauth-frontend/csr` → **1,690 passed, 0 failed, 4 ignored, 12 `test result:` lines**;
- `cargo test -p cesauth-migrate-test --test migration_chain` → **35**;
- `bash scripts/route-contracts-check.sh` → **194 routes**; E3 `47 scanned, 0 unexempted, 2 exempted`; GATE_42 `24 scanned, 0 shadowed, 0 absent, 0 exempted`; NONCE `13 call sites, 0 violations`; E4 `218 = 194 + 24 + 0`; E5 `17 = 17 + 0 + 0`; **E6 `94 = 85 claims + 9 declared + 0 unclassified`**, `85 = 67 + 0 + 18`;
- `bash scripts/drift-scan.sh` → clean; docs coverage `80 = 78 + 2 + 0`; docs links `189 seen = 177 checked + 6 absolute + 6 outside + 0 unresolvable`; `rfcs/` sweep **181 checked, 0 broken**; reconciliation `143 tags / 141 entries, 0 and 0 unexempted`;
- `mdbook build docs` → clean, 82 pages;
- `npx playwright test` in `e2e/` → **20** — needs `node_modules/.bin/wrangler dev --port 8787` **already serving and warm**;
- `bash scripts/runtime-smoke-check.sh` → passed;
- bundle, `./node_modules/.bin/wrangler deploy --dry-run --outdir bundled/`, **gzip 1.15 at its default level** → **896,990 B** (886,291 wasm + 10,699 `shim.js`), raw 2,453,743 + 61,887, measured at tag `0.92.1` after its version bump. **Expect it unchanged**: this cycle ships no Worker code. If it moves, something in §6's refactor reached the shipped build and you should say so.

**Name the command, the commit and — for any bundle figure — the gzip level.**
`-9` reads ~4.2 KB lower than the default on identical bytes, and that gap was
once mistaken for a cross-environment difference and written into an RFC
(RFC 133 §16).
