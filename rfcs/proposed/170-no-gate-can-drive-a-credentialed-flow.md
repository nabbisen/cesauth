# RFC 170 — No gate can drive a credentialed flow, and two findings are stuck behind that

**Status.** **Proposed** 2026-11-01 by the architect, while scoping 0.92.
**Tier.** **P2.** Nothing is broken. Two established findings cannot be closed
to `exercised`, and both were found by hand because no gate could find them.
**Size.** **Medium**, and the honest reason it is medium rather than small is
that it adds a CI capability the project has never had: a job with migrated D1
state and a seeded credential.
**Touches.** `.github/workflows/` (one job, new or extended),
`scripts/`, possibly `e2e/`; no product code.
**Depends on.** Nothing. **Blocks** RFC 147's evidence term and half A of
RFC 152's live witness.
**Found by.** The architect, 2026-10-31, twice in one day — from opposite
directions — which is why it is an RFC rather than a note in two others.

**On 1.0:** not declared, not scoped, not dated. Nothing here is a 1.0
requirement.

---

## 1. Summary

**Every gate in the release set runs against an unmigrated database with no
secrets and no credential.** That is a deliberate, recorded decision —
`runtime-smoke-check.sh`'s own header states it (RFC 134 T4), and
`browser-tests.yml` applies no migrations and seeds no token either. It keeps
the gates fast and hermetic, and for most of what they assert it costs nothing.

**It costs two things, both now written down as gaps:**

1. **RFC 147's deletion sweep cannot reach `exercised`.** The deliverable —
   *deletion requests are actually performed* — runs from
   `#[event(scheduled)]` → `sweep_pending_deletions(&Env)` → `execute_deletion`.
   The core function has 15 unit tests. **Its caller has none and no test
   module**, because `&worker::Env` cannot be constructed on the host. RFC 151
   §4 named the test that would close it; that test does not exist. The term is
   `observed`, driven once by hand against `wrangler dev --test-scheduled`
   (2026-10-31, `b0208ab`) — and `observed` decays by design.

2. **Nothing observes the admin cookie's attributes on a live response.**
   RFC 152 half A pinned `SameSite=Strict` on `__Host-cesauth_admin` with a host
   test over the pure builder, plus a live check in `runtime-smoke-check.sh`
   that worked **only because the login handler set the cookie from an
   unvalidated placeholder token**. Half B stage 2 fixed that handler, correctly,
   and the live check had to be rewritten to assert the fix instead. The
   attribute is still pinned against a pure function; **nothing asserts it on
   the wire.**

## 2. Why that second one matters more than it looks

Across RFC 152's three shipped halves, **every documented CSRF control that
turned out to be absent was absent for the same reason, and survivable for the
same reason**: the admin cookie is `SameSite=Strict`, so a forged cross-site
request arrives with no credential.

- `required` on 34 tenant-admin/tenancy-console rows — absent (half B).
- `required` on 7 operator-console rows — absent (half C).
- `N/A (bearer)` on 18 rows — accept a cookie (half D, open).
- `N/A (JSON)` on 11 rows — the stated CORS preflight never happens, because
  the Fetch `Request.json()` these handlers call parses the body regardless of
  `Content-Type` and `text/plain` is CORS-safelisted (half D, open).

**That is 29 rows still resting on one cookie attribute**, which no contract row
names, and whose only guard is a host test asserting a string from a pure
function. A navigation-driven edit that relaxed it — the exact scenario half A
was written to make loud — would pass every gate in the release set except that
one unit test.

This RFC does not argue the attribute is wrong. It argues that **the single
most load-bearing line in the product's CSRF story has no witness on a real
response**, and that the reason is a missing capability rather than a missing
intention.

## 3. What is not established

- **Not** that either finding is a live defect. Deletion works — driven and
  recorded. The cookie carries the right attributes — asserted at its builder.
- **Not** that the hermetic-gate decision was wrong. It was measured and
  recorded, and most gates should stay that way. The proposal is **one** job
  with state, not a change of policy for the set.
- **Not** that this is the only use. A credentialed job would also make
  RFC 152's class A and class B flows, and half B stage 2's two-step login,
  assertable rather than re-walked by hand each cycle — but those are already
  `exercised` through unit tests at their decision boundaries, so they are a
  benefit, not the justification.

## 4. Direction

**One CI job, with the smallest state that closes both findings:**

1. Apply migrations to a local D1 (`wrangler d1 migrations apply --local`).
2. Seed one admin token row and the fixtures each assertion needs — the shape
   both hand-runs already used, and both are written down
   (`.git-exclude/reviewed/152-half-c-review.md`, RFC 147's Status block).
3. Assert, as captures:
   - **the deletion sweep**: insert a due pending request, trigger
     `/__scheduled?cron=…` against `wrangler dev --test-scheduled`, and assert
     the user row is gone, the request reads `executed`/`sweep`, and the audit
     chain carries `deletion_executed` with `subject` = the deleted user. That
     is RFC 147 at `exercised`, and RFC 148's email scrub comes free in the same
     row's `reason`.
   - **the admin cookie on the wire**: walk the real two-step `/admin/login`
     flow and assert the `set-cookie` string carries `__Host-` with
     `SameSite=Strict`, `Secure`, `HttpOnly`, `Path=/`. That is half A's live
     witness restored, and it fails loudly if the attribute is ever relaxed.

**On the workflow count.** The release set is 13 + 1 off-path = 14 workflow
files, and the manifest gate asserts it. This adds one, so **the manifest's
`release` list and the count both move to 14 + 1** — state that in the handoff
rather than discovering it at the gate, which is the kind of thing this project
has tripped over before.

**What this is not allowed to become.** Not a general e2e suite with fixtures
everyone extends. Two assertions, named, each closing a written finding. A third
arrives when a third finding needs it, and the job's README says so.

## 5. The alternative, priced rather than dismissed

**Refactor instead of seeding.** Lift `sweep_pending_deletions`'s decision core
into a pure function over the repository port — the shape `execute_deletion`
already has — and gate that on the host. It is the better fix for RFC 147
specifically: no new capability, no new job, and it holds without a runtime.

**It closes one of the two findings and not the other.** No refactor makes a
cookie's `set-cookie` header observable without a response, and the response
needs a credentialed flow. So: **do the refactor as well, under RFC 147's own
remainder**, and this RFC stands for the half that cannot be refactored away.

If the owner prefers to spend only once, the refactor is the cheaper half and
the cookie witness is the one that guards 29 rows.
