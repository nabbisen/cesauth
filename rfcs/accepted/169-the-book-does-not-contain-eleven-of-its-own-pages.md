# RFC 169 — The book does not contain eleven of its own pages, and one in-book link already 404s

**Status.** **Accepted** 2026-10-31 by the owner (*"RFC 169 is accepted."*).
Proposed the same day by the architect, while reviewing v0.89.5.
**Scheduled 0.91.x — patch**, after RFC 152 half C and ahead of RFC 164, with
which it shares `drift-scan.sh`. **Not dispatched**: 0.91.0's cut is pending, and
its code must not land on `main` before that tag can be cut honestly.
**Tier.** **P2.** Nothing is broken and nothing is exposed. Current, maintained
documentation is unreachable from the published book, and one page that *is*
published links twice to one of the missing ones.
**Size.** **Small.** A `SUMMARY.md` edit, a declared-exclusion list, and a
check in `scripts/drift-scan.sh` — the same inputs that script already walks.
**Touches.** `docs/src/SUMMARY.md`, `scripts/drift-scan.sh`,
`docs/src/expert/view-rendering-policy.md` (nothing else, if the fix is the
`SUMMARY` entries).
**Depends on.** Nothing.
**Found by.** The architect, 2026-10-31, checking an unrelated anchor in
`README.md` and noticing that the page it pointed at had no built HTML.

**On 1.0:** not declared, not scoped, not dated. Nothing here is a 1.0
requirement.

---

## 1. Summary

`mdbook` builds exactly the pages `SUMMARY.md` lists. **Eleven of the eighty
`.md` files under `docs/src` are not listed**, so the published book does not
contain them, and `mdbook build` is **clean** about it — there is no warning,
no gate, and nothing that fails.

```
$ find docs/src -name '*.md' ! -name 'SUMMARY.md' | wc -l
80
$ # an orphan is one with no "(./<relpath>)" entry in SUMMARY.md
11
$ find docs/book -name '*.html' | grep -v print.html | wc -l
72
```

**One of them is already a dead link in the published book.**
`expert/view-rendering-policy.md` links to `./route-contracts.md` **twice** —
at `:6`, under the words *"Enforced by"*, and again at `:66` — and that page is
not in the book. A reader following the enforcing-document link from the policy
that names it gets a 404. A scripted check over every in-book `.md` link found
exactly this one target, so the blast radius today is one page, two links.

## 2. What is missing, and it is not marginal

| Page | Why it matters |
|---|---|
| `expert/route-contracts.md` | the route contract table every gate in `route-contracts-check.sh` reads; the target of the dead link above |
| `expert/contributing.md` | where every ruling this project makes is written down — the test command, the release procedure, the level rubric |
| `deployment/email-delivery.md` | a deployment chapter; `README.md` names Magic Link mail as a step a first deploy may need |
| `expert/i18n.md` | live operator-side digest of the string and timestamp contracts |
| `expert/generic-error-policy.md` | the authentication error-message policy — what may and may not be leaked on a failure |
| `expert/acceptance-report.md` | acceptance-criteria trace, written *"for auditors and maintainers"* |
| `expert/adr/016-operational-baseline.md` | |
| `expert/adr/017-audit-append-performance.md` | |
| `expert/adr/018-request-traceability.md` | **the three most recent ADRs.** The book's ADR chapter ends at ADR-015, so a reader of the index concludes 015 is the latest decision on record |

Two are genuinely point-in-time and should stay out:
`expert/rfc-110-baseline.md` (an audit of the v0.71.0 codebase, taken for
RFC 110) and `expert/nodejs-compat-investigation.md` (RFC 025 Step 2's
investigation). Both are records of a moment, not pages a reader navigates to.

## 3. Why this is the project's recurring shape, again

This is the **ninth** instance of *a documented thing with no gate* —
RFC 028, 151, 163, 164, 165, 166, 168, the registered-route-with-no-caller
category from RFC 152 half B, and now this. It is the first where the gap makes
**correct, current** documentation invisible rather than merely unenforced: no
page here is wrong, out of date or unmaintained. They are simply not in the
book, and nothing says so.

It is also the mirror image of RFC 164. That RFC gates links **between RFCs**,
where a stale path is a wrong status claim. This gates links **into the book**,
where a missing entry is a page that does not exist for any reader. Same
mechanism, same script, opposite direction.

## 4. Direction

1. **Add the nine to `SUMMARY.md`** — `route-contracts.md` and `contributing.md`
   under the expert section, `email-delivery.md` under deployment beside the
   other chapters, the three ADRs at the end of the ADR list, and `i18n.md`,
   `generic-error-policy.md` and `acceptance-report.md` under expert.
2. **Declare the two exclusions** in a list the check reads, each with a
   reason, in the shape `NAMED_NON_HANDLERS` already uses in
   `route-contracts-check.sh` — **including its stale-entry rule**: an entry
   naming a file that no longer exists is a hard failure, because a stale
   exemption is a pre-authorised exclusion for whatever is written at that path
   next (RFC 159 §4.5, RFC 165).
3. **Two checks in `scripts/drift-scan.sh`**, which already walks `docs/`:
   - every `docs/src/**/*.md` is either reachable from `SUMMARY.md` or on the
     declared-exclusion list;
   - no in-book page links to a `.md` the book does not build.
   Both must **report their own coverage and assert a non-zero count**, so a
   matcher that stops matching fails loudly rather than passing vacuously
   (RFC 125 T5 — and the architect's own vacuous audit of 2026-10-30 is the
   cautionary instance).
4. **Fix the two links** in `view-rendering-policy.md` by the act of adding
   `route-contracts.md` to the book; no edit to that page is needed.

The workflow count stays at **14**: the checks go inside `drift-scan.sh`, which
already has a workflow, exactly as RFC 164 plans to do.

## 5. Level and schedule

**Patch.** Nothing gains capability; a document that claimed to be part of the
book becomes part of it, and two links start resolving. No route, no schema, no
public type, no caller obligation.

**Recommended immediately after RFC 152 half C**, and ahead of RFC 164: half C
is a security-adjacent correctness item and outranks it, but this is cheaper
than 164 and shares its script, so doing it first means 164 lands against a
`drift-scan.sh` that already has the shape. The ordering is the architect's to
set; the acceptance is the owner's.

## 6. What this does not claim

- **Not** that any of the eleven pages is wrong or stale — the finding is that
  they are unreachable, which is a different defect and the reason this is P2
  rather than P1.
- **Not** that eleven links are broken. One page links to one missing page,
  twice. The rest are unreachable rather than mis-linked.
- **Not** that `mdbook` has a bug. `create-missing = false` (RFC 138) makes it
  fail on a `SUMMARY` entry with no file; there is no symmetric option for a
  file with no entry, which is why this needs a check of our own.
