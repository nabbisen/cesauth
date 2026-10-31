# Developer Handoff — RFC 169: the book omits eleven of its own pages

**Governing RFC.** `rfcs/accepted/169-the-book-does-not-contain-eleven-of-its-own-pages.md`
**Builds on.** `7e00c7e` on `main` — tag `0.91.0`, 13/13 CI green.

**Target release.** **0.91.1 — patch.** **Trigger: none hit**, and here is the
argument rather than the default: nothing gains capability. Pages that were
always part of this book become reachable in it, two links start resolving, and
a check starts failing when that stops being true. No route, no schema, no
public type, no caller obligation, no MSRV move.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-31.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. Re-derived at `7e00c7e`, so you start from a current number

```
80  .md under docs/src, excluding SUMMARY.md
11  with no "(./<relpath>)" entry in SUMMARY.md  -> mdbook never builds them
 1  in-book page linking to one of those 11
```

The eleven:

```
deployment/email-delivery.md          expert/i18n.md
expert/acceptance-report.md           expert/contributing.md
expert/generic-error-policy.md        expert/route-contracts.md
expert/rfc-110-baseline.md            expert/adr/016-operational-baseline.md
expert/nodejs-compat-investigation.md expert/adr/017-audit-append-performance.md
                                      expert/adr/018-request-traceability.md
```

The one live consequence: **`expert/view-rendering-policy.md` links to
`./route-contracts.md` twice** — at `:6` under the words *"Enforced by"*, and
again at `:66` — and that page is not in the book, so both 404 for a reader of
the published site.

## 2. Nine go in, two are declared out

**Into `SUMMARY.md`:**

| Page | Where |
|---|---|
| `expert/route-contracts.md` | expert section — it is the table every route gate reads and the target of the dead links |
| `expert/contributing.md` | expert section — where every ruling this project makes is written down |
| `expert/i18n.md` | expert section, near the other policy pages |
| `expert/generic-error-policy.md` | expert section, likewise |
| `expert/acceptance-report.md` | expert section — it says *"for auditors and maintainers"*, which is a reader |
| `deployment/email-delivery.md` | deployment, beside the other chapters |
| `expert/adr/{016,017,018}` | **at the end of the ADR list**, which currently stops at ADR-015 |

**The ADR three are the sharpest of the eleven**: a reader of the ADR index today
concludes 015 is the latest decision on record, and three more exist.

**Declared out, with a reason each:** `expert/rfc-110-baseline.md` (an audit of
the v0.71.0 codebase, taken for RFC 110) and
`expert/nodejs-compat-investigation.md` (RFC 025 Step 2's investigation). Both
are records of a moment, not pages a reader navigates to.

**Placement is yours, not mine** — put each where it reads best in the existing
structure. If any of the nine looks to you like it belongs in the declared-out
list instead, **say so with your reasoning rather than filing it quietly**:
`acceptance-report.md` is the one I was least sure of.

## 3. Two checks, in `drift-scan.sh`

That script already walks `docs/`, so this adds no workflow and the count stays
at **14**.

1. **Coverage.** Every `docs/src/**/*.md` is reachable from `SUMMARY.md` or on a
   declared-exclusion list, each entry carrying its reason.
2. **In-book link integrity.** No page the book builds links to a `.md` the book
   does not build.

Both must:

- **report their own coverage** — scanned, in-book, declared, and
  **unreachable, which must be 0** — the shape E4 has and E6 grew in 0.91.0;
- **assert a non-zero count**, so a matcher that stops matching fails loudly
  rather than passing vacuously (RFC 125 T5);
- **fail on a stale declared entry**, naming a file that no longer exists or is
  now in `SUMMARY.md` — a stale exemption is a pre-authorised exclusion for
  whatever is written at that path next (RFC 159 §4.5, RFC 165, and E6's own
  two lists).

**You are the fourth caller of "parse a project file and check a claim about
it."** E4, E5 and E6 all live in `route-contracts-check.sh` and share its
comment-stripped `lib.rs` view. These two checks read `SUMMARY.md` and the
`docs/src` tree instead, so there is nothing to share — but if you find yourself
writing a third regex family for Markdown links, stop and say so: RFC 163's
single-extractor end state is the standing direction and this would be the
second file to want it.

## 4. The link fix needs no edit

Adding `route-contracts.md` to `SUMMARY.md` makes both
`view-rendering-policy.md` links resolve. **Do not edit that page.** If after
the `SUMMARY` change the link check still reports something, that is a finding —
report it before working around it.

## 5. Tests and gates

- No host tests implied; this is a shell gate plus `SUMMARY.md` entries.
- **Negative-test both checks**, the methodology you have used three times now:
  remove a `SUMMARY.md` entry → coverage check **exit 1** naming the page; point
  an in-book page at a declared-out file → link check **exit 1** naming the
  link; add a declared entry matching nothing → **exit 1** naming it stale.
  Restore from pre-edit copies and byte-diff.
- `mdbook build docs` must stay clean **and build nine more pages** — state the
  HTML count before and after; it was **72** at `7e00c7e`.
- Full gate set. **Baselines at `7e00c7e` (tag `0.91.0`)**: host tests
  **1,653 / 0 / 12 lines**, `migration_chain` **35**, 194 routes documented,
  **E4 `218 = 194 + 24 + 0`**, **E5 `16 = 16 + 0 + 0`**, **E6 `94 = 76 claims +
  18 declared + 0 unclassified`**, Playwright **20**, manifest **13 + 1 = 14**,
  bundle **896,172 B gzip** (`885,473` wasm + `10,699` shim) under gzip 1.15. No
  Rust should change, so every one of those should match exactly — **if the
  bundle moves, something unintended happened and I want to hear about it
  before the cut.**

## 6. What to report

- The coverage line in full, with 0 unreachable.
- The HTML page count before and after.
- Any of the nine you think belongs in the declared-out list, with reasoning.
- Whether the two `view-rendering-policy.md` links resolve after the `SUMMARY`
  change alone.
- Anything else the link check caught on its first run. **That is the question
  this gate exists to answer**, and a first run that finds nothing beyond the
  known one is itself worth stating plainly.

## 7. Stop conditions

- `mdbook` rejects one of the nine for a reason you did not expect (a missing
  anchor target, a nested-list `SUMMARY` constraint) — report the page and the
  message;
- the link check finds in-book links broken for a reason unrelated to the eleven;
- either check needs a third Markdown-link regex family (§3).
