# Developer Handoff — RFC 164 + RFC 168 + RFC 165 §3: three unenforced records, one cycle

**Governing RFCs.**
`rfcs/accepted/164-the-link-sweep-rfc-000-mandates-is-unenforced.md`,
`rfcs/accepted/168-the-release-record-does-not-reconcile.md`,
`rfcs/accepted/165-the-gates-exemption-lists-are-unvalidated.md` §3.
**Builds on.** `cc5329b` on `main` — tag `0.91.1`, 13/13 CI green.

**Target release.** **0.91.2 — patch.** **Trigger: none hit**, argued rather
than defaulted: every deliverable is a check, a link target, or an exemption
list. No route, no migration, no public type, no `rust-version` change, no
caller obligation. Nothing an operator or integrator could read about and
conclude they must act.

**Why these three together.** They are the same shape — *a rule this project
wrote down and never gated* — and they live in the same two scripts.
RFC 169 has just extended `drift-scan.sh` with two census-style checks, so the
pattern, the output convention and the stale-entry rule are all already there
to copy. Three checks in one cycle, **no new workflow**.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-01.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. RFC 164 — the link sweep, measured at `cc5329b`

```
181  relative .md links across rfcs/**/*.md
 20  broken
```

RFC 164 found 25 and repaired 11 in the commit that proposed it, leaving 14.
**There are 20 now, so six have rotted in since 2026-10-30** — during the very
releases in which I was running the sweep by hand at every RFC move. That is
the argument for the gate, and it is better than the one in the RFC.

**Fourteen are the example links in the two files that define the rule** —
`rfcs/done/000-rfc-lifecycle-policy.md` (7) and
`rfcs/archive/019-rfc-lifecycle-policy.md` (7). These are illustrations like
`../done/010-revoke-tokens.md`, wrapped in live link syntax, inside prose explaining how to write
a cross-reference. **RFC 164 §4 recommends de-linking them rather than
exempting the two files, and that recommendation stands**: an exemption on a
whole file would also excuse a real broken link that appears in it later. Turn
them into inline code (`` `../done/010-revoke-tokens.md` ``) or prose, keeping
the explanation intact.

**Six are real rot, and here is each with its fix** — I located them so the
cycle starts from the work rather than from a hunt:

| Where | Broken target | The fix |
|---|---|---|
| `done/028-…:143,144,145` | `.../CHANGELOG-0.1-to-0.30.md#010` and two siblings — a literal `...` ellipsis **inside** markdown link syntax | **Line 142 of the same table has the correct form**, `../../docs/changelog-archive/CHANGELOG-0.1-to-0.30.md`. Use it for all four rows |
| `done/028-…:176` | `rfcs/done/020-migration-chain-hygiene.md` — repo-root-relative, so it resolves to `rfcs/done/rfcs/done/…` | `./020-migration-chain-hygiene.md`. **This is RFC 028's own defect class** — root-relative links in content that lives in a subdirectory — in RFC 028's own file |
| `done/011-…:263` | `012-sessions.md` — bare filename, resolves inside `rfcs/done/` where no such file exists | The real target is `docs/src/expert/adr/012-sessions.md`, which **line 78 of that same file already writes correctly** |
| `accepted/161-…:26` | `./167-nothing-takes-a-new-operator-to-production.md` | `../done/167-…`. RFC 167 moved to `done/` in 0.89.5's cut |

**That last one is mine, and it exposes a blind spot in how I sweep.** When an
RFC moves I `grep` for the old full path — `accepted/167-<slug>` — and rewrite
every hit. **A sibling file linking with `./<slug>` does not contain that
string**, so the sweep cannot see it. Four of my own moves have run that way.
It is the precise reason "the architect ran a sweep" is not a substitute for a
check, and worth a sentence in the RFC when you close it.

**The check itself**: every relative `.md` link in `rfcs/**/*.md` resolves to a
file that exists. Report the population (links scanned, broken), **assert a
non-zero scan count**, and count only what you validate — RFC 169's link check
has the shape, including the skip classes for `http`/absolute targets. There is
no declared-out list here unless you find a case that needs one; if you do, it
carries the stale-entry rule like every other list in these two scripts.

## 2. RFC 168 — three checks, and the exemption list is **ten**, not six

The three checks are specified in RFC 168 §3 and I am not restating them; build
them as written. Two things that section does not have right:

**The historical-mismatch exemption is ten entries, in two directions.**
Computed at `cc5329b` over 140 tags and 138 CHANGELOG entries (root plus all
seven archive files, `^## \[X.Y.Z\]`):

- **tagged, never documented (6)**: `0.1.0`, `0.2.0`, `0.3.1`, `0.4.0`,
  `0.50.2`, `0.79.6`
- **documented, never tagged (4)**: `0.50.3`, `0.64.0`, `0.78.13`, `0.79.7`

RFC 168 says *"the six historical mismatches"*; `contributing.md` §Every
release must satisfy names **five** (`0.79.6` plus the four). **Both are
wrong**, and the five earliest tags were missing from both counts. I verified
these are genuinely absent rather than differently formatted: the archives use
`## [X.Y.Z] - date` throughout, and none of the five appears in any file.

**Fix both documents as part of this cycle** — the RFC's own figure and
`contributing.md`'s list — and build the exemption from the computed ten.
**`docs/changelog-archive/CHANGELOG-0.1-to-0.30.md` has a `## Versioning
history note` section**; read it before writing the reasons, because it may
already explain the five earliest, and a reason copied from the record beats
one invented at the gate.

**On the manifest.** RFC 168 §3 says *"the manifest stays at 13"*, written when
13 was quoted as the workflow count. Today it is **13 `release` entries + 1
`not_on_release_path` = 14 workflow files**, and the manifest gate asserts the
whole set. You are adding no workflow, so nothing moves — but say the figure in
your report so a reader does not have to reconcile two numbers.

**§3's third requirement is the one to get right**: both checks print their
population, *comparisons performed* included. The RFC says why in its own
words — the audit behind it reported "zero violations" having compared nothing,
because its loop never advanced `prev`. That audit was mine.

## 3. RFC 165 §3 — four lists, two worked examples in the same file

`scripts/route-contracts-check.sh` carries four exemption lists with **no
staleness check**, verified at `cc5329b` (zero mentions of "stale" beside any of
the four):

- `E3_EXEMPT` (2 entries: `GET /`, `GET /login`)
- `GATE_42_EXEMPT` (1: `GET /admin/console/clients`)
- `NONCE_EXEMPT` (empty by design)
- `E4_EXEMPT` (empty by design)

**An empty list is the cheapest case, not a skippable one**: a staleness check
over an empty list costs nothing and is what keeps it empty honestly.

`NAMED_NON_HANDLERS` and `E6_BEARER_LEGACY_EXEMPT` in that same file, and
`DOCS_DECLARED_OUT` in `drift-scan.sh`, are **three worked examples of exactly
this pattern**. Copy the closest one rather than inventing a fourth idiom.

**§4 is not in scope.** The 22-entry reduction is release-unassigned by design
and its decision is made at its own dispatch. Do not start it; if §3's work
makes a §4 argument obvious, write it in the report.

## 4. Tests

- **Negative-test every check you add.** The methodology is established in this
  project four cycles running: break it, confirm **exit non-zero** naming the
  exact item, restore from a pre-edit copy, byte-diff, re-run clean. For these
  three that means: a broken `rfcs/` link; a tag with no entry and an entry with
  no tag (simulate rather than tag anything — **do not create tags**); a patch
  that adds a route, a migration, and an MSRV change, each separately; a stale
  entry in each of the four lists plus the new mismatch exemption.
- **The level backstop needs care in its own test**: it compares against the
  previous tag, so a test that fakes a route addition must be clear about which
  two commits it is comparing.
- No host tests implied — these are shell gates and Markdown fixes.
- Full gate set. **Baselines at `cc5329b` (tag `0.91.1`)**: host tests
  **1,653 / 0 / 12 lines**, `migration_chain` **35**, 194 routes documented,
  **E4 `218 = 194 + 24 + 0`**, **E5 `16 = 16 + 0 + 0`**, **E6 `94 = 76 claims +
  18 declared + 0 unclassified`**, docs coverage **`80 = 78 + 2 + 0`**, docs
  links **`189 seen = 177 checked + 6 absolute + 6 outside + 0 unresolvable;
  0 broken`**, Playwright **20**, manifest **14**, bundle **896,325 B gzip**
  (`885,626` wasm + `10,699` shim) under gzip 1.15. **No Rust should change**, so
  the bundle and the test count must match exactly — if either moves, stop and
  say so.

## 5. What to report

- The `rfcs/` link check's population line, and **0 broken** after the six fixes
  and the fourteen de-linkings — or which of the twenty you concluded was
  something other than what I called it.
- The three release-record checks' population lines, *comparisons performed*
  included.
- What the archive's `## Versioning history note` says about the five earliest
  tags, and what you wrote as their exemption reason.
- The four exemption lists' staleness checks, and whether any of the three live
  entries turned out to be stale already. **That is the question RFC 165 exists
  to answer** and nobody has asked it of these four.
- Anything these checks catch on their first run beyond what is named here.
  RFC 169's equivalent found one, and it was not in its handoff.

## 6. Stop conditions

- the `rfcs/` link check finds broken links beyond the twenty, in a shape I have
  not described — report before fixing;
- the level backstop cannot be expressed without parsing something fragile
  (commit messages, say) — describe what it would need and stop;
- RFC 168's reconciliation needs to read `git tag` in CI in a way the other
  gates do not — say so; a check that works only locally is worth less than one
  that fails in CI, and I would rather know than have it quietly skipped;
- any of the three turns out to want a fourth parsing idiom over `rfcs/` or
  `lib.rs` (§3).
