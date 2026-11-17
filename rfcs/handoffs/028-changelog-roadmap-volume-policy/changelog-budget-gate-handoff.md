# Developer Handoff — RFC 028, the CHANGELOG budget, actually enforced

**Target**: `0.107.0`, slice B of two · **Level**: minor (shipped with slice A)
**RFC**: `rfcs/done/028-changelog-roadmap-volume-policy.md` — §Step 5, §Step 6, §Outstanding
**Tool**: `scripts/changelog-archive-split.sh` (120 lines, never run on a real split)
**Convention**: `docs/changelog-archive/README.md`, whose two dated notes define the shape
**Baseline**: `996cd22` / tag `0.106.0`

---

## 1. Purpose

Root `CHANGELOG.md` is **99,916 B** against RFC 028's **~80 KB** budget —
a quarter over, and over for the first time since the 0.95.0 split. The
split tool has three recorded defects and has **never been run on a real
split** (both previous splits were done by hand). The gate RFC 028 §Step 6
specifies in full, as runnable bash, does not exist.

This slice does the three together, which is what RFC 028 §Outstanding
asked for — *"the fix belongs with the budget check RFC 028 §Step 5
specified and nobody built — one cycle, not two"*.

## 2. Why this matters

The budget is the half of RFC 028's rule that was **not** derived from
anything else. Its *"most recent ~5 minor versions"* figure was derived
**from** the budget — RFC 028 Requirement 1 says so in its own
parenthesis, *"small enough to keep the file under ~80 KB"* — and the
2026-11-07 note already ruled that the five is a stale estimate, not a
rule, because releases per minor went 1.0–1.17 (v0.31–v0.49) → 2.90
(v0.70–v0.79) → 4.00 (v0.89–v0.92) while mean bytes per entry **fell**.
So: gate the bytes, delete the five.

The 0.106.0 cut corrected the root file's own masthead, which had claimed
*"45 KB of the ~80 KB budget"* while the file was ~100 KB. **That
paragraph is now the thing most likely to go stale again** — it states a
size, and this slice changes the size. See T4.

## 3. Resolved decisions — do not re-open

- **D1. Split point: archive `v0.93.0` through `v0.101.0`.** Nine minors,
  **59,265 B** of entries, into
  `docs/changelog-archive/CHANGELOG-0.93-to-0.101.md`. Root lands at
  **≈ 39.4 KB** — 49% of budget, **≈ 42 KB of headroom** — which is the
  *"split to a floor rather than to just under the ceiling"* the README's
  own 0.93.0 and 0.95.0 notes established. It leaves `0.102`–`0.106`, the
  most recent **five** minors: the coincidence is worth one sentence in
  the README note, because it is exactly what Requirement 1's derived
  figure meant when the derivation was fresh — and it is still not a rule.
- **D2. The gate covers root `CHANGELOG.md` only. `ROADMAP.md` gets no
  gate in this slice**, and that is a decision rather than an omission.
  `ROADMAP.md` is **414,711 B** against its own ~40 KB budget — **10.1×
  over**, measured at `996cd22`, up from the 134 KB RFC 028's note
  recorded. Its remedy is condensation to *summary + link* per row, which
  RFC 028 calls *"judgement rather than a shell loop"*. A gate whose only
  remedy is an unscoped judgement job would be red the day it lands, and
  a permanently red gate is worth less than an honest row. **Record the
  number; scope the cut separately.**
- **D3. Fix the tool, then use it.** Both previous splits were hand-done,
  which is why its defects survived two opportunities. This split runs the
  tool.
- **D4. Byte reconciliation is required, in the README note, in the
  established shape**: bytes out of the root, bytes into the archive, and
  the difference **explained** (the previous two were 5 B and 22 B, both
  the `---` separator the archive header replaces). An unexplained
  difference is a defect, not a rounding detail.
- **D5. No entry text changes.** The moved entries must diff
  byte-identical against their source, exactly as the 0.95.0 note claims
  for its own move. Editing history while moving it is prohibited.

## 4. Facts already measured — do not re-derive

**Entry sizes in root `CHANGELOG.md` at `996cd22`** (preamble 3,889 B;
entries 94,739 B; file 99,916 B):

| minor | bytes | | minor | bytes |
|---|---|---|---|---|
| 0.106 | 10,821 | | 0.99 | 5,974 |
| 0.105 | 6,544 | | 0.98 | 5,053 |
| 0.104 | 5,840 | | 0.97 | 5,799 |
| 0.103 | 7,501 | | 0.96 | 4,772 |
| 0.102 | 4,768 | | 0.95 | 7,010 |
| 0.101 | 7,060 | | 0.94 | 7,462 |
| 0.100 | 4,149 | | 0.93 | 11,986 |

Archiving through 0.101 moves **59,265 B** and leaves **≈ 39,363 B** plus
whatever T4's rewrite costs.

**The tool's three defects, each located:**

1. **The README-index `sed` is invalid, and its failure is swallowed.**
   Line 118 uses `s|…|…|` while the replacement text itself contains `|`
   characters (it builds a Markdown table row), so `sed` fails — and the
   line ends `2>/dev/null || true`, so the script reports success with the
   index un-updated. Both previous splits updated the index by hand, so
   this has never surfaced in a committed file.
2. **A duplicate `## Older releases` block.** The root file's preamble
   already contains one (it is above the first `## [` heading, so the
   script's own `FIRST_SECTION` boundary preserves it), and lines 98–101
   unconditionally `echo` another. RFC 028 §Outstanding predicts *"a fifth
   duplicate"*.
3. **Root-relative links break two levels down.** A moved entry's
   `](docs/…)` or `](rfcs/…)` link resolves relative to its file, and the
   archive sits at `docs/changelog-archive/`. **This range has zero
   instances** — the entries 0.93–0.101 contain exactly **one** link and
   it is `https://github.com/verus-lang/verus`. Fix the defect anyway, and
   say in the report that the instance count was zero, so the fix is not
   mistaken for a tested one.

**Other facts:**

- `drift-scan.sh`'s release reconciliation **already reads the archive**:
  `CHANGELOG_FILES` is the root file plus every `docs/changelog-archive/*.md`
  (line ~760). Moving entries keeps it green; its line should still read
  *"162 tag(s) against 161 entr(y|ies)"* afterwards, give or take this
  cut's own release.
- The tool's size guard uses `BUDGET_KB=80` with `wc -c / 1024`, i.e.
  **KiB**. The gate must use the same definition — `80 * 1024`, not
  80,000 — or the tool and the gate will disagree by 1,920 B.
- The archive README's existing notes (0.93.0 and 0.95.0 cuts) are the
  template for T3's note, including the sentence recording that *the
  script was not run*. That sentence changes this time.

## 5. Report-and-stop gates

**None.** This slice has no copy decisions and no population to rule on;
D1 fixes the split point and §4 fixes the numbers. If the tool's output
disagrees with D1's predicted sizes by more than the `---`-separator
difference D4 allows, **stop and report before committing** rather than
adjusting the prediction.

## 6. Change scope

| file | change |
|---|---|
| `scripts/changelog-archive-split.sh` | T1 — the three defects |
| `docs/changelog-archive/CHANGELOG-0.93-to-0.101.md` | T2 — new, from the tool |
| `CHANGELOG.md` | T2 — trimmed; T4 — the masthead |
| `docs/changelog-archive/README.md` | T3 — index row + dated note |
| `scripts/drift-scan.sh` | T5 — the byte gate |
| `rfcs/done/028-changelog-roadmap-volume-policy.md` | T6 — the record |
| `ROADMAP.md` | T6 — the row for its own 414,711 B |

## 7. Explicit non-change scope

- **No `ROADMAP.md` condensation, no ROADMAP gate** (D2). One row stating
  its size, nothing more.
- **No archive restructuring.** Existing archive files are immutable by
  convention; do not re-split or rename them.
- **No entry edits** (D5), including typo fixes you notice while moving.
- **No code, no crate, no version bump.** The release commit is the
  architect's.
- **No change to `rfcs/done/028`'s Requirement 1 text itself** beyond
  deleting the stale derived figure — the RFC's history stays readable,
  so the deletion is recorded as an amendment, not a silent rewrite.

## 8. Task detail worth stating explicitly

- **T1's defect 1**: change the `sed` delimiter (or build the row with
  `awk`/a heredoc), **and delete the `2>/dev/null || true`**. A silent
  failure is the actual defect; an invalid expression is just its cause.
  The script must exit non-zero if the index cannot be updated.
- **T1's defect 2**: the script must detect an existing
  `## Older releases` block in the preamble and **update it** rather than
  prepend a second. The text also carries a version — *"Entries for
  vX.Y.x and earlier"* — which has to move with the split point.
- **T1's defect 3**: rewrite root-relative Markdown links in the moved
  block to `../../`-prefixed form, and leave `http(s)://`, anchor-only and
  already-relative links alone. State the count rewritten (expected: 0).
- **T2 runs the fixed tool**: `scripts/changelog-archive-split.sh 0.101.0`.
  Capture its stdout in the evidence log — its *"Root CHANGELOG.md
  trimmed: X KB → Y KB"* line is part of the reconciliation.
- **T3's note** follows the README's own two precedents: date, cut,
  entries moved, root before → after, byte reconciliation with the
  difference explained, headroom before → after, and — new this time —
  that **the script was run**, with its three defects fixed in the same
  commit.
- **T4 is the trap.** `CHANGELOG.md`'s masthead currently says the file is
  *"~100 KB … over RFC 028's ~80 KB budget by a quarter"* and that *"the
  next split is a cut of its own"*. After T2 both sentences are false.
  Rewrite that paragraph to state: the new size, the split that produced
  it, the headroom, and that the budget is **now gated** (naming the
  drift-scan section). Keep the 2026-11-07 correction note below it
  untouched — it is history.
- **T5's gate**, in `scripts/drift-scan.sh`, in the shape the negotiation
  gate established — one `ℹ️` line always, failure with a remedy:

  ```
  ℹ️   changelog budget: CHANGELOG.md is N bytes of 81920 (M% of budget, K bytes headroom)
  ```

  Fail when `N > 81920`, naming `scripts/changelog-archive-split.sh` as
  the remedy and the archive README as where the note goes. **Do not gate
  ROADMAP.md** (D2) — but *do* print its size on its own `ℹ️` line, with
  the ~40 KB budget and the overage factor, so the number is in every run
  rather than in one row nobody re-reads.
- **T6's record** has three parts: (a) delete Requirement 1's *"~5 minor
  versions"* derived figure, with an amendment line saying when and why
  (the 2026-11-07 note already argued it; this is the deletion that note
  called for); (b) §Outstanding's three bullets — the tool's defects are
  fixed, the §Step 6 gate exists, and the ROADMAP half is **not** done and
  is now 414,711 B rather than 134 KB; (c) a ROADMAP row for the ROADMAP
  half, carrying that number and the dated measurement.

## 9. Assert machine-checkable things mechanically

```bash
# the moved entries are byte-identical to their source (D5)
git show 996cd22:CHANGELOG.md | sed -n "/^## \[0.101.0\]/,\$p" > /tmp/before.txt
sed -n "/^## \[0.101.0\]/,\$p" docs/changelog-archive/CHANGELOG-0.93-to-0.101.md > /tmp/after.txt
diff /tmp/before.txt /tmp/after.txt && echo "byte-identical"

# reconciliation: bytes out of the root == bytes into the archive, ± the header
# exactly one '## Older releases' in the root (defect 2)
grep -c '^## Older releases' CHANGELOG.md          # want 1

# no entry lost or duplicated across the two files
grep -hoE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' CHANGELOG.md docs/changelog-archive/*.md \
  | sort | uniq -d                                  # want empty

# the index row exists and resolves
grep -n 'CHANGELOG-0.93-to-0.101.md' docs/changelog-archive/README.md
test -f docs/changelog-archive/CHANGELOG-0.93-to-0.101.md
```

## 10. Required tests and evidence

No new Rust tests — this slice touches no code. The gate set still runs,
quoted literally:

```bash
cargo test -p cesauth-core \
           -p cesauth-adapter-test \
           -p cesauth-frontend \
           -p cesauth-backend \
           -p cesauth-adapter-cloudflare \
           --features cesauth-frontend/csr > 028-evidence/host-tests.log 2>&1

cargo test -p cesauth-migrate-test --test migration_chain > 028-evidence/migrate.log 2>&1
bash scripts/route-contracts-check.sh > 028-evidence/route-contracts.log 2>&1
bash scripts/drift-scan.sh > 028-evidence/drift-scan.log 2>&1
```

Expected: host **1,732 / 0 / 4 across 12 lines** unchanged (slice A may
raise the first number; say which slice you measured on), migrate **39**,
**197 routes**, `drift-scan` clean **including the release
reconciliation line still reading the same tag/entry counts** — that line
is the one this slice could break, so quote it before and after.

**Evidence the slice is actually done**, in `028-evidence/`:

- the tool's own stdout (`split.log`),
- the byte reconciliation from §9, with the difference explained,
- `drift-scan`'s new changelog-budget line,
- **both failure directions of T5's gate demonstrated**: pad a scratch
  copy past 81,920 B and show the failure message naming the remedy, then
  show the real file passing. The negotiation gate set this bar last cut.

## 11. What must NOT be claimed

- **Not that RFC 028 is now enforced.** Half of it is: the CHANGELOG
  budget. The ROADMAP budget is unenforced **by decision** (D2), and the
  report must say so in those words rather than leaving it implied.
- **Not that the tool is now correct.** Three recorded defects are fixed
  and the tool ran once, successfully, on one split whose link-rewrite
  path had **zero** instances to exercise. That is what it is.
- **Not that the root file will stay under budget.** At this cut's entry
  sizes (mean ≈ 6.8 KB over the last five minors, and `0.106.0` alone was
  10.8 KB) the 42 KB of headroom is roughly six releases. Say the number
  rather than implying the problem is solved.

## 12. Prohibited shortcuts

- Do not hand-move the entries. The tool runs (D3); that is half the
  point of the slice.
- Do not silence the gate on `ROADMAP.md` by raising its budget to fit —
  it gets no gate at all this slice, and inventing a 420 KB "budget"
  would be the opposite of recording the overage.
- Do not delete or reword the archive README's historical notes.
- Do not run `cargo test --workspace --all-features`
  (`contributing.md:495-504`).
- Do not touch slice A's files.

## 13. Acceptance criteria

1. `CHANGELOG-0.93-to-0.101.md` exists, holds nine minors' entries
   byte-identical to their source, and is linked from the archive README's
   index table.
2. Root `CHANGELOG.md` ≈ 39 KB, exactly one `## Older releases` block,
   masthead rewritten (T4), no duplicate or missing `## [X.Y.Z]` heading
   across root + archive.
3. The split tool's three defects fixed, the `|| true` gone, and the tool
   exits non-zero when the index cannot be updated.
4. `drift-scan` carries the changelog-budget gate — green, both
   directions demonstrated — plus the ROADMAP size line, and its release
   reconciliation line is unchanged.
5. RFC 028's Requirement 1 figure deleted with an amendment line; its
   §Outstanding updated; a ROADMAP row carries `ROADMAP.md`'s own
   414,711 B.
6. Gate set green, figures as in §10.

## 14. Known risks

- **The reconciliation is where a silent loss would show up.** A dropped
  entry or a swallowed heading is invisible in a diff this size; §9's
  `uniq -d` and the byte arithmetic are the detection, so run them before
  committing, not after.
- **T4's paragraph is self-referential** and will be wrong the moment the
  split lands. It is the second time in two cuts that a sentence about
  this file's size went stale; write the new one so it states a measured
  size and the gate that keeps it true.
- **The tool is `set -euo pipefail` with an existing-file guard**, so a
  second run is safe — but a *partial* first run is not necessarily. Work
  on a clean tree so `git checkout` is a complete undo.

## 15. Review request

Write `.git-exclude/review-request/028-changelog-budget-report.md`, with
evidence under `028-evidence/`. Report the entry-point path only.
