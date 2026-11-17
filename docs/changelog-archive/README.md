# cesauth — Changelog & ROADMAP Archive

This directory holds historical CHANGELOG entries and ROADMAP shipped-table
rows that have been moved out of the root files to keep them under the size
budget (~80 KB for CHANGELOG.md, ~40 KB for ROADMAP.md).

## CHANGELOG archive

| File | Versions |
|---|---|
| [`CHANGELOG-0.1-to-0.30.md`](CHANGELOG-0.1-to-0.30.md) | v0.1.0 – v0.30.0 |
| [`CHANGELOG-0.31-to-0.40.md`](CHANGELOG-0.31-to-0.40.md) | v0.31.0 – v0.40.0 |
| [`CHANGELOG-0.41-to-0.49.md`](CHANGELOG-0.41-to-0.49.md) | v0.41.0 – v0.49.0 |
| [`CHANGELOG-0.50-to-0.59.md`](CHANGELOG-0.50-to-0.59.md) | v0.50.0 – v0.59.0 |
| [`CHANGELOG-0.60-to-0.69.md`](CHANGELOG-0.60-to-0.69.md) | v0.60.0 – v0.69.0 |
| [`CHANGELOG-0.70-to-0.79.md`](CHANGELOG-0.70-to-0.79.md) | v0.70.0 – v0.79.7 |
| [`CHANGELOG-0.80-to-0.84.md`](CHANGELOG-0.80-to-0.84.md) | v0.80.0 – v0.84.3 |
| [`CHANGELOG-0.85-to-0.87.md`](CHANGELOG-0.85-to-0.87.md) | v0.85.0 – v0.87.1 |
| [`CHANGELOG-0.88-to-0.88.md`](CHANGELOG-0.88-to-0.88.md) | v0.88.0 – v0.88.1 |
| [`CHANGELOG-0.89-to-0.89.md`](CHANGELOG-0.89-to-0.89.md) | v0.89.0 – v0.89.5 |
| [`CHANGELOG-0.90-to-0.91.md`](CHANGELOG-0.90-to-0.91.md) | v0.90.0 – v0.91.2 |
| [`CHANGELOG-0.92-to-0.92.md`](CHANGELOG-0.92-to-0.92.md) | v0.92.0 – v0.92.7 |
| [`CHANGELOG-0.93-to-0.101.md`](CHANGELOG-0.93-to-0.101.md) | v0.93 – v0.101 |

Current releases (**v0.102.0 and newer**) are in the root
[`CHANGELOG.md`](../../CHANGELOG.md).

> **2026-11-17, the 0.107.0 cut (RFC 028 slice B)**: 0.93–0.101 archived
> (nine entries), root 99,916 → **40,081 B**. Reconciled: the moved range
> diffs byte-identical against commit `b03fc9e`'s `CHANGELOG.md`
> (`git diff` against the extracted range, empty); the kept entries
> (0.102–0.106, including the now-last one's own trailing `---`
> separator, which every entry in this file carries and which this split
> correctly leaves alone) are **byte-for-byte unchanged**, 36,144 B before
> and after; the only change inside the root is its own preamble sentence
> growing by **1 B** (`v0.92.x` → `v0.101.x`, one extra digit). So
> 99,916 − 40,081 = **59,835 B** removed from root — exactly the 59,836 B
> that moved out, minus the 1 B the preamble sentence grew by. The
> archive file totals **60,007 B**: the 59,836 B of
> moved entries plus **171 B** of this file's own new header/intro text —
> no `---`-separator discrepancy this time, because none was dropped.
> Headroom: `81,920 − 40,081` = **41,839 B**, **51%** of the 81,920 B
> budget, leaving the most recent **five** minors (0.102–0.106) in the
> root — the same number Requirement 1's now-deleted derivation named,
> not because the rule still holds but because that is where this cut's
> own floor landed.
>
> **Run by the tool this time, not by hand** — `changelog-archive-split.sh`'s
> three recorded defects (the README index `sed` silently failing, the
> duplicated "## Older releases" block, root-relative links breaking two
> levels down) are fixed in the same commit, and a fourth was found running
> it on a real split for the first time: the "Current releases (**vX.Y.Z
> and newer**)" sentence just above was never updated by the original
> script either — every previous cut fixed it by hand along with the other
> three and it never got folded back into the tool. All four are fixed now.
> The link-rewrite path had **zero** instances to exercise in this range
> (confirmed: the moved entries carry exactly one Markdown link, and it is
> `https://github.com/verus-lang/verus`, already absolute) — recorded as
> such rather than claimed as tested.
>
> **The predicted moved-bytes figure (59,265 B, from the handoff's own
> per-minor table) was 571 B low against the measured 59,836 B.** Not
> investigated further — the diff-confirmed byte-identical check above is
> the correctness proof this note relies on, not agreement with a
> pre-measurement taken before the four commits between this cut's actual
> baseline (`b03fc9e`) and the handoff's stated one (`996cd22`, the
> `0.106.0` tag itself).
>
> **2026-11-10, the 0.95.0 cut**: 0.92 archived (eight entries), root
> 74,482 → **30,034 B**. Reconciled: 44,448 B out, 44,443 B in, the 5-byte
> difference being the `---` separator this file replaces with its own header;
> the moved entries diff byte-identical against tag `0.94.0`. Headroom went from
> 7,438 B — one entry from breaching — to 51,886 B. Done by hand again; the
> script was not run, so its two known defects still stand.
>
> **2026-11-08, the 0.93.0 cut**: 0.90 and 0.91 archived (four entries), root
> 79,233 → **56,005 B**. Reconciled: 23,228 B out of the root, 23,206 B into the
> archive, the 22-byte difference being the `---` separator this file replaces
> with its own header. Split **to a floor**: headroom went from 2,687 B — one
> entry from breaching — to 25,915 B. Done by hand again; the script was not
> run, so its two known defects (this table's broken `sed`, the duplicated
> "Older releases" section) were neither triggered nor fixed and still stand.
>
> **2026-11-07, the 0.92.6 cut**: 0.89 archived (six entries, 25,206 B), taking
> the root from 81,024 B to 55,818 B. The split now runs **down to a floor**
> rather than just under the ceiling, so it buys several cuts of headroom
> instead of firing every release. **The split was done by hand, not by
> `changelog-archive-split.sh`** — the script was not run, so its two known
> defects (this table's broken `sed`, the duplicated "Older releases" section)
> were neither triggered nor fixed and still stand.
>
> **Correction to the 0.92.5 note below, which was wrong twice.** It recorded
> RFC 028's five-minor and ~80 KB rules as "in open conflict" with "the byte
> rule … enforced" and winning. Measured: the five is *derived from* the budget
> in Requirement 1's own parenthesis, not asserted beside it, and it went stale
> because releases per minor rose 1.0 → 2.90 → 4.00; entry size, which the note
> blamed, has been *falling* (9,316 → 2,150 B/entry). And **neither rule is
> enforced** — the budget appears nowhere in `scripts/`, `.github/workflows/`
> or `Makefile` except this directory's own split script, which a human must
> run. RFC 028 Step 5's CI budget check was specified as runnable bash and
> never built.
>
> **2026-11-04, the 0.92.5 cut**: 0.88 archived because the byte budget fired
> at 82 KB — the first split driven by the budget rather than by neglect. It
> left **four** minor series in the root file. Shorter entries were tried and
> measured first (0.92.4's was 2,879 B) and still left zero headroom — the
> wrong variable, see the correction above. The script's two defects reproduced
> here too; both fixed by hand.
>
> The four v0.50–v0.84 files were added 2026-10-31, in one pass. The policy
> below had not been applied since v0.49, so the root file had reached **318 KB
> against its own ~80 KB budget** — forty minor versions inline instead of five.
> `scripts/changelog-archive-split.sh` did the split; it does **not** update
> this table (its `sed` for that is broken and swallowed by `|| true`) and it
> appends a duplicate "Older releases" section on each successive run. Both were
> fixed by hand here, and both are recorded in RFC 028's enforcement note.
>
> `CHANGELOG-0.85-to-0.87.md` was added 2026-11-03 (RFC 152 half D), by the
> same script, with the same two defects, fixed by hand the same way. The root
> file was at 79 KB of its 80 KB budget — under budget, so the script's own
> size guard would have refused to run — but already held eight minors against
> the five the policy states; this split ran by that rule, not by the guard.

## ROADMAP shipped-table archive

| File | Versions |
|---|---|
| [`ROADMAP-shipped-0.31-to-0.52.md`](ROADMAP-shipped-0.31-to-0.52.md) | v0.31.0 – v0.52.1 (full narrative) |

The root [`ROADMAP.md`](../../ROADMAP.md) keeps a condensed summary table
with links back to this directory.

## Archive policy (RFC 028)

- Root `CHANGELOG.md` target: ≤ 80 KB.  When the next minor release pushes
  it over budget, move the oldest minor range here (one PR).
- Root `ROADMAP.md` target: ≤ 40 KB.  Shipped rows are summary + link;
  full narrative lives here.
- Archive files are never edited after creation — they are immutable history.
- New archive files follow the naming convention:
  - `CHANGELOG-M.m-to-M.n.md` (CHANGELOG range)
  - `ROADMAP-shipped-M.m-to-M.n.md` (ROADMAP shipped range)
