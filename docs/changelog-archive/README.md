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

Current releases (**v0.85.0 and newer**) are in the root
[`CHANGELOG.md`](../../CHANGELOG.md).

> The four v0.50–v0.84 files were added 2026-10-31, in one pass. The policy
> below had not been applied since v0.49, so the root file had reached **318 KB
> against its own ~80 KB budget** — forty minor versions inline instead of five.
> `scripts/changelog-archive-split.sh` did the split; it does **not** update
> this table (its `sed` for that is broken and swallowed by `|| true`) and it
> appends a duplicate "Older releases" section on each successive run. Both were
> fixed by hand here, and both are recorded in RFC 028's enforcement note.

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
