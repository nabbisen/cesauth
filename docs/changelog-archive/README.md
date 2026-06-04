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

Current releases (v0.50.0 and newer) are in the root
[`CHANGELOG.md`](../../CHANGELOG.md).

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
