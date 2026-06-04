# RFC 028: CHANGELOG / ROADMAP volume policy — historical archive split, summary-style maintenance

**Status**: Implemented
**ROADMAP**: Internal repository hygiene — `CHANGELOG.md` (511 KB) and `ROADMAP.md` (211 KB) bloat
**ADR**: N/A — repository convention; small enough to live inline
**Severity**: **P2 — both files are large enough to slow editor open, search, and human reading; the recent-history portion most readers want is buried under hundreds of historical lines**
**Estimated scope**: Medium — split convention + per-version-range archive directory + script to regenerate root files; ~100 LOC of bash; one-shot migration of existing content
**Source**: User request in v0.52.1 conversation: "ファイルを分割したり、履歴記載比重を RFC 参照にするなどして、プロジェクト構成をすっきりした"

## Background

As of v0.52.1:

- `CHANGELOG.md` is **511,868 bytes** (~12,600
  lines). Every version from 0.1.0 onward is
  inline.
- `ROADMAP.md` is **211,114 bytes** (~1,532
  lines), with the bulk concentrated in a
  single "Shipped" table whose rows are
  multi-thousand-character narrative summaries.

Two structural problems compound:

1. **Editor / search friction.** A 500-KB markdown
   file slows IDE open, slows full-document
   search, and produces unwieldy diffs. Reviewers
   reading a CHANGELOG PR can't easily scope
   their attention.

2. **The recent-history portion is buried.** A
   reader landing on `CHANGELOG.md` to learn
   what shipped in the last release has to
   scroll past months of history. The
   reverse-chronological convention helps, but
   only the *first* recent entry; entries from
   "two releases ago" are still relative-rare
   to find without a text search.

The user's constraint:

> ファイル分割する場合、プロジェクトのルート階層を
> 複雑化させることは NG。

So the fix can introduce ONE new directory at
most, and the root must stay clean.

## Requirements

The fix must:

1. The root `CHANGELOG.md` is reduced to the most
   recent ~5 minor versions (a number large
   enough to cover most "what shipped recently"
   queries, small enough to keep the file under
   ~80 KB).
2. Older entries are preserved verbatim — never
   delete history — but live in a single
   subdirectory that does not pollute the root.
3. The same applies to the ROADMAP "Shipped"
   table: keep recent rows in `ROADMAP.md`,
   move older rows into the same archive area.
4. The root files contain a clear pointer to
   the archive (single one-line link) so a
   reader looking for older history finds it.
5. The split convention is enforceable: a script
   generates the archive split deterministically,
   and a CI check (or release-time check) flags
   when the root file gets too large.

## Decision / Plan

### Step 1 — One new archive directory

Add `docs/changelog-archive/` to the repository.
*All* historical content — both CHANGELOG entries
and ROADMAP shipped-table rows — goes here. The
project root stays unchanged (no new top-level
items beyond what already exists).

Directory layout:

```text
docs/
  changelog-archive/
    CHANGELOG-0.1-to-0.30.md       ← about 30 entries
    CHANGELOG-0.31-to-0.40.md      ← about 10
    CHANGELOG-0.41-to-0.49.md      ← about 9
    ROADMAP-shipped-0.1-to-0.40.md ← shipped-table rows
    ROADMAP-shipped-0.41-to-0.49.md
    README.md                      ← index of which file holds which versions
```

The split-by-minor-version-range pattern keeps
each archive file in the 50-100 KB range —
substantial but tractable for both diff review
and editor open.

### Step 2 — Reduce root `CHANGELOG.md`

The root file keeps:

- The masthead (the existing intro paragraph,
  Keep-a-Changelog reference, semver note).
- A new "Older releases" pointer to the archive:
  ```markdown
  ## Older releases

  v0.50.x and earlier are recorded under
  [`docs/changelog-archive/`](./docs/changelog-archive/README.md),
  split by minor-version range:
  - v0.41-v0.49 → `CHANGELOG-0.41-to-0.49.md`
  - v0.31-v0.40 → `CHANGELOG-0.31-to-0.40.md`
  - v0.1-v0.30 → `CHANGELOG-0.1-to-0.30.md`
  ```
- The most recent N minor versions inline. As of
  v0.52.1 that's v0.50.0–v0.52.1 (the
  introspection / per-RFC sequence releases).

Target: root `CHANGELOG.md` should stay below
~80 KB ongoing. When the next minor release
takes the file over budget, the oldest minor
range gets archived (one PR per archive
operation).

### Step 3 — Reduce root `ROADMAP.md`

The root file keeps:

- Versioning policy section (unchanged).
- A condensed "Shipped" table where each row
  is a *summary line* + link to the relevant
  CHANGELOG entry, NOT the multi-thousand-
  character narrative the table currently
  holds. Example:

  ```markdown
  | Area | Shipped at | Detail |
  |---|---|---|
  | Five-crate workspace + ports/adapters | v0.1.0 | [archive](./docs/changelog-archive/CHANGELOG-0.1-to-0.30.md#010) |
  | OIDC discovery + JWKS | v0.1.0 | [archive](.../CHANGELOG-0.1-to-0.30.md#010) |
  | TOTP MFA (full track) | v0.26-v0.30 | [archive](.../CHANGELOG-0.1-to-0.30.md#totp-track) |
  | RFC 7662 introspection | v0.38.0 | [archive](.../CHANGELOG-0.31-to-0.40.md#0380) |
  | Per-client introspection audience | v0.50.0 | [`#0500`](#v0500) |
  ```

- "Planned" section (largely unchanged — this
  is forward-looking, kept inline).
- "Out of scope" section (unchanged).

Target: root `ROADMAP.md` should stay below
~40 KB ongoing.

### Step 4 — Per-RFC referencing convention

For new releases going forward, the CHANGELOG
entry style should lean on RFC referencing rather
than re-narrating the design:

```markdown
## [0.53.0] - 2026-XX-XX

Implements RFC 020 (migration chain hygiene), RFC 021
(user-FK cascade alignment), RFC 022 (permission
catalog seed sync). See the linked RFCs for design
detail.

### What shipped (summary)

- D1 migration chain now applies cleanly against
  fresh databases; FKs from authenticators / consent
  / grants restored to live `users` table; case-
  insensitive email uniqueness restored on `users`.
  See [RFC 020](rfcs/done/020-migration-chain-hygiene.md).
...
```

Compare to the v0.50.0 entry's ~10000-character
single paragraph. The RFC link IS the design
record; the CHANGELOG's job is the wire-form /
operator-facing what-changed list.

This is a convention shift, not a tooling change.
RFC 028 establishes it; subsequent CHANGELOG
authors follow it.

### Step 5 — `scripts/changelog-archive-split.sh`

A helper script that, given a "split point" minor
version, moves all entries below that into the
archive directory. The script:

1. Reads `CHANGELOG.md`.
2. Identifies entries by `## [X.Y.Z]` headings.
3. Splits at the requested boundary.
4. Writes the older portion to a new file in
   `docs/changelog-archive/CHANGELOG-X.Y-to-Y.Z.md`.
5. Replaces those entries in the root file with
   the "Older releases" pointer block.
6. Updates the archive README's index.

Used at release-time when the root file approaches
budget. The script is a convenience, not a
gate — operators may also do it by hand.

### Step 6 — CI check on file size

Append to `scripts/drift-scan.sh` or a new
companion script:

```bash
# Root file size budgets per RFC 028.
CHANGELOG_BUDGET_BYTES=$((80 * 1024))     # 80 KiB
ROADMAP_BUDGET_BYTES=$((40 * 1024))        # 40 KiB

cl_size=$(stat -c %s CHANGELOG.md 2>/dev/null || stat -f %z CHANGELOG.md)
if [ "$cl_size" -gt "$CHANGELOG_BUDGET_BYTES" ]; then
    echo "CHANGELOG.md is $cl_size bytes (budget $CHANGELOG_BUDGET_BYTES). " \
         "Run scripts/changelog-archive-split.sh to archive older entries." >&2
    exit 1
fi

rm_size=$(stat -c %s ROADMAP.md 2>/dev/null || stat -f %z ROADMAP.md)
if [ "$rm_size" -gt "$ROADMAP_BUDGET_BYTES" ]; then
    echo "ROADMAP.md is $rm_size bytes (budget $ROADMAP_BUDGET_BYTES). " \
         "Move older Shipped rows to docs/changelog-archive/." >&2
    exit 1
fi
```

The CI check fails the PR if the root files have
grown past budget — the author then runs the
archive-split tool or manually moves rows. Like
the bundle-size budget in RFC 025, the budget can
be raised by a deliberate PR; the gate's role is
to make growth visible.

## Test plan

- The archive split script is tested by running
  it locally on the current `CHANGELOG.md` and
  verifying:
    - All entries are present somewhere (root
      OR archive).
    - The archive README's index lists every
      archive file.
    - Markdown anchors used in cross-references
      still resolve (entries' GitHub-flavored
      anchor IDs are stable across the move).
- The CI size check is tested by creating a
  test-only branch that bloats the file and
  asserting the workflow fails.

## Security considerations

None. This RFC is pure repository hygiene.

Indirect benefit: a CHANGELOG that's small enough
to read end-to-end during a security review is
more likely to be read. Reviewers' attention is
finite; the v0.50.0 entry alone was longer than
many full project READMEs.

## Open questions

1. **Should the archive split be by minor-version
   range or by year?** Per minor-range matches the
   project's release cadence and produces stable
   "v0.X – v0.Y" file names that don't change as
   releases continue. Year-based splits would
   mean rotating files at year boundaries. The
   range-based choice is simpler.

2. **Does the same policy apply to RFC files
   themselves?** No. RFCs are bounded artifacts
   (one file per RFC), so individual RFCs don't
   bloat. The `rfcs/proposed/` and `rfcs/done/`
   folders are already RFC-019-governed.

3. **Should we also archive ADRs?** ADRs are
   already structured one-per-file; they don't
   have the bloat shape. No change needed.

## Implementation order

1. Create `docs/changelog-archive/` with an
   initial README explaining the structure.
2. Run the (manually invoked) split:
    - `CHANGELOG-0.1-to-0.30.md`
    - `CHANGELOG-0.31-to-0.40.md`
    - `CHANGELOG-0.41-to-0.49.md`
3. Reduce root `CHANGELOG.md` to v0.50.0+
   plus the "Older releases" pointer.
4. Reduce root `ROADMAP.md` Shipped table to
   summary-line shape with archive links.
5. Land the archive-split script.
6. Land the CI size check.
7. Document the new RFC-referencing convention
   in `cesauth-開発指示書` (the development
   directive doc) so future CHANGELOG entries
   follow it.
8. One PR per step is preferable — the bulk
   move (steps 2-4) is large but mechanical
   and reviewable.

## Notes for the implementer

- Anchor stability matters: GitHub renders
  `## [0.50.0] - 2026-04-30` to anchor `#0500`.
  External references to `#0500` work whether
  that entry is in the root file or in
  `docs/changelog-archive/CHANGELOG-0.50-...`.
  The archive README must spell out which file
  holds which version range so external link
  rewriters can do the math.
- Do not delete entries during the move. The
  archive is the durable record.
- The root files can live at the project root
  per the user's constraint. The single new
  directory `docs/changelog-archive/` is the
  one allowed addition.
- For the very-long-row ROADMAP "Shipped"
  cells, the conversion to summary-line + link
  is *manual editorial work*. A script can't
  do it well — the summary line is human-
  authored, distilling the multi-paragraph
  narrative.
- The "Planned" section of ROADMAP and "Out of
  scope" stay inline. Only the "Shipped" table
  is touched.
