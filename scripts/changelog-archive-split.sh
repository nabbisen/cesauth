#!/usr/bin/env bash
# changelog-archive-split.sh
#
# RFC 028: Move CHANGELOG entries older than a given minor version to the
# docs/changelog-archive/ directory.
#
# Usage:
#   scripts/changelog-archive-split.sh <split-from-version>
#
# Example (archive everything older than v0.53.0):
#   scripts/changelog-archive-split.sh 0.53.0
#
# The script:
#   1. Finds the line in CHANGELOG.md where ## [<split-version>] starts.
#   2. Everything at that version and older goes to a new archive file.
#   3. The root CHANGELOG.md is trimmed to keep only newer entries.
#   4. The archive README is updated.
#
# The script is idempotent: running it twice with the same arguments
# produces the same result (it checks whether the archive file already
# exists before writing).
#
# Requires: bash 4+, grep, sed, awk, python3.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHANGELOG="$REPO_ROOT/CHANGELOG.md"
ARCHIVE_DIR="$REPO_ROOT/docs/changelog-archive"
BUDGET_KB=80

# ── argument parsing ──────────────────────────────────────────────────

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <split-from-version>" >&2
  echo "  e.g. $0 0.53.0  # archives everything at v0.53.0 and older" >&2
  exit 1
fi
SPLIT_VERSION="$1"

# ── size guard ────────────────────────────────────────────────────────

current_kb=$(( $(wc -c < "$CHANGELOG") / 1024 ))
if [[ $current_kb -le $BUDGET_KB ]]; then
  echo "CHANGELOG.md is ${current_kb} KB (≤ ${BUDGET_KB} KB budget). No split needed."
  exit 0
fi
echo "CHANGELOG.md is ${current_kb} KB. Archiving entries at v${SPLIT_VERSION} and older…"

# ── find section boundary ─────────────────────────────────────────────

SPLIT_LINE=$(grep -n "^## \[${SPLIT_VERSION}\]" "$CHANGELOG" | head -1 | cut -d: -f1)
if [[ -z "$SPLIT_LINE" ]]; then
  echo "Error: ## [${SPLIT_VERSION}] not found in CHANGELOG.md" >&2
  exit 1
fi

# Determine the previous minor for the archive filename.
# E.g. split at 0.53.0 means we're archiving "older than 0.53.0".
# We'll name the file by looking at what's actually in the range.
OLDEST_VERSION=$(grep "^## \[" "$CHANGELOG" | tail -1 | grep -oP '\d+\.\d+\.\d+' | head -1)
NEWEST_ARCHIVED=$(sed -n "${SPLIT_LINE}p" "$CHANGELOG" | grep -oP '\d+\.\d+\.\d+' | head -1)

# Archive filename: e.g. CHANGELOG-0.41-to-0.52.md
OLDEST_MINOR=$(echo "$OLDEST_VERSION" | cut -d. -f1-2)
NEWEST_MINOR=$(echo "$NEWEST_ARCHIVED" | cut -d. -f1-2)
ARCHIVE_FILE="$ARCHIVE_DIR/CHANGELOG-${OLDEST_MINOR}-to-${NEWEST_MINOR}.md"

if [[ -f "$ARCHIVE_FILE" ]]; then
  echo "Archive file already exists: $ARCHIVE_FILE" >&2
  echo "Delete it manually before re-running if you intend to overwrite." >&2
  exit 1
fi

TOTAL_LINES=$(wc -l < "$CHANGELOG")
HEADER_END=$((SPLIT_LINE - 1))

# ── write archive file ────────────────────────────────────────────────
#
# Defect 3 (fixed here): a moved entry's relative Markdown link
# (`](docs/…)` or `](rfcs/…)`) resolved against the ROOT CHANGELOG.md's
# own directory. The archive file sits two levels down
# (docs/changelog-archive/), so the same link there must gain a `../../`
# prefix to resolve to the same target. Absolute (http/https), anchor-only
# (#...) and already-relative (./ or ../) links are left untouched.

{
  echo "# cesauth — CHANGELOG (archive: v${OLDEST_MINOR}–v${NEWEST_MINOR})"
  echo ""
  echo "> This file is part of the changelog archive."
  echo "> Current releases are in the root [\`CHANGELOG.md\`](../../CHANGELOG.md)."
  echo ""
  sed -n "${SPLIT_LINE},${TOTAL_LINES}p" "$CHANGELOG"
} > "$ARCHIVE_FILE"

REWRITTEN_LINKS=$(python3 - "$ARCHIVE_FILE" <<'PYEOF'
import re
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    text = f.read()

pattern = re.compile(r'\]\((docs/|rfcs/)([^)]*)\)')
count = 0

def rewrite(m):
    global count
    count += 1
    return f"](../../{m.group(1)}{m.group(2)})"

new_text = pattern.sub(rewrite, text)
with open(path, "w", encoding="utf-8") as f:
    f.write(new_text)
print(count)
PYEOF
)

echo "Wrote archive: $ARCHIVE_FILE (rewrote ${REWRITTEN_LINKS} root-relative link(s) to ../../-prefixed form)"

# ── trim root CHANGELOG.md ────────────────────────────────────────────
#
# Defect 2 (fixed here): the root preamble already carries its own
# "## Older releases" section (above the first "## [" entry heading, so
# it survives FIRST_SECTION's own boundary). The original script always
# `echo`d a second one. This version detects an existing block and
# REPLACES its version-range line in place instead of adding a new
# heading.

FIRST_SECTION=$(grep -n "^## \[" "$CHANGELOG" | head -1 | cut -d: -f1)
PREAMBLE_OLDER_LINE=$(sed -n "1,$((FIRST_SECTION - 1))p" "$CHANGELOG" | grep -n "^## Older releases" | head -1 | cut -d: -f1 || true)

if [[ -n "${PREAMBLE_OLDER_LINE:-}" ]]; then
  # An "## Older releases" section already exists in the preamble.
  # Update its "Entries for vX.Y.x and earlier are in" sentence to the
  # new split point, in place, rather than prepending a duplicate
  # section header.
  python3 - "$CHANGELOG" "$NEWEST_MINOR" "$FIRST_SECTION" <<'PYEOF'
import re
import sys

path, newest_minor, first_section = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(path, encoding="utf-8") as f:
    lines = f.readlines()

preamble = lines[:first_section - 1]
body = lines[first_section - 1:]

# Matches the existing "vX.Y.x and earlier are in [...]" sentence
# regardless of the exact surrounding bold/punctuation the note was
# last hand-written with -- only the version token itself is replaced,
# everything else in the sentence is left exactly as it was.
pattern = re.compile(r'v\d+\.\d+\.x and earlier are in')
replacement = f"v{newest_minor}.x and earlier are in"
new_preamble_text, n = pattern.subn(replacement, "".join(preamble))
if n == 0:
    print("ERROR: could not find a 'vX.Y.x and earlier are in' sentence to update", file=sys.stderr)
    sys.exit(1)

with open(path, "w", encoding="utf-8") as f:
    f.write(new_preamble_text)
    f.writelines(body)
print(f"updated in place ({n} replacement)")
PYEOF
  echo "Preamble's existing '## Older releases' section updated in place (not duplicated)."
else
  # No existing block — original behaviour, write a fresh one. Keeps
  # ALL entries for now (not just up to the split point): the
  # unconditional truncation step below drops the archived range,
  # the same way for both branches, rather than each branch deciding
  # independently where to stop.
  {
    sed -n "1,$((FIRST_SECTION - 1))p" "$CHANGELOG"
    echo "## Older releases"
    echo ""
    echo "Entries for v${NEWEST_MINOR}.x and earlier are in"
    echo "[\`docs/changelog-archive/\`](docs/changelog-archive/README.md)."
    echo ""
    sed -n "${FIRST_SECTION},${TOTAL_LINES}p" "$CHANGELOG"
  } > "${CHANGELOG}.new"
  mv "${CHANGELOG}.new" "$CHANGELOG"
fi

# Drop the archived entries themselves, regardless of which branch above ran.
NEW_FIRST_SECTION=$(grep -n "^## \[" "$CHANGELOG" | head -1 | cut -d: -f1)
NEW_SPLIT_LINE=$(grep -n "^## \[${SPLIT_VERSION}\]" "$CHANGELOG" | head -1 | cut -d: -f1)
sed -n "1,$((NEW_SPLIT_LINE - 1))p" "$CHANGELOG" > "${CHANGELOG}.new"
mv "${CHANGELOG}.new" "$CHANGELOG"

new_kb=$(( $(wc -c < "$CHANGELOG") / 1024 ))
echo "Root CHANGELOG.md trimmed: ${current_kb} KB → ${new_kb} KB"

# ── update archive README index ───────────────────────────────────────
#
# Defect 1 (fixed here): the original `sed -i "s|…|…|"` broke because the
# replacement text itself builds a Markdown table row containing `|`
# characters, and its failure was swallowed by `2>/dev/null || true`, so
# the script reported success with the index left stale. Builds the new
# row with Python instead of a one-line `sed` substitution, and does NOT
# swallow a failure to find the insertion point — a README whose table
# shape has changed must fail loudly, not silently skip the index update.

README="$ARCHIVE_DIR/README.md"
BASENAME=$(basename "$ARCHIVE_FILE")

# The new oldest version still in the root, read from the trimmed
# CHANGELOG.md itself rather than assumed by minor-number arithmetic
# (a gap in release numbering would make "newest archived + 1" wrong).
NEW_OLDEST_KEPT_VERSION=$(grep "^## \[" "$CHANGELOG" | tail -1 | grep -oP '\d+\.\d+\.\d+' | head -1)

python3 - "$README" "$BASENAME" "$OLDEST_MINOR" "$NEWEST_MINOR" "$NEW_OLDEST_KEPT_VERSION" <<'PYEOF'
import re
import sys

path, basename, oldest_minor, newest_minor, new_oldest_kept = sys.argv[1:6]
with open(path, encoding="utf-8") as f:
    lines = f.readlines()

new_row = f"| [`{basename}`]({basename}) | v{oldest_minor} – v{newest_minor} |\n"

# Append the new row as the LAST row of the existing table, not just
# before the "Current releases (...)" sentence that follows a blank
# line after the table — inserting there would leave a blank line
# between the table and the new row, which breaks GFM table continuity.
marker = "Current releases ("
marker_at = None
for i, line in enumerate(lines):
    if line.startswith(marker):
        marker_at = i
        break

if marker_at is None:
    sys.stderr.write(
        "ERROR: could not find the 'Current releases (' marker line in "
        f"{path} to anchor the table's end.\n"
    )
    sys.exit(1)

insert_at = None
for i in range(marker_at - 1, -1, -1):
    if lines[i].startswith("| "):
        insert_at = i + 1
        break

if insert_at is None:
    sys.stderr.write(
        f"ERROR: could not find the CHANGELOG archive table's last row "
        f"(a line starting with '| ') above the 'Current releases (' "
        f"marker in {path}.\n"
    )
    sys.exit(1)

lines.insert(insert_at, new_row)

# Defect 4 (found running this script on a real split for the first
# time, D3): the "Current releases (**vX.Y.Z and newer**)" sentence
# names the OLD oldest-kept version and was never updated by the
# original script at all -- every previous split fixed it by hand,
# same as the other three defects, and it just never got folded back
# into the tool. Fixed here rather than left for a fifth hand-fix.
pattern = re.compile(r'v\d+\.\d+\.\d+ and newer')
new_text, n = pattern.subn(f"v{new_oldest_kept} and newer", "".join(lines))
if n == 0:
    sys.stderr.write(
        f"ERROR: could not find the 'vX.Y.Z and newer' sentence in {path} "
        "to update.\n"
    )
    sys.exit(1)

with open(path, "w", encoding="utf-8") as f:
    f.write(new_text)
PYEOF

echo "Archive README index updated: ${BASENAME}"
echo "Done. Verify docs/changelog-archive/README.md and commit all changed files."
