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
# Requires: bash 4+, grep, sed, awk.

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

{
  echo "# cesauth — CHANGELOG (archive: v${OLDEST_MINOR}–v${NEWEST_MINOR})"
  echo ""
  echo "> This file is part of the changelog archive."
  echo "> Current releases are in the root [\`CHANGELOG.md\`](../../CHANGELOG.md)."
  echo ""
  sed -n "${SPLIT_LINE},${TOTAL_LINES}p" "$CHANGELOG"
} > "$ARCHIVE_FILE"

echo "Wrote archive: $ARCHIVE_FILE"

# ── trim root CHANGELOG.md ────────────────────────────────────────────

# Extract header (everything before the first ## [ section)
FIRST_SECTION=$(grep -n "^## \[" "$CHANGELOG" | head -1 | cut -d: -f1)

{
  sed -n "1,$((FIRST_SECTION - 1))p" "$CHANGELOG"
  echo "## Older releases"
  echo ""
  echo "Entries for v${NEWEST_MINOR}.x and earlier are in"
  echo "[\`docs/changelog-archive/\`](docs/changelog-archive/README.md)."
  echo ""
  sed -n "${FIRST_SECTION},$((SPLIT_LINE - 1))p" "$CHANGELOG"
} > "${CHANGELOG}.new"

mv "${CHANGELOG}.new" "$CHANGELOG"

new_kb=$(( $(wc -c < "$CHANGELOG") / 1024 ))
echo "Root CHANGELOG.md trimmed: ${current_kb} KB → ${new_kb} KB"

# ── update archive README index ───────────────────────────────────────

README="$ARCHIVE_DIR/README.md"
BASENAME=$(basename "$ARCHIVE_FILE")

# Insert the new entry into the CHANGELOG archive table.
# Find the "| Current releases" line and insert before it.
sed -i "s|^Current releases.*|\`| [${BASENAME}](${BASENAME}) | v${OLDEST_MINOR} – v${NEWEST_MINOR} |\n&|" "$README" 2>/dev/null || true

echo "Done. Verify docs/changelog-archive/README.md and commit all changed files."
