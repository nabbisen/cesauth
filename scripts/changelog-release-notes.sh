#!/usr/bin/env bash
# RFC-less handoff `rfcs/handoffs/0.109.0-release-machinery/` — extract one
# version's CHANGELOG entry, verbatim, for the GitHub Release workflow
# (T1/T2) to publish as the Release body. Runnable locally so a reviewer
# (or the §5 stop condition) can inspect exactly what a tag push would
# publish without dispatching anything:
#
#   bash scripts/changelog-release-notes.sh 0.108.0
#
# D1: looks in the root CHANGELOG.md first, then every archive file under
# docs/changelog-archive/ — the same file set drift-scan.sh's own release
# reconciliation (`CHANGELOG_FILES`) builds, so this script and that gate
# agree about where an entry can live without a second hand-written list.
#
# Exit codes, each its own failure mode (handoff §7):
#   0  found exactly one non-empty entry; printed to stdout
#   3  not found in any CHANGELOG file
#   4  found in more than one file (or twice in one) — a reconciliation
#      defect the release must not paper over, not a case to pick the
#      first match for
#   5  found, but the entry's body is empty (heading only)
#   2  usage error
set -euo pipefail

if [[ $# -ne 1 || -z "${1:-}" ]]; then
    echo "usage: $0 <version>   (e.g. $0 0.108.0)" >&2
    exit 2
fi
version="$1"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# D1: root file first, then every archive file — same construction as
# drift-scan.sh's CHANGELOG_FILES, so the two cannot drift apart silently.
CHANGELOG_FILES=("${REPO_ROOT}/CHANGELOG.md")
while IFS= read -r -d '' f; do
    CHANGELOG_FILES+=("$f")
done < <(find "${REPO_ROOT}/docs/changelog-archive" -name "*.md" -print0 | sort -z)

# Escape regex metacharacters in the version (dots are the only ones a
# version string can contain) so "0.108.0" matches literally, not as a
# wildcard.
escaped_version="${version//./\\.}"
heading_pattern="^## \\[${escaped_version}\\] - [0-9]{4}-[0-9]{2}-[0-9]{2}\$"

matches=()
for f in "${CHANGELOG_FILES[@]}"; do
    while IFS=: read -r lineno; do
        [[ -z "$lineno" ]] && continue
        matches+=("${f}:${lineno}")
    done < <(grep -nE "$heading_pattern" "$f" | cut -d: -f1 || true)
done

if [[ ${#matches[@]} -eq 0 ]]; then
    echo "error: no CHANGELOG entry found for version ${version} (searched ${#CHANGELOG_FILES[@]} file(s))" >&2
    exit 3
fi

if [[ ${#matches[@]} -gt 1 ]]; then
    echo "error: version ${version} has ${#matches[@]} CHANGELOG entries — a reconciliation defect, not resolved by picking one:" >&2
    printf '  %s\n' "${matches[@]}" >&2
    exit 4
fi

match="${matches[0]}"
file="${match%%:*}"
start_line="${match##*:}"

# D1/§2: extract the heading through the line before the next `## [`
# heading or the trailing `---` separator, whichever comes first — or
# end-of-file, for a file's oldest entry, which has no trailing
# separator of its own (confirmed against docs/changelog-archive/
# CHANGELOG-0.93-to-0.101.md's 0.93.0 entry).
body="$(awk -v start="$start_line" '
    NR < start { next }
    NR == start { print; next }
    /^## \[/ { exit }
    /^---$/ { exit }
    { print }
' "$file")"

# Empty-body check: strip the heading line itself, then see whether
# anything non-blank remains.
content_after_heading="$(printf '%s\n' "$body" | tail -n +2)"
if [[ -z "$(printf '%s' "$content_after_heading" | tr -d '[:space:]')" ]]; then
    echo "error: ${version}'s CHANGELOG entry (${file}:${start_line}) has no body past its heading" >&2
    exit 5
fi

printf '%s\n' "$body"
