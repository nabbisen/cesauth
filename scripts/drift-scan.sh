#!/usr/bin/env bash
# scripts/drift-scan.sh — detect stale narrative phrases in codebase.
#
# RFC 012 (v0.52.1): Runs on every PR and as part of the release checklist.
# Each pattern corresponds to a claim that was true in an old version of
# cesauth but is now false. A match means a comment or doc still refers to
# a removed subsystem or superseded behavior.
#
# To add a new pattern:
#   1. Identify the stale phrase (be specific — avoid common words).
#   2. Append to PATTERNS with a comment explaining why it's stale.
#   3. Fix any existing hits before merging.
#
# Usage:
#   ./scripts/drift-scan.sh           # exit 0 = clean, exit 1 = stale phrases found
#   ./scripts/drift-scan.sh --verbose # print every matched line (not just files)
set -euo pipefail

VERBOSE=0
[[ "${1:-}" == "--verbose" ]] && VERBOSE=1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN_PATHS=("${REPO_ROOT}/crates" "${REPO_ROOT}/docs" "${REPO_ROOT}/README.md")

# ---------------------------------------------------------------------------
# Stale-phrase registry.
# Each entry is "pattern|reason" (tab-separated — no tabs in patterns please).
# Patterns must be specific enough not to fire on *historical explanations* of
# why something changed (e.g. migration docs legitimately reference "R2 audit").
# Target: present-tense claims about removed behavior.
# ---------------------------------------------------------------------------
declare -a PATTERNS=(
    # README/intro claim: "all land in R2" — false since v0.32.0.
    "all land in R2	present-tense audit-to-R2 claim (v0.32.0 moved to D1, ADR-010)"
    # Binding name removed in v0.32.0.
    "R2_AUDIT	R2_AUDIT binding removed in v0.32.0"
    # OTP field naming: v0.50.3 renamed code_plaintext → delivery_payload (RFC 008).
    # Note: the audit/tests.rs denylist file itself references "code_plaintext" as a
    # string to detect — that's intentional and excluded below via grep's -l vs -n.
    # Pattern is specific enough: `code_plaintext:` (field declaration) not a string literal.
    "pub code_plaintext	renamed to delivery_payload in v0.50.3 (RFC 008); field should not re-appear"
    # README claim corrected in v0.52.1 (RFC 012).
    "No management GUI	README claim corrected in v0.52.1 (RFC 012)"
)

found=0

for entry in "${PATTERNS[@]}"; do
    pattern="${entry%%	*}"
    reason="${entry##*	}"

    matches=()
    for path in "${SCAN_PATHS[@]}"; do
        if [[ -e "$path" ]]; then
            while IFS= read -r line; do
                matches+=("$line")
            done < <(grep -rn --include="*.rs" --include="*.md" --include="*.toml" \
                         -E "$pattern" "$path" 2>/dev/null || true)
        fi
    done

    if [[ ${#matches[@]} -gt 0 ]]; then
        echo "STALE: \"$pattern\" ($reason)"
        if [[ $VERBOSE -eq 1 ]]; then
            for m in "${matches[@]}"; do
                echo "  $m"
            done
        fi
        found=$((found + 1))
    fi
done

if [[ $found -gt 0 ]]; then
    echo ""
    echo "$found stale-phrase pattern(s) detected."
    echo "Update or remove the stale text, then re-run this script."
    exit 1
fi

echo "drift-scan: clean — no stale phrases detected."
