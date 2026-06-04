#!/usr/bin/env bash
# route-contracts-check.sh — RFC 027
#
# Verifies that every route registered in crates/worker/src/lib.rs has a
# corresponding row in docs/src/expert/route-contracts.md.
#
# Run from the repository root:
#   bash scripts/route-contracts-check.sh
#
# Exit codes:
#   0 — all routes documented
#   1 — routes missing from the contracts table
#
# The check is intentionally simple: it does NOT validate the content of
# each row — that is a code-review responsibility.  It only enforces that
# no registered route is absent from the table.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB_RS="$REPO_ROOT/crates/worker/src/lib.rs"
CONTRACTS_MD="$REPO_ROOT/docs/src/expert/route-contracts.md"

# ── extract registered routes from lib.rs ────────────────────────────
# Pattern: .(get|post|put|delete)_async("/path/...",
# We normalise to uppercase METHOD + PATH, strip trailing spaces.

registered=$(
  grep -E '\.(get|post|put|delete)_async\s*\("' "$LIB_RS" |
  sed -E 's/.*\.(get|post|put|delete)_async\s*\("([^"]+)".*/\U\1\E \2/' |
  sort -u
)

# ── extract documented routes from contracts table ────────────────────
# Pattern: | GET | /path | ... (markdown table rows in any section)

documented=$(
  grep -E '^\|\s*(GET|POST|PUT|DELETE)\s+\|' "$CONTRACTS_MD" |
  sed -E 's/^\|\s*(GET|POST|PUT|DELETE)\s+\|\s*`([^`]+)`.*/\1 \2/' |
  sort -u
)

# ── diff: registered but not documented ──────────────────────────────

missing=$(comm -23 <(echo "$registered") <(echo "$documented") 2>/dev/null || true)
extra=$(comm -13 <(echo "$registered") <(echo "$documented") 2>/dev/null || true)

exit_code=0

if [ -n "$missing" ]; then
  echo "❌  Routes in lib.rs but MISSING from route-contracts.md:" >&2
  echo "$missing" | while read -r line; do echo "    $line" >&2; done
  echo "" >&2
  echo "    Add a row for each missing route to docs/src/expert/route-contracts.md" >&2
  exit_code=1
fi

if [ -n "$extra" ]; then
  echo "⚠   Routes documented but NOT registered in lib.rs (stale):" >&2
  echo "$extra" | while read -r line; do echo "    $line" >&2; done
  echo "" >&2
  echo "    Remove the stale rows from route-contracts.md" >&2
  exit_code=1
fi

if [ "$exit_code" -eq 0 ]; then
  registered_count=$(echo "$registered" | grep -c .) 2>/dev/null || true
  echo "✅  All ${registered_count} routes are documented in route-contracts.md"
fi

exit "$exit_code"
