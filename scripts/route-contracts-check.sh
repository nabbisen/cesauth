#!/usr/bin/env bash
# route-contracts-check.sh — RFC 027, path/diagnostic fix RFC 125 (T4/T5)
#
# Verifies that every route registered in crates/backend/src/lib.rs has a
# corresponding row in docs/src/expert/route-contracts.md.
#
# Run from the repository root:
#   bash scripts/route-contracts-check.sh
#
# Exit codes:
#   0 — all routes documented, and at least one route was found
#   1 — routes missing from the contracts table, or the extraction found
#       zero registered routes (RFC 125 T5: a zero count is a failure,
#       not a vacuous pass)
#   2 — the expected input file does not exist (named diagnostic instead
#       of a raw `grep:` error, so a future crate rename fails loudly)
#
# The check is intentionally simple: it does NOT validate the content of
# each row — that is a code-review responsibility.  It only enforces that
# no registered route is absent from the table.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB_RS="$REPO_ROOT/crates/backend/src/lib.rs"
CONTRACTS_MD="$REPO_ROOT/docs/src/expert/route-contracts.md"

if [ ! -f "$LIB_RS" ]; then
  echo "❌  Expected route registration file not found: $LIB_RS" >&2
  echo "    (route-contracts-check.sh's LIB_RS path is stale — the Worker" >&2
  echo "    entrypoint crate was renamed and this script was not updated)" >&2
  exit 2
fi

if [ ! -f "$CONTRACTS_MD" ]; then
  echo "❌  Expected route contracts table not found: $CONTRACTS_MD" >&2
  exit 2
fi

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

registered_count=$(printf '%s\n' "$registered" | grep -c . || true)

if [ "$exit_code" -eq 0 ]; then
  if [ "$registered_count" -eq 0 ]; then
    echo "❌  Extracted 0 registered routes from $LIB_RS." >&2
    echo "    This is a failure, not a pass — either the file has no" >&2
    echo "    routes (unexpected) or the extraction pattern no longer" >&2
    echo "    matches the route-registration idiom used there." >&2
    exit_code=1
  else
    echo "✅  All ${registered_count} routes are documented in route-contracts.md"
  fi
fi

exit "$exit_code"
