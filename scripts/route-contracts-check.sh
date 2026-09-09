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

if [ "$registered_count" -eq 0 ]; then
  echo "❌  Extracted 0 registered routes from $LIB_RS." >&2
  echo "    This is a failure, not a pass — either the file has no" >&2
  echo "    routes (unexpected) or the extraction pattern no longer" >&2
  echo "    matches the route-registration idiom used there." >&2
  exit_code=1
fi

# ── E2 (RFC 132): every documented row must declare a Rendering mode ──
#
# route-contracts.md's 7th field (added by RFC 132) is the `Rendering`
# column: server | client | n/a, per docs/src/expert/view-rendering-policy.md.
# A missing or misspelled value fails the same way an undocumented route
# does — a partially-filled column that this check does not notice is
# exactly the failure mode a "✅ All 0 routes documented" empty-input pass
# once had (RFC 125 T5).
bad_rendering=$(
  awk -F'|' '
    /^\|[[:space:]]*(GET|POST|PUT|DELETE)[[:space:]]*\|/ {
      method = $2; gsub(/^[ \t]+|[ \t]+$/, "", method)
      path   = $3; gsub(/^[ \t]+`|`[ \t]*$/, "", path)
      rendering = $7; gsub(/^[ \t]+|[ \t]+$/, "", rendering)
      if (rendering != "server" && rendering != "client" && rendering != "n/a") {
        printf "%s %s -> \"%s\"\n", method, path, rendering
      }
    }
  ' "$CONTRACTS_MD"
)

if [ -n "$bad_rendering" ]; then
  echo "❌  Routes with a missing or invalid Rendering value (must be server|client|n/a):" >&2
  echo "$bad_rendering" | while read -r line; do echo "    $line" >&2; done
  echo "" >&2
  echo "    See docs/src/expert/view-rendering-policy.md." >&2
  exit_code=1
fi

# ── E3 (RFC 132): a `server`-declared route's handler must not call
#    leptos_html_shell ────────────────────────────────────────────────
#
# C1-132: three named, dated exemptions — the RFC 132 review's ruling on
# the conformance gap this check found while being built. Each entry is
# "METHOD PATH" -> the RFC that removes it. Do NOT widen this into a
# general exemption facility (RFC 132 §8 reserves that decision); add an
# entry here only on an explicit review ruling, same as these three.
#
#   GET /                          -- RFC 131 R3 (RFC 132 §8, original).
#                                     A green E3 here does NOT mean `/`
#                                     behaves: as of RFC 131 C1-131, `/`
#                                     was found served entirely by
#                                     Cloudflare Workers Static Assets
#                                     (Trunk's dev-only index.html),
#                                     never reaching this handler at all
#                                     -- no CSP, no security headers, a
#                                     live regression against RFC 006.
#                                     E3 only asserts the shell-call
#                                     invariant on code that, at `/`,
#                                     was off the request path entirely.
#                                     Fixed in C2-131 (index.html no
#                                     longer shipped); see that RFC for
#                                     current status before trusting
#                                     this exemption describes reality.
#   GET /login                     -- RFC 131 R3 (RFC 132 §8, original)
#   GET /me/security/totp/verify   -- RFC 131 R3 (RFC 132 C1-132 ruling 1,
#                                      2026-09-09 — found while building
#                                      this check; on the *only* recovery
#                                      path for a no-JS TOTP user, so R3
#                                      must fix it alongside `/login`, not
#                                      as an afterthought)
E3_EXEMPT="GET /
GET /login
GET /me/security/totp/verify"

# Resolve a handler's qualified name (e.g. "routes::magic_link::verify",
# as lib.rs spells the call) to one of three states, distinguished by
# return code — NOT just "does it call the shell": a handler this cannot
# locate at all must never be silently treated as clean.
#
#   0 — resolved; its own function body calls leptos_html_shell
#   1 — resolved; its own function body does not call leptos_html_shell
#   2 — UNRESOLVED — neither shape below found the function. Hard
#       failure, not a pass. (RFC 132 C1-132 review: the original draft
#       `return 1`'d here, i.e. treated "could not find it" the same as
#       "found it and it's clean" — indistinguishable to the caller.
#       Silent under-reporting is the exact failure class RFC 125 T5
#       exists to prevent; this check must not reintroduce it.)
#
# Two shapes cover every route in this codebase as of this writing
# (verified against all 188): a direct function in a module file
# (routes::ui::login -> routes/ui.rs, fn login), and a same-named
# single-function re-export (routes::magic_link::verify -> `pub use
# verify::verify;` in routes/magic_link.rs -> routes/magic_link/verify.rs,
# fn verify). A *renamed* re-export (e.g. oidc.rs's `pub use
# userinfo::handler as userinfo_handler`) resolves neither shape and is
# therefore now a hard failure on the day a route using it is ever
# declared `server` — which is exactly when this needs extending, and
# the failure says so rather than passing silently.
resolve_handler_shell_status() {
  local qualified="$1"
  local fn="${qualified##*::}"
  local modpath="${qualified%::*}"
  local dirpath="${modpath//:://}"

  # Shape 1: direct function in <dirpath>.rs
  local f1="$REPO_ROOT/crates/backend/src/${dirpath}.rs"
  if [ -f "$f1" ] && fn_exists_in_file "$f1" "$fn"; then
    if fn_body_has_shell "$f1" "$fn"; then return 0; else return 1; fi
  fi

  # Shape 2: same-named submodule re-export, <dirpath>/<fn>.rs
  local f2="$REPO_ROOT/crates/backend/src/${dirpath}/${fn}.rs"
  if [ -f "$f2" ] && fn_exists_in_file "$f2" "$fn"; then
    if fn_body_has_shell "$f2" "$fn"; then return 0; else return 1; fi
  fi

  return 2
}

# Is function $2 defined (as `pub async fn`/`pub fn`/`fn`, top-level) in
# file $1?
fn_exists_in_file() {
  grep -qE "^(pub async fn|pub fn|fn) $2(<|\()" "$1"
}

# Does function $2's body in file $1 contain leptos_html_shell? Bounded
# from its `pub async fn <name>` line to the next top-level `pub async
# fn`/`pub fn`/`fn` line, or EOF. Caller must have already confirmed the
# function exists (fn_exists_in_file) — this does not distinguish
# "clean" from "not found."
fn_body_has_shell() {
  awk -v want="$2" '
    /^pub async fn [a-zA-Z0-9_]+/ || /^pub fn [a-zA-Z0-9_]+/ || /^fn [a-zA-Z0-9_]+/ {
      if (match($0, /fn [a-zA-Z0-9_]+/)) {
        cur = substr($0, RSTART+3, RLENGTH-3)
      }
      in_target = (cur == want)
    }
    in_target && /leptos_html_shell/ { found=1 }
    END { exit !found }
  ' "$1"
}

# (method, path, qualified-handler) for every route registered in
# lib.rs. Flattens the router chain so a registration whose closure body
# spans multiple lines (the common case) is still one record.
route_handlers=$(
  awk '
    BEGIN { chunk=""; method=""; path=""; started=0 }
    /\.(get|post|put|delete)_async[[:space:]]*\(/ {
      if (started) print method "\t" path "\t" chunk
      started=1
      chunk=$0
      if (match($0, /\.(get|post|put|delete)_async/)) {
        m = substr($0, RSTART+1, RLENGTH-1); gsub(/_async/, "", m); method = toupper(m)
      }
      if (match($0, /"[^"]+"/)) path = substr($0, RSTART+1, RLENGTH-2)
      next
    }
    started && /\.run\(req/ { print method "\t" path "\t" chunk; started=0; next }
    started { chunk = chunk " " $0 }
  ' "$LIB_RS" | while IFS=$'\t' read -r m p c; do
    if [[ "$c" =~ (routes::[a-zA-Z0-9_:]+) ]]; then
      printf '%s\t%s\t%s\n' "$m" "$p" "${BASH_REMATCH[1]}"
    fi
  done
)

# server-declared (method, path) pairs from route-contracts.md.
server_routes=$(
  awk -F'|' '
    /^\|[[:space:]]*(GET|POST|PUT|DELETE)[[:space:]]*\|/ {
      method = $2; gsub(/^[ \t]+|[ \t]+$/, "", method)
      path   = $3; gsub(/^[ \t]+`|`[ \t]*$/, "", path)
      rendering = $7; gsub(/^[ \t]+|[ \t]+$/, "", rendering)
      if (rendering == "server") print method" "path
    }
  ' "$CONTRACTS_MD"
)

e3_violations=""
e3_unresolved=""
while IFS= read -r route; do
  [ -z "$route" ] && continue
  m="${route%% *}"
  p="${route#* }"
  handler=$(printf '%s\n' "$route_handlers" | awk -F'\t' -v m="$m" -v p="$p" '$1==m && $2==p {print $3; exit}')
  if [ -z "$handler" ]; then
    continue  # no handler resolved (shouldn't happen; the earlier missing/extra diff already covers registration)
  fi
  if resolve_handler_shell_status "$handler"; then
    status=0
  else
    status=$?
  fi
  case "$status" in
    0)
      exempted=$(printf '%s\n' "$E3_EXEMPT" | grep -Fx "$route" || true)
      if [ -z "$exempted" ]; then
        e3_violations="${e3_violations}${m} ${p} -> ${handler} calls leptos_html_shell, not on the exemption list
"
      fi
      ;;
    1) ;;  # clean, resolved
    2)
      e3_unresolved="${e3_unresolved}${m} ${p} -> ${handler} (neither direct-function nor same-named-re-export shape resolved it)
"
      ;;
  esac
done <<< "$server_routes"

if [ -n "$e3_unresolved" ]; then
  echo "❌  server-declared route(s) whose handler E3 could not locate in source:" >&2
  printf '%s' "$e3_unresolved" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
  echo "" >&2
  echo "    This is a hard failure, not a pass — an unresolved handler must never" >&2
  echo "    be treated as clean. Likely a renamed re-export (see resolve_handler_shell_status's" >&2
  echo "    comment); extend the resolver in scripts/route-contracts-check.sh to cover it." >&2
  exit_code=1
fi

if [ -n "$e3_violations" ]; then
  echo "❌  server-declared route(s) whose handler calls leptos_html_shell, and are not an approved exemption:" >&2
  printf '%s' "$e3_violations" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
  echo "" >&2
  echo "    Either the handler needs to stop calling the shell, or this needs a reviewed," >&2
  echo "    dated addition to E3_EXEMPT above — not a silent reclassification to client." >&2
  exit_code=1
fi

if [ "$exit_code" -eq 0 ]; then
  echo "✅  All ${registered_count} routes are documented in route-contracts.md"
fi

exit "$exit_code"
