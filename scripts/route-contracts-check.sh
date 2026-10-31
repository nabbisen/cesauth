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
APP_RS="$REPO_ROOT/crates/frontend/src/app.rs"
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

# RFC 159 cycle 3 (§4.4): every extractor below that scans lib.rs for a
# registration or a `routes::` call reads THIS, not the raw file --
# "a line whose first non-whitespace is `//` is not a registration" made
# true once, from one shared step, rather than patched separately into
# each grep/awk that looks at lib.rs (which is how E1's registered-route
# extraction and E4's liveness check ended up with two DIFFERENT blind
# spots to the same commented-out-registration case in the first place).
# Whole comment LINES only, matched after trimming leading whitespace --
# `//` also occurs inside path/URL string literals this file registers
# (`"/*catchall"`, line 523, among others), so this deliberately does
# NOT attempt block comments: a naive `/* ... */` stripper would read
# that literal as an opening fence and eat the rest of the file. There
# are no block comments in lib.rs to miss by skipping that case.
LIB_RS_LIVE=$(grep -v '^[[:space:]]*//' "$LIB_RS")

# ── extract registered routes from lib.rs ────────────────────────────
# Pattern: .(get|post|put|delete)_async("/path/...",
# We normalise to uppercase METHOD + PATH, strip trailing spaces.

registered=$(
  printf '%s\n' "$LIB_RS_LIVE" |
  grep -E '\.(get|post|put|delete)_async\s*\("' |
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
#
# The TOTP verify gate was exempted here (RFC 132 C1-132 ruling 1,
# 2026-09-09) and is no longer: RFC 143 paid that debt — the handler renders
# the server-side template directly and does not call the shell. Removing
# the entry is RFC 143's stated acceptance test, not a reclassification.
E3_EXEMPT="GET /
GET /login"

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
    resolve_body_shell_status "$f1" "$fn"; return $?
  fi

  # Shape 2: same-named submodule re-export, <dirpath>/<fn>.rs
  local f2="$REPO_ROOT/crates/backend/src/${dirpath}/${fn}.rs"
  if [ -f "$f2" ] && fn_exists_in_file "$f2" "$fn"; then
    resolve_body_shell_status "$f2" "$fn"; return $?
  fi

  return 2
}

# RFC 145 — the E3 wrapper-indirection gap, found building cycle 1's
# fires/does-not-fire pair. `fn_body_has_shell` greps for the literal
# `leptos_html_shell`, but most GET handlers in this codebase (24 + 11 of
# them, measured) don't call it directly — they call one of two shared
# helpers that call it one level down:
#   operator_json_api::shell       -> routes/admin/operator_json_api.rs
#   tenant_admin::json_api::shell  -> routes/admin/tenant_admin/json_api.rs
# so a handler that reaches the shell only through a wrapper used to pass
# E3 silently. This resolves exactly those two, by file (not by chasing
# every `super::`/bare/`crate::`-prefixed spelling a generic path
# resolver would need to) — deliberately **one level**, per RFC 145's
# E3-wrapper-indirection handoff D1: we check the wrapper's OWN body for
# `leptos_html_shell` directly, never what the wrapper itself might call.
# A third wrapper, or a chain deeper than one level, is not something this
# function goes looking for — see its own fallback to UNRESOLVED below.
#
# Status codes match `resolve_handler_shell_status`'s: 0 shell, 1 clean,
# 2 UNRESOLVED (hard failure, same C1-132 ruling — a wrapper this cannot
# positively account for must never be silently treated as clean).
resolve_body_shell_status() {
  local file="$1" fn="$2"
  if fn_body_has_shell "$file" "$fn"; then
    return 0
  fi
  if fn_body_calls "$file" "$fn" 'operator_json_api::shell('; then
    # Re-verified every run, not assumed: if this wrapper's own body ever
    # stops calling the shell directly, the fact this whole branch relies
    # on no longer holds, and the caller must not read that as "clean".
    if fn_body_has_shell "$REPO_ROOT/crates/backend/src/routes/admin/operator_json_api.rs" "shell"; then
      return 0
    else
      return 2
    fi
  fi
  if fn_body_calls "$file" "$fn" 'json_api::shell('; then
    if fn_body_has_shell "$REPO_ROOT/crates/backend/src/routes/admin/tenant_admin/json_api.rs" "shell"; then
      return 0
    else
      return 2
    fi
  fi
  return 1
}

# Does function $2's body in file $1 contain the literal substring $3?
# Same bounding as `fn_body_has_shell` (its own `pub async fn`/`pub fn`/
# `fn` line to the next top-level one, or EOF), generalised to an
# arbitrary needle instead of `leptos_html_shell` specifically.
fn_body_calls() {
  awk -v want="$2" -v needle="$3" '
    /^pub async fn [a-zA-Z0-9_]+/ || /^pub fn [a-zA-Z0-9_]+/ || /^fn [a-zA-Z0-9_]+/ {
      if (match($0, /fn [a-zA-Z0-9_]+/)) {
        cur = substr($0, RSTART+3, RLENGTH-3)
      }
      in_target = (cur == want)
    }
    in_target && index($0, needle) { found=1 }
    END { exit !found }
  ' "$1"
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
  ' <<< "$LIB_RS_LIVE" | while IFS=$'\t' read -r m p c; do
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

# ── §4.2 (RFC 145 cycle 3): a `client`-declared GET row must have a
#    real, unambiguous `app.rs` route — RFC 145 §15.2 / cycle-3 handoff §3 ──
#
# A `client`-declared route serves the Leptos shell; the shell is useless
# if `leptos_router` has no `<Route>` for the path, or — the worse case,
# found at dispatch (RFC 145 §15.1) — a *different* route's `:param`
# segment swallows it. `/admin/tenancy/tenants/new` matched neither
# "has no route" check this project tried before landing on the right
# one (see the table below); it is captured by `path!("/admin/tenancy/
# tenants/:tid")`, so a system admin trying to create a tenant was shown
# the tenant-detail page for a tenant literally named "new" — not a
# Not Found, a different and plausible-looking page.
#
# Getting "matching" right took three attempts, recorded here so a
# future edit does not re-walk them:
#
#   | # | Rule | What it got wrong |
#   |---|---|---|
#   | 1 | a `:param` segment matches any segment | **False live**: swallows a literal, scoring a shadowed route as fine |
#   | 2 | "exact" = the app.rs route has no params at all | **False dead**: an app.rs route that is itself all-params (e.g. `/admin/tenancy/tenants/:tid`) can still be an exact structural match for an identically-shaped contract row |
#   | 3 | **exact = segment lists equal, literal-for-literal and param-for-param; otherwise a live route whose only differing segments are its own param standing over the contract row's literal is a SHADOW** | correct |
#
# So every `client`-declared GET row classifies into exactly one of
# three outcomes, not two:
#   - EXACT    — a live route with the identical segment shape. Pass.
#   - SHADOWED — no exact match, but a live route of the same segment
#                count would consume this path at runtime because one of
#                ITS segments is a `:param` sitting where this row has a
#                literal. Fail, and name the shadowing route — this is
#                the worse symptom (a different page renders, not
#                Not Found) and silence here is exactly how it went
#                undetected before RFC 145 §15.1 found it by hand.
#   - ABSENT   — no live route matches at all, by either rule. Fail.
#
# Named, dated, reviewed exemptions only — one today — same discipline as
# E3_EXEMPT above; this is not a general escape hatch (that decision
# stays with whoever can grant it, not this file).
#
#   GET /admin/console/clients  -- RFC 145 §11.3: no template exists for
#                                   it at all (`console/clients.rs` is
#                                   JSON throughout); RFC 141 cycle 2 owns
#                                   building the screen. Absent, and
#                                   expected to be, until that cycle lands.
GATE_42_EXEMPT="GET /admin/console/clients"

# Split a route path into its '/'-separated segments as a single
# space-joined string (bash word-splitting does the rest at call sites).
# A leading '/' produces a leading empty field, same on both sides of
# every comparison, so it cancels out consistently.
path_segments() {
  local IFS='/'
  # shellcheck disable=SC2086
  set -- $1
  echo "$@"
}

# Classify one `client`-declared GET path against the full list of
# app.rs path!() routes (one per line, in $app_routes). Echoes the
# shadowing route on a SHADOWED result. Returns 0 EXACT, 1 SHADOWED,
# 2 ABSENT.
classify_client_route() {
  local candidate="$1"
  local -a cseg
  read -ra cseg <<< "$(path_segments "$candidate")"
  local clen=${#cseg[@]}

  local live
  while IFS= read -r live; do
    [ -z "$live" ] && continue
    local -a lseg
    read -ra lseg <<< "$(path_segments "$live")"
    if [ "${#lseg[@]}" -ne "$clen" ]; then continue; fi
    local exact=1
    local i
    for ((i = 0; i < clen; i++)); do
      if [ "${lseg[$i]}" != "${cseg[$i]}" ]; then exact=0; break; fi
    done
    if [ "$exact" -eq 1 ]; then return 0; fi
  done <<< "$app_routes"

  while IFS= read -r live; do
    [ -z "$live" ] && continue
    local -a lseg
    read -ra lseg <<< "$(path_segments "$live")"
    if [ "${#lseg[@]}" -ne "$clen" ]; then continue; fi
    local shadow=1
    local i
    for ((i = 0; i < clen; i++)); do
      if [ "${lseg[$i]}" == "${cseg[$i]}" ]; then continue; fi
      if [[ "${lseg[$i]}" == :* ]] && [[ "${cseg[$i]}" != :* ]]; then continue; fi
      shadow=0; break
    done
    if [ "$shadow" -eq 1 ]; then echo "$live"; return 1; fi
  done <<< "$app_routes"

  return 2
}

if [ ! -f "$APP_RS" ]; then
  echo "❌  Expected frontend router file not found: $APP_RS" >&2
  echo "    (route-contracts-check.sh's APP_RS path is stale)" >&2
  exit 2
fi

app_routes=$(
  grep -oE 'path!\("[^"]+"\)' "$APP_RS" |
  sed -E 's/path!\("(.*)"\)/\1/' |
  sort -u
)

client_get_routes=$(
  awk -F'|' '
    /^\|[[:space:]]*GET[[:space:]]*\|/ {
      path      = $3; gsub(/^[ \t]+`|`[ \t]*$/, "", path)
      rendering = $7; gsub(/^[ \t]+|[ \t]+$/, "", rendering)
      if (rendering == "client") print path
    }
  ' "$CONTRACTS_MD" | sort -u
)

gate42_shadowed=""
gate42_absent=""
while IFS= read -r path; do
  [ -z "$path" ] && continue
  exempted=$(printf '%s\n' "$GATE_42_EXEMPT" | grep -Fx "GET $path" || true)
  shadow_route=$(classify_client_route "$path") && status=0 || status=$?
  case "$status" in
    0) ;;  # EXACT — pass
    1)
      if [ -z "$exempted" ]; then
        gate42_shadowed="${gate42_shadowed}GET ${path} -- shadowed by app.rs route \"${shadow_route}\"
"
      fi
      ;;
    2)
      if [ -z "$exempted" ]; then
        gate42_absent="${gate42_absent}GET ${path} -- no app.rs route of any shape
"
      fi
      ;;
  esac
done <<< "$client_get_routes"

if [ -n "$gate42_shadowed" ]; then
  echo "❌  client-declared GET route(s) SHADOWED by a different app.rs route's :param" \
       "(the worse symptom — a different page renders, not Not Found):" >&2
  printf '%s' "$gate42_shadowed" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
  echo "" >&2
  echo "    Either wire this GET server-side (RFC 145) or make the app.rs route" >&2
  echo "    unambiguous — a literal segment must never be shadowed by a sibling" >&2
  echo "    route's :param at the same position." >&2
  exit_code=1
fi

if [ -n "$gate42_absent" ]; then
  echo "❌  client-declared GET route(s) with NO app.rs route at all" \
       "(serves the shell, renders <NotFound/>):" >&2
  printf '%s' "$gate42_absent" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
  echo "" >&2
  echo "    Either add the matching <Route> to crates/frontend/src/app.rs, or wire" >&2
  echo "    this GET server-side (RFC 145) and declare it \`server\`." >&2
  exit_code=1
fi

# ── RFC 150: Response::from_html must not be reached except through a
#    nonce-setting call, in the same function ──────────────────────────
#
# RFC 006's invariant is a *per-request* CSP nonce. The security-headers
# middleware (`lib.rs`) builds the header by reading back whatever
# `cesauth_frontend::render_nonce()` holds; a handler that renders HTML
# without first calling `render_body_with_nonce` / `render_with_nonce` /
# `set_render_nonce` doesn't error — it silently reuses whatever an
# earlier, unrelated request left in that global. RFC 150 found this on
# seven of the crate's eleven `Response::from_html` call sites, confirmed
# live (two unrelated requests on one warm isolate sharing a nonce;
# `/admin/login` rendering unstyled on a cold one).
#
# Same shape as E3: resolve the function enclosing each `from_html` call,
# check whether that function's OWN body also calls one of the three
# nonce-setting names, and hard-fail — never silently pass — when the
# enclosing function cannot be resolved at all. A check that degrades to
# "found no fn, so nothing to flag" is the exact blind spot RFC 145 §11.2
# found in E3 and C1-132 ruled against repeating.
#
# Named, dated, reviewed exemptions only, same discipline as E3_EXEMPT
# and GATE_42_EXEMPT above — empty by design: all eleven call sites are
# fixed as of RFC 150, so there is nothing to exempt yet.
NONCE_EXEMPT=""

# One known one-level indirection, named explicitly rather than resolved
# generically — same E3 D1 precedent (RFC 145): `me/totp/verify.rs`'s
# `get_handler` never calls a nonce-setter itself; it calls
# `decide_verify_get`, which does (RFC 150 §2's own table: "yes — via
# decide_verify_get"). Re-verified every run, not assumed: if that
# function's own body ever stops calling `set_render_nonce` directly,
# this returns false and the caller falls through to a real violation —
# never silently treated as clean.
nonce_set_via_known_wrapper() {
  local file="$1" fn="$2"
  local totp_verify_rs="$REPO_ROOT/crates/backend/src/routes/me/totp/verify.rs"
  if [ "$file" = "$totp_verify_rs" ] && [ "$fn" = "get_handler" ]; then
    if fn_body_calls "$file" "$fn" 'decide_verify_get(' &&
       fn_body_calls "$totp_verify_rs" 'decide_verify_get' 'set_render_nonce('; then
      return 0
    fi
  fi
  return 1
}

# Scanned across the whole crate, not just `routes/`. Reviewed 2026-10-28:
# scoping this to `crates/backend/src/routes` let a nonce-less
# `Response::from_html` in `lib.rs` pass the gate — verified by adding one.
# All eleven sites happen to live under `routes/` today; the gate exists for
# the twelfth, which has no obligation to.
from_html_sites=$(
  grep -rn 'from_html(' "$REPO_ROOT/crates/backend/src" --include='*.rs' |
  grep -v 'tests\?\.rs\|tests/'
)

nonce_violations=""
nonce_unresolved=""

while IFS= read -r line; do
  [ -z "$line" ] && continue
  file="${line%%:*}"
  rest="${line#*:}"
  lineno="${rest%%:*}"
  rel="${file#"$REPO_ROOT"/}"

  fn=$(awk -v target="$lineno" '
    /^pub async fn [a-zA-Z0-9_]+/ || /^pub fn [a-zA-Z0-9_]+/ || /^fn [a-zA-Z0-9_]+/ {
      if (match($0, /fn [a-zA-Z0-9_]+/)) {
        cur = substr($0, RSTART+3, RLENGTH-3)
      }
    }
    NR == target { print cur; exit }
  ' "$file")

  if [ -z "$fn" ]; then
    nonce_unresolved="${nonce_unresolved}${rel}:${lineno} -- could not resolve an enclosing top-level fn
"
    continue
  fi

  key="${rel}::${fn}"
  if fn_body_calls "$file" "$fn" 'render_body_with_nonce(' ||
     fn_body_calls "$file" "$fn" 'render_with_nonce(' ||
     fn_body_calls "$file" "$fn" 'set_render_nonce(' ||
     nonce_set_via_known_wrapper "$file" "$fn"; then
    : # clean — a nonce-setting call lives in the same function's body
  else
    exempted=$(printf '%s\n' "$NONCE_EXEMPT" | grep -Fx "$key" || true)
    if [ -z "$exempted" ]; then
      nonce_violations="${nonce_violations}${rel}:${lineno} (fn ${fn}) -- Response::from_html reached with no nonce-setting call in this function's body
"
    fi
  fi
done <<< "$from_html_sites"

if [ -n "$nonce_unresolved" ]; then
  echo "❌  Response::from_html call(s) whose enclosing function E150 could not resolve:" >&2
  printf '%s' "$nonce_unresolved" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
  echo "" >&2
  echo "    This is a hard failure, not a pass — an unresolved call must never be" >&2
  echo "    treated as clean. Extend the fn-boundary resolver in this script." >&2
  exit_code=1
fi

if [ -n "$nonce_violations" ]; then
  echo "❌  Response::from_html call(s) with no nonce-setting call in the same function" \
       "(RFC 150 — the CSP nonce will be whatever an earlier, unrelated request left behind):" >&2
  printf '%s' "$nonce_violations" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
  echo "" >&2
  echo "    Mint and publish a nonce before rendering — render_body_with_nonce()" >&2
  echo "    (crates/backend/src/routes/admin/console/render.rs) is the shared helper" >&2
  echo "    every other HTML responder in this crate uses. Do not give this site its" >&2
  echo "    own set_render_nonce call; that per-site pattern is what produced RFC 150." >&2
  exit_code=1
fi

# ── E4 (RFC 159): every handler-shaped `pub async fn` in routes/ must be
#    reachable from lib.rs ──────────────────────────────────────────────
#
# RFC 125/145/150/157 all check something a *registered* route must do.
# None of them asks the opposite question: is a handler-shaped function
# registered at all? RFC 157's own cycle found fourteen that weren't,
# and a bare-name grep used to find them had already been shown (RFC 159
# §1) to hide a dead handler sharing its name with a live one — a
# same-named sibling makes the bare name "exist" in lib.rs even though
# *this* definition is never called. So this check works off each
# handler's full qualified path, not its bare name, same discipline as
# E3's resolver below it.
#
# A handler's natural qualified path is its file location relative to
# routes/ (routes/admin/console/alerts.rs, fn page_json -> qualified
# admin::console::alerts::page_json). RFC 159's own two named cases show
# that is not the only path that reaches it: a **one-level-up**
# re-export in the file that declares `mod <leaf>;` also reaches it,
# in either of two shapes (both exist today, both must resolve):
#   brace    -- admin.rs:32's `pub use legacy::{create_user, revoke_session};`
#   renaming -- oidc.rs:16/20's `pub use userinfo::handler as userinfo_handler;`
# (the trivial same-name case, `pub use leaf::fn;`, is the same shape
# E3's Shape 2 already resolves in the other direction, and is handled
# here too since it is just the renaming form with no alias). One level
# only -- same E3/NONCE precedent in this file; a re-export chain deeper
# than that is out of scope until a route using one is ever declared.
#
# A handler with no live qualified path -- natural or one-level
# flattened -- fails. Named, dated, reviewed exemptions only, same
# discipline as E3_EXEMPT/GATE_42_EXEMPT/NONCE_EXEMPT above. Empty by
# design: RFC 159 deleted its ten known-dead handlers (the nine named at
# dispatch, plus `admin::console::preview::handler` -- a tenth E4 itself
# found on its first real run, confirmed dead and folded in rather than
# exempted) rather than exempting them.
E4_EXEMPT=""

# RFC 159 continuation (§4.2): a qualified-path check only covers what it
# can recognise as a handler in the first place. The first E4 draft
# matched exactly one signature shape -- `(req: Request, ctx:
# RouteContext<D>)` on one physical line -- and so silently never looked
# at the eleven real, registered handlers under `me::security`/`me::totp`,
# which take `(req: Request, env: worker::Env)` instead (no `<D>`, no
# RouteContext -- `lib.rs` calls them as `routes::me::...(req,
# ctx.env)`), often spread across several lines. All eleven turned out to
# already be registered, so nothing was hiding there *today* -- but a dead
# handler added to that family tomorrow would have been exactly as
# invisible as the nine this RFC exists to catch, and the check would not
# even have said it had skipped them.
#
# So coverage, not just reachability, is now asserted: every top-level
# `pub async fn` under routes/ (216 as of this writing, test files
# excluded) must be either
#   (A) the RouteContext handler shape,
#   (B) the Env handler shape, or
#   (N) on NAMED_NON_HANDLERS below, with a reason,
# and anything in none of the three is a hard failure -- "a new shape
# appeared and nobody taught the gate about it" must stop the build, not
# print nothing. (A) and (B) are deliberately a *structural* match, not an
# enumerated list: every handler in this crate takes its `req` and its
# `ctx`/`env` **by value** (it owns the request, being the entry point);
# every non-handler below takes at least one of them **by reference** (or
# has no `req`/`env` parameter at all), because it is a helper called BY a
# handler, not the handler itself. That split holds for all 216 functions
# checked while building this, with zero exceptions on either side, so
# widening (A)/(B) to a new owned-param handler family costs nothing, and
# NAMED_NON_HANDLERS only has to carry the irreducible by-reference
# helpers -- it does not have to grow every time a new route is added.
#
# Grouped by why each is a helper, not a route handler -- "it takes its
# req/env by reference" is the mechanical tell in every case, which is
# exactly what keeps it out of (A)/(B):
#
#   admin/auth.rs::{resolve_from_request,resolve_or_respond,
#     resolve_from_request_header_only,resolve_or_respond_header_only}
#     -- principal resolution called BY admin handlers, not registered
#     itself (the header-only pair, RFC 152 half C, is the class-B
#     counterpart of the first two: same shape, no cookie fallback).
#   admin/operator_json_api.rs::{resolve_admin,shell} -- the operator-
#     console shell/resolve pair E3's own wrapper resolution already
#     names one level down from this list.
#   admin/tenancy_console/forms/common.rs::{require_manage,parse_form} --
#     shared form-helper utilities used by multiple tenancy-console forms.
#   admin/tenant_admin/gate.rs::{resolve_or_respond,check_action,
#     check_read,build_affordances} -- the tenant-admin authorization gate.
#   admin/tenant_admin/json_api.rs::{resolve_ctx,shell} -- the same
#     resolve/shell pair as operator_json_api, for the tenant_admin family.
#   api_v1/auth.rs::require -- the API-level permission-check helper.
#   api_v1/quota.rs::{check_quota,unwrap_storage,count_users,
#     count_organizations,count_groups} -- quota accounting and a
#     storage-result unwrapper; none takes a `Request` at all, only `&Env`
#     (or nothing).
#   leptos_shell.rs::leptos_html_shell -- the shared shell renderer E3's
#     own `fn_body_has_shell` greps for by name; a route handler calls it,
#     it is not one.
#   me/auth.rs::resolve_or_redirect -- the `me::` family's session
#     resolution helper, same role as admin/auth.rs's pair above.
#   me/totp/disable.rs::decide_disable_post,
#   me/totp/verify.rs::decide_verify_get -- pure decision functions
#     extracted from their handlers (RFC 150); `decide_verify_get` is the
#     one NONCE's own `nonce_set_via_known_wrapper` already names as a
#     one-level wrapper target.
NAMED_NON_HANDLERS="crates/backend/src/routes/admin/auth.rs::resolve_from_request
crates/backend/src/routes/admin/auth.rs::resolve_or_respond
crates/backend/src/routes/admin/auth.rs::resolve_from_request_header_only
crates/backend/src/routes/admin/auth.rs::resolve_or_respond_header_only
crates/backend/src/routes/admin/operator_json_api.rs::resolve_admin
crates/backend/src/routes/admin/operator_json_api.rs::shell
crates/backend/src/routes/admin/tenancy_console/forms/common.rs::require_manage
crates/backend/src/routes/admin/tenancy_console/forms/common.rs::parse_form
crates/backend/src/routes/admin/tenant_admin/gate.rs::resolve_or_respond
crates/backend/src/routes/admin/tenant_admin/gate.rs::check_action
crates/backend/src/routes/admin/tenant_admin/gate.rs::check_read
crates/backend/src/routes/admin/tenant_admin/gate.rs::build_affordances
crates/backend/src/routes/admin/tenant_admin/json_api.rs::resolve_ctx
crates/backend/src/routes/admin/tenant_admin/json_api.rs::shell
crates/backend/src/routes/api_v1/auth.rs::require
crates/backend/src/routes/api_v1/quota.rs::check_quota
crates/backend/src/routes/api_v1/quota.rs::unwrap_storage
crates/backend/src/routes/api_v1/quota.rs::count_users
crates/backend/src/routes/api_v1/quota.rs::count_organizations
crates/backend/src/routes/api_v1/quota.rs::count_groups
crates/backend/src/routes/leptos_shell.rs::leptos_html_shell
crates/backend/src/routes/me/auth.rs::resolve_or_redirect
crates/backend/src/routes/me/totp/disable.rs::decide_disable_post
crates/backend/src/routes/me/totp/verify.rs::decide_verify_get"

ROUTES_DIR="$REPO_ROOT/crates/backend/src/routes"
ROUTES_ROOT_FILE="$REPO_ROOT/crates/backend/src/routes.rs"

# File path (under routes/, or routes.rs itself) -> its own module path,
# "" for routes.rs (the crate-relative root -- routes::<name> with
# nothing in between).
e4_modpath_of() {
  local file="$1"
  if [ "$file" = "$ROUTES_ROOT_FILE" ]; then
    echo ""
    return
  fi
  local rel="${file#"$ROUTES_DIR"/}"
  rel="${rel%.rs}"
  echo "${rel//\//::}"
}

# Echoes zero or more additional bare names this handler is ALSO
# reachable as, one level up, by resolving every `pub use <leaf>::...;`
# statement in $3 (the file declaring `mod <leaf>;`) that mentions fn
# $2. Handles brace (`{a, b}`) and renaming (`a as b`) forms; a plain
# `leaf::fn;` falls out of the same renaming-form parse with no alias.
e4_reexport_names() {
  local leaf="$1" fn="$2" parent_file="$3"
  [ -f "$parent_file" ] || return 0
  local stmt body item name alias
  while IFS= read -r stmt; do
    [ -z "$stmt" ] && continue
    body="${stmt#pub use "${leaf}"::}"
    body="${body%;}"
    if [[ "$body" == \{*\} ]]; then
      body="${body#\{}"
      body="${body%\}}"
    fi
    IFS=',' read -ra items <<< "$body"
    for item in "${items[@]}"; do
      item="$(echo "$item" | xargs)"
      name="$item"
      alias=""
      if [[ "$item" == *" as "* ]]; then
        name="${item% as *}"
        alias="${item##* as }"
      fi
      if [ "$name" = "$fn" ]; then
        if [ -n "$alias" ]; then echo "$alias"; else echo "$fn"; fi
      fi
    done
  done < <(grep -oE "^pub use ${leaf}::[A-Za-z0-9_{}, ]+;" "$parent_file" || true)
}

# Every top-level `pub async fn <name>` under routes/ (test files
# excluded), one record per function: file \t start-line \t name \t
# signature. The signature is captured from the `pub async fn` line
# through the first subsequent line containing `{` (that line closes
# either the signature itself or a trailing `where` clause -- both
# precede the body in every shape this crate uses) and internal
# whitespace is squeezed to single spaces, so a signature spread over
# several aligned-column lines matches the same single-line regex a
# one-line signature does.
e4_all_defs() {
  local f
  while IFS= read -r f; do
    awk -v file="$f" '
      /^pub async fn [a-zA-Z0-9_]+/ {
        if (match($0, /fn [a-zA-Z0-9_]+/)) { name = substr($0, RSTART+3, RLENGTH-3) }
        start = NR
        buf = $0
        if (index($0, "{") > 0) { printf "%s\t%d\t%s\t%s\n", file, start, name, buf; next }
        capturing = 1
        next
      }
      capturing {
        buf = buf " " $0
        if (index($0, "{") > 0) {
          printf "%s\t%d\t%s\t%s\n", file, start, name, buf
          capturing = 0
        }
      }
    ' "$f"
  done < <(grep -rl '^pub async fn' "$ROUTES_DIR" --include='*.rs' | grep -v '/tests\?\.rs$\|/tests/')
}

# Shape A: owned (req: Request, ctx: RouteContext<D>) -> (worker::)?Result<Response>
e4_shapeA_re='fn [a-zA-Z0-9_]+<[A-Za-z]+>\( ?(mut )?_?req: Request, *_?ctx: RouteContext<[A-Za-z]+>,? ?\) -> (worker::)?Result<Response> ?\{'
# Shape B: owned (req: Request, env: worker::Env) -> (worker::)?Result<Response>
e4_shapeB_re='fn [a-zA-Z0-9_]+\( ?(mut )?_?req: Request, *_?env: worker::Env,? ?\) -> (worker::)?Result<Response> ?\{'

e4_total=0
e4_countA=0
e4_countB=0
e4_named_count=0
e4_unclassified_count=0
e4_unclassified=""
e4_handlers=""  # file \t name, one per classified handler (A or B)
e4_named_matched=""  # NAMED_NON_HANDLERS keys actually matched this run

while IFS=$'\t' read -r file line name buf; do
  [ -z "$file" ] && continue
  e4_total=$((e4_total + 1))
  sig=$(echo "$buf" | tr -s '[:space:]' ' ')
  if [[ "$sig" =~ $e4_shapeA_re ]] || [[ "$sig" =~ $e4_shapeB_re ]]; then
    if [[ "$sig" =~ $e4_shapeA_re ]]; then e4_countA=$((e4_countA + 1)); else e4_countB=$((e4_countB + 1)); fi
    e4_handlers="${e4_handlers}${file}\t${name}\n"
  else
    rel="${file#"$REPO_ROOT"/}"
    key="${rel}::${name}"
    named=$(printf '%s\n' "$NAMED_NON_HANDLERS" | grep -Fx "$key" || true)
    if [ -n "$named" ]; then
      e4_named_count=$((e4_named_count + 1))
      e4_named_matched="${e4_named_matched}${key}\n"
    else
      e4_unclassified_count=$((e4_unclassified_count + 1))
      e4_unclassified="${e4_unclassified}${rel}:${line} (fn ${name})\n"
    fi
  fi
done < <(e4_all_defs)

# RFC 159 cycle 4 (§4.5): a NAMED_NON_HANDLERS entry that matched nothing
# during THIS scan is stale -- the function behind it was deleted,
# renamed, or its signature changed to match shape (A)/(B) -- and is left
# sitting as a pre-authorised exemption for whatever gets written at that
# same `file::fn` next, reviewed by nobody. This is a distinct, named
# failure from an unclassified fn (too many classifications) and from a
# dead handler (a real handler, unreachable): it is the list itself
# claiming more than the scan can back up. Checked directly against what
# was actually matched this run, not against the static list length --
# the matched count existing at all does not make a stale entry visible;
# only checking for one by name does.
e4_named_stale=""
while IFS= read -r entry; do
  [ -z "$entry" ] && continue
  if ! printf '%b' "$e4_named_matched" | grep -Fxq "$entry"; then
    e4_named_stale="${e4_named_stale}${entry}\n"
  fi
done <<< "$NAMED_NON_HANDLERS"

if [ -n "$e4_named_stale" ]; then
  echo "❌  NAMED_NON_HANDLERS entr(y|ies) matching NO scanned fn this run (stale):" >&2
  printf '%b' "$e4_named_stale" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
  echo "" >&2
  echo "    The function behind this entry was deleted, renamed, or its signature" >&2
  echo "    changed to match a handler shape -- the entry is now a pre-authorised" >&2
  echo "    exemption for whatever gets written at that path next, reviewed by" >&2
  echo "    nobody. Remove it from NAMED_NON_HANDLERS above." >&2
  exit_code=1
fi

if [ -n "$e4_unclassified" ]; then
  echo "❌  pub async fn(s) under routes/ matching NEITHER known handler signature" \
       "shape NOR on NAMED_NON_HANDLERS:" >&2
  printf '%b' "$e4_unclassified" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
  echo "" >&2
  echo "    A new signature shape appeared and the gate was not taught about it --" >&2
  echo "    that must stop the build, not pass silently (RFC 159 §4.2). Either it is" >&2
  echo "    a handler (widen the (A)/(B) shape regexes in this script) or it is a" >&2
  echo "    helper (add it to NAMED_NON_HANDLERS above, with a reason)." >&2
  exit_code=1
fi

e4_dead=""
while IFS=$'\t' read -r file name; do
  [ -z "$file" ] && continue

  modpath=$(e4_modpath_of "$file")
  if [ -n "$modpath" ]; then natural="${modpath}::${name}"; else natural="$name"; fi

  live=0
  if grep -qF "routes::${natural}(" <<< "$LIB_RS_LIVE"; then
    live=1
  fi

  if [ "$live" -eq 0 ]; then
    leaf="$(basename "$file" .rs)"
    parent_file="$(dirname "$file").rs"
    parent_modpath=$(e4_modpath_of "$parent_file")
    while IFS= read -r alias; do
      [ -z "$alias" ] && continue
      if [ -n "$parent_modpath" ]; then flat="${parent_modpath}::${alias}"; else flat="$alias"; fi
      if grep -qF "routes::${flat}(" <<< "$LIB_RS_LIVE"; then
        live=1
        break
      fi
    done < <(e4_reexport_names "$leaf" "$name" "$parent_file")
  fi

  if [ "$live" -eq 0 ]; then
    rel="${file#"$REPO_ROOT"/}"
    key="routes::${natural}"
    exempted=$(printf '%s\n' "$E4_EXEMPT" | grep -Fx "$key" || true)
    if [ -z "$exempted" ]; then
      e4_dead="${e4_dead}${key} (${rel}, fn ${name})\n"
    fi
  fi
done < <(printf '%b' "$e4_handlers")

if [ -n "$e4_dead" ]; then
  echo "❌  Handler-shaped fn(s) with NO qualified path reachable from lib.rs" \
       "(dead -- registered nowhere, directly or via a one-level re-export):" >&2
  printf '%b' "$e4_dead" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
  echo "" >&2
  echo "    Either route it in crates/backend/src/lib.rs, delete it, or add a named," >&2
  echo "    dated, reasoned entry to E4_EXEMPT above -- not a silent pass." >&2
  exit_code=1
fi

e4_handler_count=$((e4_countA + e4_countB))

# RFC 159 cycle 3 (§4.3): the coverage line's own arithmetic must hold in
# every run, passing or failing -- not just happen to add up in the ones
# anyone checked by hand. A coverage figure that can misstate itself in
# precisely the run where it is load-gating (a failing one) is the same
# "reconcile a derived figure against its parts" defect this project
# already has a standing rule against, found here inside the gate that
# reports the figure. Asserted, not just printed: a mismatch is a hard
# failure in its own right, distinct from (and in addition to) an actual
# unclassified fn.
if [ "$e4_total" -ne "$((e4_handler_count + e4_named_count + e4_unclassified_count))" ]; then
  echo "❌  E4 coverage arithmetic does not close: ${e4_total} scanned !=" \
       "${e4_handler_count} handlers + ${e4_named_count} named +" \
       "${e4_unclassified_count} unclassified -- this is a bug in the check" \
       "itself, not a finding about routes/." >&2
  exit_code=1
fi

echo "ℹ️   E4 coverage: scanned ${e4_total} pub async fn under routes/ -- ${e4_handler_count}" \
     "classified as handlers (${e4_countA} RouteContext-shaped, ${e4_countB} Env-shaped)," \
     "${e4_named_count} named non-handlers, ${e4_unclassified_count} unclassified"

# ── E5 (RFC 162): every .json URL the frontend fetches must have a
#    route -- the inverse of E4 ──────────────────────────────────────
#
# E4 asks "is this handler reachable from lib.rs". This asks the other
# direction: a `.json` literal or `format!`-built URL in
# crates/frontend/src, with `{name}` segments treated as captures, must
# match a registered GET route, or the build fails. RFC 162 found two
# that didn't: `/admin/t/{slug}.json` and
# `/admin/tenancy/tenants/{tid}.json` each have the SAME segment count
# as a real, shorter route (`/admin/t/:slug`,
# `/admin/tenancy/tenants/:tid`) because the `{slug}`/`{tid}` placeholder
# is glued directly to the literal `.json` suffix with no `/` between
# them -- one path segment, not two. A segment-count-only check would
# call that an exact match; it is not, because nothing at that position
# is a bare placeholder. At runtime the capture swallows the whole
# segment including the literal suffix, and the real route the frontend
# meant to call (`.../detail.json`, one segment longer) never gets hit.
#
# A `format!`-built URL is not special-cased: `format!("/a/{x}/b.json")`
# is still the plain string literal `"/a/{x}/b.json"` as `format!`'s
# first argument, so the same literal-string grep that finds
# `"/a/fixed.json"` finds it too. What's special is the MATCHING, not
# the extraction.
#
# Candidate routes of the same segment length are tried fewest-captures
# first, not first-registered-first: the first E5 prototype took the
# first same-length match and reported
# `/admin/t/:slug/organizations/new.json` (itself a real, literally
# fully-registered route) as a THIRD defect, swallowed by the unrelated
# `/admin/t/:slug/organizations/:oid` -- a false positive, caught before
# it ever reached a report. Ranking by capture count means the more
# literal, already-correct route is tried first and matches cleanly.
#
# Three outcomes, not two:
#   EXACT              -- a same-length route whose every literal
#                          segment matches textually, and whose every
#                          capture segment the candidate ALSO spells as
#                          a bare `{name}` (nothing else in that
#                          segment). Pass.
#   CAPTURE-SWALLOWED   -- a same-length route whose every literal
#                          segment matches, but at least one of its
#                          capture positions is a candidate segment
#                          that is NOT a bare placeholder (a plain
#                          literal, or a placeholder glued to more
#                          text) -- this is the shape that makes it
#                          match a capture instead of 404ing. Fail.
#   UNRESOLVED          -- no live GET route of the same segment count
#                          has all its literal positions match at all.
#                          Fail.
e5_capture_count() {
  local path="$1"
  local -a segs
  read -ra segs <<< "$(path_segments "$path")"
  local n=0 seg
  for seg in "${segs[@]}"; do
    [[ "$seg" == :* ]] && n=$((n + 1))
  done
  echo "$n"
}

e5_is_bare_placeholder() {
  [[ "$1" =~ ^\{[A-Za-z_][A-Za-z0-9_]*\}$ ]]
}

# Resolve one candidate .json URL ($1) against the live GET routes
# ($2, newline-separated, `:name` captures). Echoes the chosen route.
# Returns 0 EXACT, 1 CAPTURE-SWALLOWED, 2 UNRESOLVED.
e5_resolve() {
  local candidate="$1" routes="$2"
  local -a cseg
  read -ra cseg <<< "$(path_segments "$candidate")"
  local clen=${#cseg[@]}

  local live ranked=""
  while IFS= read -r live; do
    [ -z "$live" ] && continue
    local -a lseg
    read -ra lseg <<< "$(path_segments "$live")"
    if [ "${#lseg[@]}" -eq "$clen" ]; then
      ranked="${ranked}$(e5_capture_count "$live")\t${live}\n"
    fi
  done <<< "$routes"
  [ -z "$ranked" ] && return 2

  local sorted
  sorted=$(printf '%b' "$ranked" | sort -n -t $'\t' -k1,1)

  while IFS=$'\t' read -r _ live; do
    [ -z "$live" ] && continue
    local -a lseg
    read -ra lseg <<< "$(path_segments "$live")"
    local i all_literal_match=1
    for ((i = 0; i < clen; i++)); do
      if [[ "${lseg[$i]}" != :* ]] && [ "${lseg[$i]}" != "${cseg[$i]}" ]; then
        all_literal_match=0; break
      fi
    done
    if [ "$all_literal_match" -eq 1 ]; then
      local exact=1
      for ((i = 0; i < clen; i++)); do
        if [[ "${lseg[$i]}" == :* ]] && ! e5_is_bare_placeholder "${cseg[$i]}"; then
          exact=0; break
        fi
      done
      echo "$live"
      if [ "$exact" -eq 1 ]; then return 0; else return 1; fi
    fi
  done <<< "$sorted"

  return 2
}

e5_candidates=$(
  grep -rhoE '"[^"]*\.json"' "$REPO_ROOT/crates/frontend/src" --include='*.rs' |
  grep -v '/tests\?\.rs:\|/tests/' |
  sed -E 's/^"(.*)"$/\1/' |
  sort -u
)

e5_get_routes=$(
  printf '%s\n' "$LIB_RS_LIVE" |
  grep -E '\.get_async\s*\("' |
  sed -E 's/.*\.get_async\s*\("([^"]+)".*/\1/' |
  sort -u
)

e5_total=0
e5_exact=0
e5_capture=0
e5_unresolved=0
e5_capture_report=""
e5_unresolved_report=""

while IFS= read -r candidate; do
  [ -z "$candidate" ] && continue
  e5_total=$((e5_total + 1))
  matched=$(e5_resolve "$candidate" "$e5_get_routes") && status=0 || status=$?
  case "$status" in
    0) e5_exact=$((e5_exact + 1)) ;;
    1)
      e5_capture=$((e5_capture + 1))
      e5_capture_report="${e5_capture_report}${candidate} -- swallowed by ${matched}\n"
      ;;
    2)
      e5_unresolved=$((e5_unresolved + 1))
      e5_unresolved_report="${e5_unresolved_report}${candidate} -- no live GET route of the same segment count\n"
      ;;
  esac
done <<< "$e5_candidates"

if [ "$e5_total" -ne "$((e5_exact + e5_capture + e5_unresolved))" ]; then
  echo "❌  E5 coverage arithmetic does not close: ${e5_total} scanned !=" \
       "${e5_exact} exact + ${e5_capture} capture-swallowed + ${e5_unresolved}" \
       "unresolved -- this is a bug in the check itself, not a finding" \
       "about crates/frontend/src." >&2
  exit_code=1
fi

if [ -n "$e5_capture_report" ]; then
  echo "❌  .json URL(s) the frontend fetches that match no route EXACTLY, but" \
       "are swallowed by a shorter route's capture segment (match at runtime," \
       "with the wrong handler, not a 404):" >&2
  printf '%b' "$e5_capture_report" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
  echo "" >&2
  echo "    Point the fetch at the route that actually serves this data." >&2
  exit_code=1
fi

if [ -n "$e5_unresolved_report" ]; then
  echo "❌  .json URL(s) the frontend fetches with NO live GET route of the same" \
       "segment count at all:" >&2
  printf '%b' "$e5_unresolved_report" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
  echo "" >&2
  echo "    Register the route in crates/backend/src/lib.rs, or fix the fetch URL." >&2
  exit_code=1
fi

echo "ℹ️   E5 coverage: scanned ${e5_total} .json URL(s) fetched by the frontend --" \
     "${e5_exact} resolved exactly, ${e5_capture} resolved via capture (defect)," \
     "${e5_unresolved} unresolved"

# ── E6 (RFC 152 half B, generalised by half C): every mutating
#    route-contracts.md row whose CSRF cell makes a claim -- `required`,
#    `required (<mechanism>)`, or `N/A (bearer)` -- must resolve through
#    its registration in lib.rs to a handler whose body backs that exact
#    claim. Half A (v0.86.3) made the table honest for 34 cells
#    (`N/A (SameSite=Strict)`, truthfully, because nothing else was
#    there); half B stage 1 added the real control and flipped those
#    cells to `required`; half C found the identical defect on the
#    operator-console surface (RFC 152 §Half C) AND its mirror image --
#    `N/A (bearer)` cells claiming NO cookie-derived credential works,
#    on handlers that accept one anyway. A flipped cell with nothing
#    behind it is the same lie half A fixed, just inverted; an `N/A`
#    cell that is not actually true is the SAME lie pointed the other
#    way -- a claim that a weaker check suffices when it does not. This
#    re-derives every one of those three claims from the registration,
#    never from the table's own say-so.
#
# Scoped to POST/PUT/DELETE rows only, not GET: CSRF and credential-
# acceptance are concerns about state-changing requests. (A handful of
# GET rows in the table carry a stray `required` in the CSRF column --
# a pre-existing labelling slip, not this cycle's, see the half C
# report -- which is exactly why this scoping is stated and not
# incidental: including GET would make E6 fail on that slip, a finding
# unrelated to what E6 exists to check.)
COMMON_RS="$REPO_ROOT/crates/backend/src/routes/admin/tenancy_console/forms/common.rs"

# `required (<mechanism>)` cells name a control other than the
# double-submit `csrf::verify`/`verify_csrf` pair. Named, dated table --
# same discipline as NAMED_NON_HANDLERS/E4_EXEMPT above -- of the
# mechanism text (as it appears in the cell, inside the parens) to a
# substring E6 requires somewhere in the resolved handler's body.
# Two entries as of RFC 152 half C (2026-10-31): `/logout`'s pre-existing
# `required (Origin check)`, and the two `config/log_level/{preview,apply}`
# routes' `required (preview-token binding)`, found by half C's own
# measurement to carry a *different* real control
# (`cesauth_core::admin::preview::verify_preview_token`) that the
# original 36-row population scan did not know to look for.
#
# Two kinds of entry: an ERE pattern to search the resolved body for
# (grep -E), or the sentinel `STANDARD` meaning "this parenthetical is
# scope commentary on the ordinary double-submit check, not a different
# mechanism" -- `required (form path)` on `/magic-link/verify` is
# exactly that: the handler genuinely calls `csrf::verify(`, the
# "(form path)" clause says WHEN the check applies (not on the JSON
# path), and treating it as an unknown mechanism would be a false
# failure on a row that is already correct. Empty means truly unknown:
# add a case, or the row is misdocumented.
e6_mechanism_check() {
  case "$1" in
    "Origin check")          echo "check_origin_or_referer\\(" ;;
    "preview-token binding") echo "mint_preview_token\\(|verify_preview_token\\(" ;;
    "form path")             echo "STANDARD" ;;
    *)                       echo "" ;;
  esac
}

# `N/A (bearer)`'s default check requires the SHARED header-only
# resolver (resolve_from_request_header_only/resolve_or_respond_header_only).
# RFC 152 half C cycle 2 found one route genuinely header-only by a
# DIFFERENT, independent mechanism: `routes::oidc::userinfo_handler`
# (OIDC Core §5.3's UserInfo endpoint) reads only the `Authorization`
# header via its own `extract_bearer`, predating `admin::auth` entirely
# and unrelated to the admin cookie this whole RFC is about -- not
# broken, just not the shared helper. Named here rather than folded
# into either E6_BEARER_LEGACY_EXEMPT (that list means "known not to
# back its claim, pending its own fix") or a blind regex widening (that
# would also accept a FUTURE route's own one-off "looks bearer-ish"
# helper that never actually checked for a cookie). Keyed by the
# qualified handler name, since `extract_bearer` is this one file's own
# name, not a generically reusable marker the way the mechanism-check
# table's functions are.
e6_bearer_alt_check() {
  case "$1" in
    "routes::oidc::userinfo_handler") echo "extract_bearer\\(" ;;
    *)                                echo "" ;;
  esac
}

# **RFC 152 half C's own finding, exempted rather than fixed here.**
# `N/A (bearer)` on these 18 rows is NOT true today: `legacy.rs`'s two
# handlers and every `/api/v1/*` route (all 16, through the single
# `api_v1::auth::require` they share) resolve via `auth::resolve_or_respond`
# -- header OR the `__Host-cesauth_admin` cookie -- not the header-only
# resolver the cell's claim requires. Measured while generalising E6
# (2026-10-31); not fixed here. Flipping 17 routes from accepting a
# cookie to rejecting one is a caller-obligation change of its own size
# and was never asked for by this cycle's handoff, which scoped itself to
# 7 operator-console routes. Reported in the half C report as a finding
# for its own sizing decision, the same way half C itself was found
# inside stage 2's review rather than folded into stage 2's fix. Named,
# dated, and must shrink as each is actually fixed -- an entry that
# stops matching (because the route was fixed, renamed, or removed)
# is caught by the same "scanned-but-never-matched" discipline as
# NAMED_NON_HANDLERS's own stale-entry check below, not silently kept.
E6_BEARER_LEGACY_EXEMPT="POST /admin/users
DELETE /admin/sessions/:id
POST /api/v1/tenants
POST /api/v1/tenants/:tid/status
POST /api/v1/tenants/:tid/organizations
POST /api/v1/tenants/:tid/organizations/:oid/status
POST /api/v1/tenants/:tid/groups
POST /api/v1/tenants/:tid/memberships
POST /api/v1/organizations/:oid/memberships
POST /api/v1/groups/:gid/memberships
POST /api/v1/role_assignments
POST /api/v1/tenants/:tid/subscription/plan
POST /api/v1/tenants/:tid/subscription/status
DELETE /api/v1/tenants/:tid/memberships/:uid
DELETE /api/v1/organizations/:oid/memberships/:uid
DELETE /api/v1/groups/:gid
DELETE /api/v1/groups/:gid/memberships/:uid
DELETE /api/v1/role_assignments/:id"

# Echoes the `routes::a::b::fn` call inside the `.{method}_async("$2", ...)`
# registration for method $1 (lowercase). Half B's version of this
# required the literal path AND the handler call on the SAME line --
# true for both admin surfaces (confirmed before writing it) but false
# for 10+ rows elsewhere in lib.rs, registered as multi-line closures
# (`.post_async("/webauthn/register/start", |req, ctx| async move {`
# on one line, `routes::webauthn::register_start(req, ctx).await` on the
# next) -- found while generalising E6 to the whole table, exactly the
# blind spot half C's own handoff predicted. E4 solves a DIFFERENT
# question (is this handler reachable from ANYWHERE in lib.rs, via a
# whole-file substring search) and its answer carries no route identity,
# so it cannot name which handler serves a given path; reusing it
# directly is not available here. Rather than writing a third,
# independently-regexed extractor over lib.rs (RFC 163's concern), this
# is a bounded WIDENING of E6's own existing literal-substring technique
# -- same `routes::[A-Za-z0-9_:]+\(` pattern it always matched on, same
# shared `LIB_RS_LIVE`, now searched across the window from the matching
# registration line up to (not including) the next `.{get,post,put,
# delete}_async(` line, instead of requiring both on one line.
e6_qualified_handler_for() {
  local method="$1" path="$2"
  awk -v n1=".${method}_async(" -v n2="\"${path}\"" '
    BEGIN { collecting = 0 }
    function emit() {
      if (match($0, /routes::[A-Za-z0-9_:]+\(/)) {
        s = substr($0, RSTART, RLENGTH)
        sub(/\($/, "", s)
        print s
        return 1
      }
      return 0
    }
    {
      if (collecting) {
        if (index($0, ".get_async(") > 0 || index($0, ".post_async(") > 0 ||
            index($0, ".put_async(") > 0 || index($0, ".delete_async(") > 0) { exit }
        if (emit()) exit
        next
      }
      if (index($0, n1) > 0 && index($0, n2) > 0) {
        if (emit()) exit
        collecting = 1
      }
    }
  ' <<< "$LIB_RS_LIVE"
}

# routes::a::b::fn -> crates/backend/src/routes/a/b.rs. One level only --
# every one of these 36 registrations names its handler's natural
# qualified path directly (confirmed by inspection), so there is no
# re-export chain to chase here the way E4 chases one for dead handlers.
#
# RFC 152 half C's generalisation found the one case this assumption
# does not hold: `routes::magic_link::verify` is `magic_link.rs`'s own
# `pub use verify::verify;` -- a same-name, one-level re-export (E4's
# own "Shape 2", `mod.rs`-per-handler, the doc comment at the top of
# `magic_link.rs` names the convention: "One submodule per handler").
# The direct guess (routes/magic_link.rs) exists but does not define
# `fn verify` at its top level; the fallback
# (routes/magic_link/verify.rs, same fn name) does. Tries the direct
# path first -- true for every one of the two admin surfaces this
# started on -- and only falls back to the one-level submodule guess
# when the direct file does not actually define the function, rather
# than chasing a general re-export graph (E4's own job, for a
# different question).
#
# Echoes `file<TAB>fn_name` -- the fn name can differ from the one in
# `$1` when the registration names a RENAMING re-export (E4's own
# "Shape 2" in the other direction): `routes::oidc::userinfo_handler`
# is `oidc.rs`'s `pub use userinfo::handler as userinfo_handler;`,
# found while fixing cycle 2's `/userinfo` row -- the real function is
# `handler`, in `oidc/userinfo.rs`, not a function literally named
# `userinfo_handler` anywhere. Same one-level discipline as the
# same-name submodule fallback above it (and as E4's own
# `e4_reexport_names`, chased here in the opposite direction: given the
# alias, find what it is an alias FOR).
e6_file_for_qualified() {
  local q="${1#routes::}"
  local modpath="${q%::*}"
  local fn="${q##*::}"
  local direct="$REPO_ROOT/crates/backend/src/routes/${modpath//::/\/}.rs"
  if [ -f "$direct" ] && grep -qE "fn ${fn}[<(]" "$direct"; then
    printf '%s\t%s\n' "$direct" "$fn"
    return
  fi
  local submodule="$REPO_ROOT/crates/backend/src/routes/${modpath//::/\/}/${fn}.rs"
  if [ -f "$submodule" ] && grep -qE "fn ${fn}[<(]" "$submodule"; then
    printf '%s\t%s\n' "$submodule" "$fn"
    return
  fi
  if [ -f "$direct" ]; then
    local reexport leaf real
    reexport=$(grep -oE "pub use [A-Za-z0-9_]+::[A-Za-z0-9_]+ as ${fn};" "$direct" | head -1)
    if [ -n "$reexport" ]; then
      leaf=$(echo "$reexport" | sed -E 's/pub use ([A-Za-z0-9_]+)::.*/\1/')
      real=$(echo "$reexport" | sed -E 's/.*::([A-Za-z0-9_]+) as .*/\1/')
      local renamed="$REPO_ROOT/crates/backend/src/routes/${modpath//::/\/}/${leaf}.rs"
      if [ -f "$renamed" ] && grep -qE "fn ${real}[<(]" "$renamed"; then
        printf '%s\t%s\n' "$renamed" "$real"
        return
      fi
    fi
  fi
  printf '%s\t%s\n' "$direct" "$fn"
}

# The CSRF form-field name the resolved HANDLER FUNCTION checks --
# scoped to that one function's body, not the whole file: deletions.rs
# has two field names in one file (`csrf` in `request_self_form`/
# `cancel_self`, `csrf_token` in `admin_cancel`/`admin_execute`), so a
# whole-file grep would silently pick whichever occurs first in the file
# regardless of which function this row actually resolved to.
#
# RFC 152 half B stage 1's review (2026-10-31) flagged the first version
# of this: it bounded the slice by the next top-level `pub async fn` (or
# EOF), which swallows a non-`pub` `async fn` declared after a handler
# into that handler's own slice -- no false pass existed in that stage's
# population (the reviewer re-derived all 34 rows by brace-counting and
# got the same answer, row for row), but a future handler whose own
# `verify_csrf` call got removed could hide behind a still-verifying
# helper below it. Hardened here to stop at the function's own matching
# closing brace, by depth, rather than at the next function signature --
# correct regardless of what's declared after it, `pub` or not.
e6_fn_body() {
  local file="$1" fn="$2"
  awk -v fn="$fn" '
    function count(ch, s,    n, i) {
      n = 0
      for (i = 1; i <= length(s); i++) if (substr(s, i, 1) == ch) n++
      return n
    }
    BEGIN { in_fn = 0; depth = 0; opened = 0 }
    in_fn == 0 {
      if ($0 ~ ("fn " fn "[<(]")) {
        in_fn = 1
        # The signature line itself may already carry the opening
        # (and, for a one-liner, the closing) brace of this function --
        # count it here, even though the line is not printed, so depth
        # starts from what this line actually opened, not from zero.
        o = count("{", $0)
        if (o > 0) opened = 1
        depth += o - count("}", $0)
        if (opened && depth <= 0) { exit }
      }
      next
    }
    in_fn {
      o = count("{", $0)
      if (o > 0) opened = 1
      print
      depth += o - count("}", $0)
      if (opened && depth <= 0) { exit }
    }
  ' "$file"
}

# Generalising E6 past the tenancy-console/tenant-admin surfaces hit
# the `me/totp/*` family's own established pattern (RFC 150): the
# registered handler extracts the request-shaped values and calls a
# sibling `decide_<name>_post` function -- itself plain, pure, and
# independently host-tested -- which is where `csrf::verify(` actually
# appears as literal text. The handler's own body never contains it,
# so e6_fn_body alone reports a false "unresolved" for all four totp
# routes (confirmed: all four follow this shape, same file, same
# `let decision = decide_..._post(` call). One bounded hop -- look for
# a `decide_[A-Za-z0-9_]+(` call in the resolved handler's body, and if
# found, OR in that function's own body from the SAME file (this
# pattern is always file-local) -- same "modest widening of an
# existing check" discipline as e6_qualified_handler_for's own
# multi-line extension above, not a new traversal strategy.
e6_resolve_body() {
  local file="$1" fn="$2" body decide_fn
  body=$(e6_fn_body "$file" "$fn")
  decide_fn=$(printf '%s\n' "$body" | grep -oE 'decide_[A-Za-z0-9_]+\(' | head -1 | sed -E 's/\($//')
  if [ -n "$decide_fn" ]; then
    body="${body}
$(e6_fn_body "$file" "$decide_fn")"
  fi
  echo "$body"
}

e6_field_name_for() {
  local file="$1" fn="$2" name body
  body=$(e6_fn_body "$file" "$fn")
  name=$(printf '%s\n' "$body" | grep -oE '\.get\("csrf[A-Za-z0-9_]*"\)' | head -1 | sed -E 's/.*"(.*)".*/\1/')
  if [ -z "$name" ] && printf '%s\n' "$body" | grep -q 'verify_csrf('; then
    name=$(grep -oE '\.get\("csrf[A-Za-z0-9_]*"\)' "$COMMON_RS" | head -1 | sed -E 's/.*"(.*)".*/\1/')
  fi
  echo "$name"
}

# RFC 152 half C cycle 2: the classifier below used to be a `case`
# with three arms and a silent `*) continue` -- 19 of 94 mutating rows
# fell through it without trace, including `POST /userinfo`'s
# `N/A (Bearer)` (capital B, a bearer claim E6 should have checked and
# did not) and one row that was a bare `N/A` with no reason recorded at
# all (`POST /accept-invite` -- see below). E4 closes its own census
# with "0 unclassified" and fails loudly if that is untrue; this list
# gives E6 the same property: every cell value that legitimately
# carries no check is named here, with why, and the stale-entry check
# a few lines down means a value that stops matching is caught the same
# way a fixed/renamed/removed row already is for
# E6_BEARER_LEGACY_EXEMPT above.
#
# `POST /accept-invite` was the one bare `N/A` (RFC 152 half C cycle 2
# deliberately did not say which, or what it meant, wanting a real
# reading rather than a confirmed guess). Read `accept_submit`
# (routes/invitations.rs): it authenticates nothing -- no
# `auth::resolve_or_respond`, no cookie read at all -- and RFC 153 §3's
# own design is that nothing is accepted or written on this POST ("the
# invitation stays pending"); completion happens later, elsewhere, once
# a real magic-link verification succeeds. CSRF's danger model needs an
# ambient credential (a cookie) the request rides on; there is none
# here, and no state changes either way, so there is nothing a forged
# cross-site POST could do that a direct, uncredentialed POST could not
# already do. Genuinely `N/A`, not a missing check.
#
# One more thing worth recording rather than fixing: `accept_page`'s
# rendered form DOES carry a hidden `csrf_token` field (the name predates
# the `csrf` convention the rest of this codebase settled on), and
# `accept_submit` never reads a form field by that name -- `grep -n
# '"csrf_token"' routes/invitations.rs` shows it only in the render side
# and in that file's own render-level tests. Dead weight, not a defect:
# with no credential to protect, an unchecked decorative field changes
# nothing. Left alone -- removing it is a template cleanup, not a CSRF
# fix, and this cycle is a gate change only.
E6_DECLARED_NO_CHECK="N/A (JSON)
N/A (CORS preflight)
N/A (RFC 7009)
N/A (Authorization-only)
N/A (dev only)
N/A (SameSite=Strict)
N/A (no ambient credential, no state change)"

e6_rows=$(awk -F'|' '
  /^\|/ {
    method = $2; gsub(/^[ \t]+|[ \t]+$/, "", method)
    if (method != "POST" && method != "PUT" && method != "DELETE") next
    path = $3; gsub(/^[ \t]+|[ \t]+$/, "", path); gsub(/`/, "", path)
    csrf = $9; gsub(/^[ \t]+|[ \t]+$/, "", csrf)
    print method "\t" path "\t" csrf
  }
' "$CONTRACTS_MD")

e6_scanned=0        # every mutating row, regardless of CSRF cell
e6_claims=0         # rows whose cell is one of the three E6 checks
e6_resolved=0
e6_unresolved=0
e6_exempted=0
e6_declared=0        # cells on E6_DECLARED_NO_CHECK -- legitimately no check
e6_unclassified=0    # cells matching neither a claim nor a declared value
e6_unresolved_report=""
e6_fields=""
e6_exempt_matched=""
e6_declared_matched=""

while IFS=$'\t' read -r method path csrf_cell; do
  [ -z "$method" ] && continue
  e6_scanned=$((e6_scanned + 1))

  mech=""
  case "$csrf_cell" in
    "required") kind="plain" ;;
    "required ("*")")
      kind="mechanism"
      mech="${csrf_cell#required \(}"
      mech="${mech%\)}"
      ;;
    "N/A (bearer)") kind="bearer" ;;
    *)
      if printf '%s\n' "$E6_DECLARED_NO_CHECK" | grep -Fxq "$csrf_cell"; then
        e6_declared=$((e6_declared + 1))
        e6_declared_matched="${e6_declared_matched}${csrf_cell}\n"
        continue
      fi
      e6_unclassified=$((e6_unclassified + 1))
      echo "❌  route-contracts.md row with an unrecognised CSRF cell:" >&2
      echo "    ${method} ${path} -- \"${csrf_cell}\"" >&2
      echo "" >&2
      echo "    Either this is a claim E6 should check (add a case above), or it" >&2
      echo "    is a legitimate no-check value (add it to E6_DECLARED_NO_CHECK" >&2
      echo "    with its reason) -- a cell E6 does not recognise must fail the" >&2
      echo "    build, not pass silently (RFC 159 §4.5's rule, applied here)." >&2
      exit_code=1
      continue
      ;;
  esac
  e6_claims=$((e6_claims + 1))

  lc_method=$(printf '%s' "$method" | tr '[:upper:]' '[:lower:]')
  qualified=$(e6_qualified_handler_for "$lc_method" "$path")
  file="" fn_name="" body=""
  if [ -n "$qualified" ]; then
    IFS=$'\t' read -r file fn_name <<< "$(e6_file_for_qualified "$qualified")"
    [ -f "$file" ] && body=$(e6_resolve_body "$file" "$fn_name")
  fi

  if [ "$kind" = "bearer" ]; then
    exempt_key="${method} ${path}"
    if printf '%s\n' "$E6_BEARER_LEGACY_EXEMPT" | grep -Fxq "$exempt_key"; then
      e6_exempted=$((e6_exempted + 1))
      e6_exempt_matched="${e6_exempt_matched}${exempt_key}\n"
      continue
    fi
  fi

  ok=0
  reason=""
  if [ -z "$qualified" ] || [ ! -f "$file" ]; then
    reason="no ${method} registration resolved to a handler file"
  else
    case "$kind" in
      plain)
        printf '%s\n' "$body" | grep -qE 'csrf::verify\(|verify_csrf\(' && ok=1 || reason="does not call csrf::verify"
        ;;
      mechanism)
        needle=$(e6_mechanism_check "$mech")
        if [ -z "$needle" ]; then
          reason="unknown mechanism name \"${mech}\" -- add it to e6_mechanism_check"
        elif [ "$needle" = "STANDARD" ]; then
          printf '%s\n' "$body" | grep -qE 'csrf::verify\(|verify_csrf\(' && ok=1 || reason="does not call csrf::verify"
        elif printf '%s\n' "$body" | grep -qE "$needle"; then
          ok=1
        else
          reason="does not call the control named \"${mech}\""
        fi
        ;;
      bearer)
        bearer_pattern='resolve_from_request_header_only\(|resolve_or_respond_header_only\('
        bearer_alt=$(e6_bearer_alt_check "$qualified")
        [ -n "$bearer_alt" ] && bearer_pattern="${bearer_pattern}|${bearer_alt}"
        printf '%s\n' "$body" | grep -qE "$bearer_pattern" \
          && ok=1 || reason="resolves via a cookie-accepting path, not the header-only resolver (or a named alternate) its N/A (bearer) cell claims"
        ;;
    esac
  fi

  if [ "$ok" -eq 1 ]; then
    e6_resolved=$((e6_resolved + 1))
    if [ "$kind" = "plain" ]; then
      field=$(e6_field_name_for "$file" "$fn_name")
      [ -n "$field" ] && e6_fields="${e6_fields}${field}\n"
    fi
  else
    e6_unresolved=$((e6_unresolved + 1))
    e6_unresolved_report="${e6_unresolved_report}${method} ${path} -- ${qualified:-?} ${reason}\n"
  fi
done <<< "$e6_rows"

if [ "$e6_claims" -ne "$((e6_resolved + e6_unresolved + e6_exempted))" ]; then
  echo "❌  E6 coverage arithmetic does not close: ${e6_claims} claims !=" \
       "${e6_resolved} resolved + ${e6_unresolved} unresolved + ${e6_exempted}" \
       "exempted -- this is a bug in the check itself, not a finding about the" \
       "backend." >&2
  exit_code=1
fi

if [ "$e6_scanned" -ne "$((e6_claims + e6_declared + e6_unclassified))" ]; then
  echo "❌  E6 coverage arithmetic does not close: ${e6_scanned} scanned !=" \
       "${e6_claims} claims + ${e6_declared} declared-no-check + ${e6_unclassified}" \
       "unclassified -- this is a bug in the check itself, not a finding about" \
       "the backend." >&2
  exit_code=1
fi

if [ "$e6_claims" -eq 0 ]; then
  echo "❌  E6 found ZERO mutating rows making a CSRF/bearer claim it checks --" \
       "the check would pass vacuously." >&2
  exit_code=1
fi

if [ -n "$e6_unresolved_report" ]; then
  echo "❌  route-contracts.md row(s) whose CSRF cell's claim the resolved handler" \
       "does not back:" >&2
  printf '%b' "$e6_unresolved_report" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
  echo "" >&2
  echo "    Either make the handler back the claim, or the cell is claiming a" >&2
  echo "    control the code does not have -- correct the cell if that's actually" >&2
  echo "    true." >&2
  exit_code=1
fi

# Stale-exemption check -- same discipline as NAMED_NON_HANDLERS's own,
# applied to E6_BEARER_LEGACY_EXEMPT: an entry that matched no row this
# run (the route was fixed, renamed, or removed) is a pre-authorised
# exemption nobody is reviewing any more, sitting over whatever lands at
# that method+path next.
e6_exempt_stale=""
while IFS= read -r entry; do
  [ -z "$entry" ] && continue
  if ! printf '%b' "$e6_exempt_matched" | grep -Fxq "$entry"; then
    e6_exempt_stale="${e6_exempt_stale}${entry}\n"
  fi
done <<< "$E6_BEARER_LEGACY_EXEMPT"

if [ -n "$e6_exempt_stale" ]; then
  echo "❌  E6_BEARER_LEGACY_EXEMPT entr(y|ies) matching NO scanned row this run" \
       "(stale):" >&2
  printf '%b' "$e6_exempt_stale" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
  echo "" >&2
  echo "    The route behind this entry was fixed, renamed, or removed -- remove" >&2
  echo "    it from E6_BEARER_LEGACY_EXEMPT above, rather than leaving a" >&2
  echo "    pre-authorised exemption nobody is reviewing." >&2
  exit_code=1
fi

# Same stale-entry discipline, applied to E6_DECLARED_NO_CHECK: a
# declared value matching no row this run is a declaration nobody is
# reviewing any more either.
e6_declared_stale=""
while IFS= read -r entry; do
  [ -z "$entry" ] && continue
  if ! printf '%b' "$e6_declared_matched" | grep -Fxq "$entry"; then
    e6_declared_stale="${e6_declared_stale}${entry}\n"
  fi
done <<< "$E6_DECLARED_NO_CHECK"

if [ -n "$e6_declared_stale" ]; then
  echo "❌  E6_DECLARED_NO_CHECK entr(y|ies) matching NO scanned row this run" \
       "(stale):" >&2
  printf '%b' "$e6_declared_stale" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
  echo "" >&2
  echo "    The row carrying this cell value was fixed, renamed, or removed --" >&2
  echo "    remove it from E6_DECLARED_NO_CHECK above." >&2
  exit_code=1
fi

e6_distinct_fields=$(printf '%b' "$e6_fields" | grep -v '^$' | sort -u)
e6_distinct_field_count=$(printf '%s\n' "$e6_distinct_fields" | grep -c . || true)

echo "ℹ️   E6 coverage: scanned ${e6_scanned} mutating row(s) repo-wide -- ${e6_claims}" \
     "make a CSRF/bearer claim E6 checks (${e6_resolved} resolved, ${e6_unresolved}" \
     "unresolved, ${e6_exempted} exempted -- RFC 152 half C finding, not this" \
     "cycle's fix), ${e6_declared} declared as legitimately uncheckable," \
     "${e6_unclassified} unclassified. Distinct CSRF field name(s) in use:" \
     "${e6_distinct_field_count} ($(printf '%s' "$e6_distinct_fields" | tr '\n' ',' | sed 's/,$//'))"

if [ "$exit_code" -eq 0 ]; then
  echo "✅  All ${registered_count} routes are documented in route-contracts.md, and every" \
       "handler-shaped fn in routes/ is reachable from lib.rs"
fi

exit "$exit_code"
