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
#
# RFC 182: with `pipefail` (below), piping a large variable into a reader
# that can exit before reading all of it -- `grep -q`/`grep -*q`, `head`,
# or an `awk` script with its own `exit` -- risks SIGPIPE on the writer.
# Under load, the writer can be scheduled late enough to still be writing
# when the reader is done, and pipefail then reports the pipeline as
# failed (128+13=141) even though the reader's own match succeeded: a
# real match silently reported as a miss (or, for a bare, unguarded
# `var=$(... | head ...)`, the whole script aborting on a false
# failure). Fixed throughout this file by feeding such readers a
# here-string (`<<<`) instead of a pipe, which has no writer process to
# kill, or by appending `|| true` to a bare assignment whose pipe ends
# in `head`/an exiting `awk`. New checks in this file should follow the
# same rule rather than reintroduce a `cmd | grep -q`/`| head`/
# `| awk '...{exit}'` pipe.

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

# RFC 168 patch-method-gap cycle: the HTTP methods a route registration
# can use, as one constant every site below reads, rather than the
# literal `(get|post|put|delete)`/`(GET|POST|PUT|DELETE)`/`!= "POST" &&
# != "PUT" && != "DELETE"` this file had copied **nine** separate times
# (the dispatching handoff found and named six; sweeping for every
# shape of the same vocabulary -- lowercase regex, uppercase regex, and
# a chained `!=` -- found three more it did not). All nine existed
# because the vocabulary was never shared in the first place -- `patch`
# was added to Worker routing with `.patch_async(` and every one of
# these nine copies independently failed to notice, so two live PATCH
# routes were invisible to every check in this file that starts from a
# method keyword. Adding the next method this project registers with
# needs exactly one edit, here (`ROUTE_METHODS`, and its derived
# `ROUTE_METHODS_UPPER`/`ROUTE_METHODS_MUTATING_UPPER` below).
ROUTE_METHODS='get|post|put|delete|patch'

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
# Pattern: .(get|post|put|delete|patch)_async("/path/...",
# We normalise to uppercase METHOD + PATH, strip trailing spaces.

registered=$(
  printf '%s\n' "$LIB_RS_LIVE" |
  grep -E "\\.(${ROUTE_METHODS})_async\\s*\\(\"" |
  sed -E "s/.*\\.(${ROUTE_METHODS})_async\\s*\\(\"([^\"]+)\".*/\\U\\1\\E \\2/" |
  sort -u
)

# ── extract documented routes from contracts table ────────────────────
# Pattern: | GET | /path | ... (markdown table rows in any section)

ROUTE_METHODS_UPPER=$(tr '[:lower:]' '[:upper:]' <<< "$ROUTE_METHODS")

documented=$(
  grep -E "^\\|\\s*(${ROUTE_METHODS_UPPER})\\s+\\|" "$CONTRACTS_MD" |
  sed -E "s/^\\|\\s*(${ROUTE_METHODS_UPPER})\\s+\\|\\s*\`([^\`]+)\`.*/\\1 \\2/" |
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
  awk -F'|' -v methods="$ROUTE_METHODS_UPPER" '
    BEGIN { re_row = "^\\|[[:space:]]*(" methods ")[[:space:]]*\\|" }
    $0 ~ re_row {
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

# ── RFC 165 §3: one shared staleness check for every exemption list in
#    this file ─────────────────────────────────────────────────────────
#
# RFC 159 §4.5 established the rule for NAMED_NON_HANDLERS: an entry that
# matched nothing this run is a pre-authorised exemption for whatever is
# written at that key next, reviewed by nobody -- the same failure mode
# a stale `#[allow]` or a stale test skip is, just further from where
# anyone looks. Four sibling lists in this file (E3_EXEMPT,
# GATE_42_EXEMPT, NONCE_EXEMPT, E4_EXEMPT) carried the same risk with no
# check at all, verified before writing this (`grep -n stale` beside any
# of the four: zero hits). One helper, used by all five rather than five
# near-identical inline blocks -- RFC 165 §3's own point 1.
#
# $1: the list's full content, one entry per line.
# $2: every entry actually matched this run (i.e. every value the
#     caller's loop passed to `grep -Fx` against the list and got a hit),
#     also one per line, duplicates allowed -- the comparison below only
#     cares whether each declared entry appears at least once.
# Echoes each entry in $1 that does not appear in $2, one per line.
exemption_stale_entries() {
  local list="$1" matched="$2"
  while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    if ! grep -Fxq "$entry" <<< "$matched"; then
      echo "$entry"
    fi
  done <<< "$list"
}

# Reports stale entries (if any) for one exemption list, in the message
# shape RFC 159 §4.5 settled on. $1 list name (for the message), $2 list
# content, $3 matched-this-run content. Sets exit_code=1 on any finding;
# the caller's own $exit_code must already be in scope (it is, globally,
# throughout this script).
report_exemption_staleness() {
  local name="$1" list="$2" matched="$3"
  local stale
  stale=$(exemption_stale_entries "$list" "$matched")
  if [ -n "$stale" ]; then
    echo "❌  ${name} entr(y|ies) matching NO scanned item this run (stale):" >&2
    printf '%s\n' "$stale" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
    echo "" >&2
    echo "    The item behind this entry was fixed, renamed, or removed -- remove" >&2
    echo "    it from ${name} above, rather than leaving a pre-authorised" >&2
    echo "    exemption nobody is reviewing." >&2
    exit_code=1
  fi
}

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
  awk -v methods="$ROUTE_METHODS" '
    BEGIN { chunk=""; method=""; path=""; started=0; re_start = "\\.(" methods ")_async[[:space:]]*\\(" }
    $0 ~ re_start {
      if (started) print method "\t" path "\t" chunk
      started=1
      chunk=$0
      if (match($0, ("\\.(" methods ")_async"))) {
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
  awk -F'|' -v methods="$ROUTE_METHODS_UPPER" '
    BEGIN { re_row = "^\\|[[:space:]]*(" methods ")[[:space:]]*\\|" }
    $0 ~ re_row {
      method = $2; gsub(/^[ \t]+|[ \t]+$/, "", method)
      path   = $3; gsub(/^[ \t]+`|`[ \t]*$/, "", path)
      rendering = $7; gsub(/^[ \t]+|[ \t]+$/, "", rendering)
      if (rendering == "server") print method" "path
    }
  ' "$CONTRACTS_MD"
)

e3_scanned=0
e3_violations=""
e3_unresolved=""
e3_exempted_count=0
e3_matched=""
while IFS= read -r route; do
  [ -z "$route" ] && continue
  e3_scanned=$((e3_scanned + 1))
  m="${route%% *}"
  p="${route#* }"
  handler=$(awk -F'\t' -v m="$m" -v p="$p" '$1==m && $2==p {print $3; exit}' <<< "$route_handlers") || true
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
      else
        e3_exempted_count=$((e3_exempted_count + 1))
        e3_matched="${e3_matched}${exempted}
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

report_exemption_staleness "E3_EXEMPT" "$E3_EXEMPT" "$e3_matched"

echo "ℹ️   E3 coverage: scanned ${e3_scanned} server-declared route(s) --" \
     "$(printf '%s' "$e3_violations" | grep -c . || true) calling the shell unexempted," \
     "${e3_exempted_count} exempted, $(printf '%s' "$e3_unresolved" | grep -c . || true) unresolved"

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
# Named, dated, reviewed exemptions only; this is not a general escape
# hatch (that decision stays with whoever can grant it, not this file).
#
# `GET /admin/console/clients` was here (RFC 145 §11.3: no template
# existed for it at all) until RFC 141 cycle 2 (2026-11-03) built the
# screen and its `app.rs` route. Empty by design, like `NONCE_EXEMPT`
# and `E4_EXEMPT` -- an empty list is the cheapest case to keep honest,
# not a skippable one (RFC 165 §3).
GATE_42_EXEMPT=""

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

gate42_scanned=0
gate42_shadowed=""
gate42_absent=""
gate42_exempted_count=0
gate42_matched=""
while IFS= read -r path; do
  [ -z "$path" ] && continue
  gate42_scanned=$((gate42_scanned + 1))
  exempted=$(printf '%s\n' "$GATE_42_EXEMPT" | grep -Fx "GET $path" || true)
  shadow_route=$(classify_client_route "$path") && status=0 || status=$?
  case "$status" in
    0) ;;  # EXACT — pass
    1)
      if [ -z "$exempted" ]; then
        gate42_shadowed="${gate42_shadowed}GET ${path} -- shadowed by app.rs route \"${shadow_route}\"
"
      else
        gate42_exempted_count=$((gate42_exempted_count + 1))
        gate42_matched="${gate42_matched}${exempted}
"
      fi
      ;;
    2)
      if [ -z "$exempted" ]; then
        gate42_absent="${gate42_absent}GET ${path} -- no app.rs route of any shape
"
      else
        gate42_exempted_count=$((gate42_exempted_count + 1))
        gate42_matched="${gate42_matched}${exempted}
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

report_exemption_staleness "GATE_42_EXEMPT" "$GATE_42_EXEMPT" "$gate42_matched"

echo "ℹ️   GATE_42 coverage: scanned ${gate42_scanned} client-declared GET route(s) --" \
     "$(printf '%s' "$gate42_shadowed" | grep -c . || true) shadowed," \
     "$(printf '%s' "$gate42_absent" | grep -c . || true) absent," \
     "${gate42_exempted_count} exempted"

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

nonce_scanned=0
nonce_violations=""
nonce_unresolved=""
nonce_exempted_count=0
nonce_matched=""

while IFS= read -r line; do
  [ -z "$line" ] && continue
  nonce_scanned=$((nonce_scanned + 1))
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
    else
      nonce_exempted_count=$((nonce_exempted_count + 1))
      nonce_matched="${nonce_matched}${exempted}
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

report_exemption_staleness "NONCE_EXEMPT" "$NONCE_EXEMPT" "$nonce_matched"

echo "ℹ️   NONCE coverage: scanned ${nonce_scanned} Response::from_html call site(s) --" \
     "$(printf '%s' "$nonce_violations" | grep -c . || true) violations," \
     "${nonce_exempted_count} exempted," \
     "$(printf '%s' "$nonce_unresolved" | grep -c . || true) unresolved"

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
  if ! grep -Fxq "$entry" <<< "$(printf '%b' "$e4_named_matched")"; then
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
e4_exempt_matched=""
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
    else
      e4_exempt_matched="${e4_exempt_matched}${exempted}\n"
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

report_exemption_staleness "E4_EXEMPT" "$E4_EXEMPT" "$(printf '%b' "$e4_exempt_matched")"

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
# original 36-row population scan did not know to look for. A third,
# `required (header token)`, added by RFC 141 cycle 2 (2026-11-03) for the
# four `/admin/console/clients*` write routes: a JSON-body endpoint has no
# form field to carry a double-submit token, so the control is a
# non-safelisted request header instead (`crate::csrf::verify_csrf_header`,
# called via `clients.rs`'s own `csrf_header_ok` -- the grep below matches
# the shared primitive, not the per-file wrapper, the same way `plain`
# rows below match `csrf::verify\(|verify_csrf\(` rather than every
# route's own call site name). A fourth, `required (Content-Type)`, added
# by RFC 152 half D (2026-11-03): for a JSON-body endpoint the mere
# presence of a non-safelisted `Content-Type: application/json` is
# itself a complete CSRF defence (`crate::csrf::require_json_content_type`
# -- see its own doc for why), distinct from `header token` above (a
# CUSTOM header, also non-safelisted, but compared against the CSRF
# cookie too). Three rows: `/me/security/delete-account` (the control
# already existed; only its cell was false), `/webauthn/authenticate/
# {start,finish}` (the control was added this cycle, confirmed against
# `static/webauthn.js`'s real caller first). `/webauthn/register/
# {start,finish}` deliberately do NOT get this mechanism -- no live
# caller exists to confirm it against; see `N/A (no ambient credential)`
# below instead.
#
# `preview-token binding` (the two `config/log_level/{preview,apply}`
# entries described two paragraphs up) was REMOVED by RFC 174(b)
# (2026-11-03): both routes were deleted outright (a live probe found the
# console rendered no form reaching them, and `apply` answered 400 before
# the KV write or the audit event it falsely claimed). Removing the two
# `route-contracts.md` rows left this `case` arm matching nothing --
# checked, nothing failed, because the "scanned-but-never-matched"
# staleness discipline below covers `NAMED_NON_HANDLERS` and the
# exemption lists, not these mechanism arms. Extending it to cover them
# too is queued separately (RFC 174 §3), not built here.
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
    "header token")          echo "verify_csrf_header\\(" ;;
    "Content-Type")          echo "require_json_content_type\\(" ;;
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
# table's functions are. A second entry, RFC 152 half D (2026-11-03):
# `routes::api_v1::anonymous::promote` reads only the `Authorization`
# header via its own `resolve_anonymous_bearer` (crates/backend/src/
# routes/api_v1/anonymous.rs) -- the same shape as `userinfo_handler`
# above, an independent header-only resolver unrelated to `admin::auth`.
e6_bearer_alt_check() {
  case "$1" in
    "routes::oidc::userinfo_handler")    echo "extract_bearer\\(" ;;
    "routes::api_v1::anonymous::promote") echo "resolve_anonymous_bearer\\(" ;;
    *)                                    echo "" ;;
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
# delete,patch}_async(` line, instead of requiring both on one line.
#
# RFC 152 half D (2026-11-03): the registration-line match used to be
# `index($0, ".${method}_async(")` -- a literal substring, no space
# tolerated between `_async` and `(`. 13 registrations in `lib.rs` are
# column-aligned as `.post_async  ("...", ...)` (two spaces, so every
# route's handler starts in the same column); the substring check could
# never match any of them. Invisible until now because all but one of
# the 13 are `N/A (bearer)` rows already sitting in
# `E6_BEARER_LEGACY_EXEMPT`, which `continue`s before ever using the
# (empty, unresolved) qualified name -- `/api/v1/anonymous/promote`
# becoming a real bearer-alt claim this cycle is what made the gap
# fail loudly instead of silently. Fixed by matching the method/async
# boundary as a regex tolerating any run of spaces, not by reformatting
# 13 lines of an unrelated file to dodge a parser's assumption.
e6_qualified_handler_for() {
  local method="$1" path="$2"
  # `re1` is built INSIDE the awk script from `method` (passed via -v
  # with no regex metacharacters of its own) rather than passed in
  # pre-escaped -- gawk's own `-v` assignment does its own backslash
  # processing and silently drops an unrecognised escape (`\.` becomes
  # plain `.`), which a pre-escaped `-v re1=...` string could not
  # survive. Built as a literal awk string instead, where `\\` is
  # awk's own string escape for one backslash, so the backslash reaches
  # the regex engine intact.
  awk -v method="$method" -v n2="\"${path}\"" -v methods="$ROUTE_METHODS" '
    BEGIN { collecting = 0; re1 = "\\." method "_async[ ]*\\("; re_next = "\\.(" methods ")_async[ ]*\\(" }
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
        if ($0 ~ re_next) { exit }
        if (emit()) exit
        next
      }
      if ($0 ~ re1 && index($0, n2) > 0) {
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
    reexport=$(grep -oE "pub use [A-Za-z0-9_]+::[A-Za-z0-9_]+ as ${fn};" "$direct" | head -1) || true
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
  # A fourth shape, found resolving RFC 152 half D's own new claims:
  # `webauthn.rs`'s `pub use authenticate::{authenticate_finish,
  # authenticate_start};` and `pub use register::{register_finish,
  # register_start};` -- a BRACE-LIST re-export, same names (so the
  # renaming case above never matches: there is no ` as `), from a
  # submodule file named after the *ceremony* (`authenticate.rs`,
  # `register.rs`), not after either individual function the way the
  # one-level submodule guess above assumes. Every one of the three
  # existing shapes resolved every row before this cycle, so this is
  # new vocabulary, not a fix to a wrong answer -- `authenticate_start`/
  # `authenticate_finish`/`register_start`/`register_finish` were always
  # `N/A (JSON)` (declared, no resolution needed) until two of the four
  # became `required (Content-Type)` claims this cycle.
  if [ -f "$direct" ] && grep -qE "pub use [A-Za-z0-9_]+::\{[^}]*\\b${fn}\\b[^}]*\\};" "$direct"; then
    local brace_leaf="$direct"
    leaf=$(grep -oE "pub use [A-Za-z0-9_]+::\{[^}]*\\b${fn}\\b[^}]*\\};" "$brace_leaf" | head -1 | sed -E 's/pub use ([A-Za-z0-9_]+)::.*/\1/') || true
    local braced="$REPO_ROOT/crates/backend/src/routes/${modpath//::/\/}/${leaf}.rs"
    if [ -f "$braced" ] && grep -qE "fn ${fn}[<(]" "$braced"; then
      printf '%s\t%s\n' "$braced" "$fn"
      return
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
  decide_fn=$(grep -oE 'decide_[A-Za-z0-9_]+\(' <<< "$body" | head -1 | sed -E 's/\($//') || true
  if [ -n "$decide_fn" ]; then
    body="${body}
$(e6_fn_body "$file" "$decide_fn")"
  fi
  echo "$body"
}

e6_field_name_for() {
  local file="$1" fn="$2" name body
  body=$(e6_fn_body "$file" "$fn")
  name=$(grep -oE '\.get\("csrf[A-Za-z0-9_]*"\)' <<< "$body" | head -1 | sed -E 's/.*"(.*)".*/\1/') || true
  if [ -z "$name" ] && grep -q 'verify_csrf(' <<< "$body"; then
    name=$(grep -oE '\.get\("csrf[A-Za-z0-9_]*"\)' "$COMMON_RS" | head -1 | sed -E 's/.*"(.*)".*/\1/') || true
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
#
# `N/A (JSON)` removed here by RFC 152 half D (2026-11-03): all seven
# rows that carried it were false (the cell claimed a Content-Type check
# that did not exist) and are now one of `required (Content-Type)`
# (a real control, confirmed against a real caller first) or the new
# `N/A (no ambient credential)` below (no live caller, or none that
# could be confirmed, so no check to add). No row uses the literal value
# `N/A (JSON)` any more -- left in the list it would be caught as stale
# by the check a few lines down; removed instead of waiting for that.
#
# `N/A (no ambient credential)` is new, narrower than the existing
# `N/A (no ambient credential, no state change)` below: three rows
# (`webauthn/register/{start,finish}`, `api_v1/anonymous::begin`) read no
# ambient credential the same way `POST /accept-invite` does, but DO
# change state (an authenticator row; a new anonymous user) where
# `accept_submit` changes none. CSRF's danger model is about an ambient
# credential a forged request can ride on; without one, whether state
# changes is beside the point -- a forged POST does nothing a direct,
# credential-less POST with the same body could not already do. Kept as
# its own value rather than stretched onto the existing one, per this
# file's own rule against inventing a synonym for a value that already
# exists but also against silently widening one to cover a case its own
# wording does not describe.
E6_DECLARED_NO_CHECK="N/A (CORS preflight)
N/A (RFC 7009)
N/A (Authorization-only)
N/A (dev only)
N/A (SameSite=Strict)
N/A (no ambient credential, no state change)
N/A (no ambient credential)"

ROUTE_METHODS_MUTATING_UPPER=$(sed -E 's/^GET\|?//' <<< "$ROUTE_METHODS_UPPER")

e6_rows=$(awk -F'|' -v mutating="$ROUTE_METHODS_MUTATING_UPPER" '
  BEGIN { re_mutating = "^(" mutating ")$" }
  /^\|/ {
    method = $2; gsub(/^[ \t]+|[ \t]+$/, "", method)
    if (method !~ re_mutating) next
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
      if grep -Fxq "$csrf_cell" <<< "$E6_DECLARED_NO_CHECK"; then
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
    if grep -Fxq "$exempt_key" <<< "$E6_BEARER_LEGACY_EXEMPT"; then
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
        grep -qE 'csrf::verify\(|verify_csrf\(' <<< "$body" && ok=1 || reason="does not call csrf::verify"
        ;;
      mechanism)
        needle=$(e6_mechanism_check "$mech")
        if [ -z "$needle" ]; then
          reason="unknown mechanism name \"${mech}\" -- add it to e6_mechanism_check"
        elif [ "$needle" = "STANDARD" ]; then
          grep -qE 'csrf::verify\(|verify_csrf\(' <<< "$body" && ok=1 || reason="does not call csrf::verify"
        elif grep -qE "$needle" <<< "$body"; then
          ok=1
        else
          reason="does not call the control named \"${mech}\""
        fi
        ;;
      bearer)
        bearer_pattern='resolve_from_request_header_only\(|resolve_or_respond_header_only\('
        bearer_alt=$(e6_bearer_alt_check "$qualified")
        [ -n "$bearer_alt" ] && bearer_pattern="${bearer_pattern}|${bearer_alt}"
        grep -qE "$bearer_pattern" <<< "$body" \
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
  if ! grep -Fxq "$entry" <<< "$(printf '%b' "$e6_exempt_matched")"; then
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
  if ! grep -Fxq "$entry" <<< "$(printf '%b' "$e6_declared_matched")"; then
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

# ── E7 (RFC 171 §3 Q1): for every PortError variant a caller matches,
#    can the production adapter behind that call return it? ─────────────
#
# The census (rfcs/handoffs/171-.../q1-census.md) is this check's own
# specification -- §6 is the shape below, §5 is the expected findings,
# §3's tables are the data this reproduces from source every run rather
# than carrying forward as committed per-method rows (RFC 165 §3's own
# lesson: a per-method table nobody re-derives is a list waiting to go
# stale the way E4/E6's own exemption lists once did).
#
# Population: every `pub trait` under crates/core/src whose methods
# return PortResult<T> -- not "a trait the adapters implement" (the
# census's first attempt at that rule needed a judgement call for
# TurnstileVerifier, whose one implementation lives in cesauth-backend,
# not either adapter crate). Checked per method, not per trait: of 38
# `pub trait` definitions, 36 have EVERY method return PortResult<T>;
# the other two (MagicLinkMailer, ImportSink) use a different error
# vocabulary entirely and are out of Q1's scope by construction.
E7_CORE_SRC="$REPO_ROOT/crates/core/src"

e7_population=$(
  find "$E7_CORE_SRC" -name '*.rs' | sort | while read -r f; do
    awk -v file="$f" '
      /^pub trait [A-Za-z0-9_]+/ {
        match($0, /pub trait [A-Za-z0-9_]+/)
        traitname = substr($0, RSTART+10, RLENGTH-10)
        depth = 0; started = 0; buf = ""
      }
      traitname != "" {
        buf = buf $0 "\n"
        depth += gsub(/{/, "{"); depth -= gsub(/}/, "}")
        if (index($0, "{") > 0) started = 1
        if (started && depth == 0) {
          n = split(buf, lines, "\n")
          for (i = 1; i <= n; i++) {
            line = lines[i]
            if (match(line, /fn [A-Za-z0-9_]+/)) {
              mname = substr(line, RSTART+3, RLENGTH-3)
              sig = line; j = i
              while (index(sig, ";") == 0 && j < n) { j++; sig = sig " " lines[j] }
              if (sig ~ /PortResult</) { print traitname "\t" mname }
            }
          }
          traitname = ""; buf = ""
        }
      }
    ' "$f"
  done
)
e7_total=$(printf '%s\n' "$e7_population" | grep -c . || true)
e7_trait_count=$(printf '%s\n' "$e7_population" | cut -f1 | sort -u | grep -c . || true)

# Production implementer: exactly one file under either adapter crate or
# cesauth-backend (TurnstileVerifier's own exception) implements each
# trait. More or fewer than one is this check's own stop condition --
# RFC 171 §3 Q1's own census rule, a stable textual anchor or a reported
# failure, never a guess.
e7_impl_unresolved=0
e7_impl_files=""
e7_struct_names=""
while IFS= read -r trait; do
  [ -z "$trait" ] && continue
  matches=$(grep -rlE "impl ${trait} for " "$REPO_ROOT/crates/adapter-cloudflare/src" "$REPO_ROOT/crates/backend/src" --include='*.rs' 2>/dev/null || true)
  n=$(printf '%s\n' "$matches" | grep -c . || true)
  if [ "$n" -ne 1 ]; then
    echo "❌  E7: trait ${trait} has ${n} implementation(s) matching" \
         "\"impl ${trait} for \" under adapter-cloudflare/backend (want" \
         "exactly 1) -- report this rather than guessing which to use." >&2
    e7_impl_unresolved=$((e7_impl_unresolved + 1))
    continue
  fi
  f="$matches"
  struct=$(grep -oE "impl ${trait} for [A-Za-z0-9_]+" "$f" | head -1 | sed -E "s/impl ${trait} for //") || true
  e7_impl_files="${e7_impl_files}${trait}\t${f}\n"
  e7_struct_names="${e7_struct_names}${trait}\t${struct}\n"
done <<< "$(printf '%s\n' "$e7_population" | cut -f1 | sort -u)"

if [ "$e7_impl_unresolved" -gt 0 ]; then
  exit_code=1
fi

# Extracts an impl-block method's body (indented, never `pub` -- trait
# methods are visible through the trait, not their own keyword), bounded
# from its `async fn`/`fn` line to the matching close brace.
e7_method_body() {
  awk -v want="$2" '
    match($0, /^[ \t]*(pub[ \t]+)?(async[ \t]+)?fn[ \t]+[A-Za-z0-9_]+/) {
      line = $0
      sub(/^[ \t]*(pub[ \t]+)?(async[ \t]+)?fn[ \t]+/, "", line)
      match(line, /^[A-Za-z0-9_]+/)
      cur = substr(line, RSTART, RLENGTH)
      in_target = (cur == want)
      if (in_target) { depth = 0; started = 0 }
    }
    in_target {
      print $0
      depth += gsub(/{/, "{"); depth -= gsub(/}/, "}")
      if (index($0, "{") > 0) started = 1
      if (started && depth == 0) in_target = 0
    }
  ' "$1" 2>/dev/null
}

# Producer-helper registry (census §6.2): a helper call does not
# literally spell a PortError variant where it is CALLED -- only inside
# its own definition, which the calling method never shows. Small,
# hand-curated (the census's own census hit exactly this -- "the number
# I am not quoting" -- so this stays a short, named, verified list, not
# a per-method table), staleness-checked below: if a helper here is
# never called by any producer method this run, the entry is stale.
e7_producer_helper_variants() {
  case "$1" in
    run_err)              echo "Unavailable" ;;
    classify_insert_err)  echo "Unavailable,Conflict,NotFound" ;;
    *) echo "" ;;
  esac
}
# classify_insert_message is NOT its own registry entry: it is
# classify_insert_err's own internal delegate (repo.rs calls
# classify_insert_message(&e.to_string()) from inside
# classify_insert_err's own body) -- no producer method body ever
# spells "classify_insert_message(" directly, so listing it here
# would always be stale by construction, not a real finding.
E7_PRODUCER_HELPERS="run_err
classify_insert_err"
e7_helper_matched=""

e7_producer_sets=""
while IFS=$'\t' read -r trait method; do
  [ -z "$trait" ] && continue
  file=$(awk -F'\t' -v t="$trait" '$1==t{print $2; exit}' <<< "$(printf '%b' "$e7_impl_files")") || true
  [ -z "$file" ] && continue
  body=$(e7_method_body "$file" "$method")
  variants=""
  for v in NotFound Conflict PreconditionFailed Serialization Unavailable; do
    grep -q "PortError::${v}" <<< "$body" && variants="${variants} ${v}"
  done
  for h in $E7_PRODUCER_HELPERS; do
    if grep -q "${h}(" <<< "$body"; then
      variants="${variants} $(e7_producer_helper_variants "$h" | tr ',' ' ')"
      e7_helper_matched="${e7_helper_matched}${h}\n"
    fi
  done
  # Three ad-hoc `contains("UNIQUE")` matcher sites named in census
  # §5.1 -- no shared function to call, a bare inline string check,
  # resolved to its own measured producible set rather than guessed:
  # D1's message text reads "UNIQUE constraint failed" for both
  # SQLITE_CONSTRAINT_UNIQUE and _PRIMARYKEY on these tables.
  if grep -q 'contains("UNIQUE"' <<< "$body"; then
    variants="${variants} Conflict Unavailable"
  fi
  sorted=$(printf '%s\n' $variants | sort -u | tr '\n' ',' | sed 's/,$//')
  e7_producer_sets="${e7_producer_sets}${trait}\t${method}\t${sorted}\n"
done <<< "$e7_population"

# Sink registry (census §6.1): a function/conversion whose OWN body is
# the authoritative place a PortError variant becomes "matched" for
# every call routed through it. The three `impl From<PortError> for X`
# conversions are discovered fresh every run (RFC 171's own lesson: a
# registry that stops matching is the failure mode this whole RFC is
# about) -- not hand-maintained, so a fourth one added later needs no
# edit here. `port_error_response` is likewise discovered, by its own
# signature shape (a function taking a bare PortError). `unwrap_storage`
# is the one hand-curated alias: its signature takes PortResult<T>, not
# PortError, so the same discovery cannot find it, and its own body
# (crates/backend/src/routes/api_v1/quota.rs) just forwards to
# port_error_response -- verified below every run, not assumed once.
#
# A variant OR'd together with another on the SAME match arm
# (ClientOpError's `PreconditionFailed | Unavailable | Serialization =>
# Internal`) is not distinctly matched -- no code path depends on
# telling it apart from its arm-mates. Only a variant on its own arm
# counts (found live: the naive "every literal variant" reading falsely
# flagged ClientRepository::create for PreconditionFailed, which its
# real match arm merges with two others into one identical outcome).
e7_distinct_variants() {
  awk '
    # ok_or(PortError::X) operates on an Option, not a Result -- it
    # synthesises a fresh Err(X) from the port call own Ok(None); the
    # adapter never produced X at all. Confirmed false positive without
    # this exclusion: BucketSafetyRepository::get only ever returns
    # {Serialization, Unavailable}; its one caller writes
    # safety.get(...).await?.ok_or(PortError::NotFound)? -- NotFound
    # there is manufactured from a legitimate Ok(None).
    /ok_or\([ \t]*PortError::/ { next }
    { n = gsub(/PortError::[A-Za-z]+/, "&", $0); if (n == 0) next
      line = $0; count = 0; delete seen
      while (match(line, /PortError::[A-Za-z]+/)) {
        v = substr(line, RSTART+11, RLENGTH-11)
        if (!(v in seen)) { seen[v] = 1; count++ }
        line = substr(line, RSTART+RLENGTH)
      }
      if (count == 1) { for (v in seen) print v }
    }
  ' | sort -u
}

e7_conversion_sinks=""
while IFS=: read -r file line rest; do
  [ -z "$file" ] && continue
  target=$(printf '%s' "$rest" | sed -E 's/.*impl From<PortError> for ([A-Za-z0-9_]+).*/\1/')
  fromline=$(awk -v start="$line" 'NR>=start && NR<=start+5 && /fn from/ {print NR; exit}' "$file")
  [ -z "$fromline" ] && continue
  body=$(awk -v startline="$fromline" '
    NR < startline { next }
    { print $0
      depth += gsub(/{/, "{"); depth -= gsub(/}/, "}")
      if (index($0, "{") > 0) started = 1
      if (started && depth == 0) exit
    }' "$file")
  set=$(printf '%s' "$body" | e7_distinct_variants | tr '\n' ',' | sed 's/,$//')
  e7_conversion_sinks="${e7_conversion_sinks}${target}\t${set}\n"
done <<< "$(grep -rn "impl From<PortError> for " "$E7_CORE_SRC" "$REPO_ROOT/crates/backend/src" --include='*.rs' 2>/dev/null || true)"

e7_port_error_response_sink=""
while IFS=: read -r file line rest; do
  [ -z "$file" ] && continue
  fname=$(printf '%s' "$rest" | sed -E 's/.*fn ([A-Za-z0-9_]+)\(.*/\1/')
  body=$(awk -v startline="$line" '
    NR < startline { next }
    { print $0
      depth += gsub(/{/, "{"); depth -= gsub(/}/, "}")
      if (index($0, "{") > 0) started = 1
      if (started && depth == 0) exit
    }' "$file")
  set=$(printf '%s' "$body" | e7_distinct_variants | tr '\n' ',' | sed 's/,$//')
  e7_port_error_response_sink="${fname}\t${set}"
done <<< "$(grep -rnE 'fn [A-Za-z0-9_]+\([a-z_]+: *(cesauth_core::ports::)?PortError\)' "$E7_CORE_SRC" "$REPO_ROOT/crates/backend/src" --include='*.rs' 2>/dev/null | grep -v 'fn from(' || true)"

E7_UNWRAP_STORAGE="$REPO_ROOT/crates/backend/src/routes/api_v1/quota.rs"
e7_unwrap_storage_stale=1
if [ -f "$E7_UNWRAP_STORAGE" ] && grep -q "fn unwrap_storage" "$E7_UNWRAP_STORAGE" \
   && awk '/fn unwrap_storage/{f=1} f && /port_error_response\(/{found=1} f && /^}/{exit} END{exit !found}' "$E7_UNWRAP_STORAGE"; then
  e7_unwrap_storage_stale=0
fi

e7_sink_set() {
  case "$1" in
    unwrap_storage)
      if [ "$e7_unwrap_storage_stale" -eq 0 ]; then
        printf '%b\n' "$e7_port_error_response_sink" | cut -f2 | head -1 || true
      fi
      ;;
    *)
      { printf '%b' "$e7_conversion_sinks"; printf '%b\n' "$e7_port_error_response_sink"; } \
        | awk -F'\t' -v n="$1" '$1==n{print $2; exit}' || true
      ;;
  esac
}
E7_SINK_NAMES="$(printf '%b' "$e7_conversion_sinks" | cut -f1 | grep -v '^$' || true) $(printf '%b\n' "$e7_port_error_response_sink" | cut -f1) unwrap_storage"

# The two shapes RFC 171 §3 Q1's own census drew and the exemptions
# review asked restored: `written` (a distinct outcome the caller can
# never reach -- a reader notices the wrong thing happening) vs
# `chokepoint` (the missing variant only ever passes through the
# SHARED, ~50-site generic dispatcher -- port_error_response/
# unwrap_storage -- which was never engineered for this one caller and
# promised it nothing). A bespoke `impl From<PortError> for X`
# conversion (ClientOpError, AuthFailure, ...) IS caller/domain-specific
# -- it exists to let exactly that caller's own match arms distinguish
# outcomes -- so a missing variant explained ONLY by one of those, or
# by a literal `PortError::X` the caller wrote directly, is `written`.
# e7_fn_matched_set therefore returns "<generic>|||<bespoke>" instead
# of one merged set, so the caller can tell which bucket a missing
# variant actually came from.
E7_GENERIC_SINKS="unwrap_storage $(printf '%b\n' "$e7_port_error_response_sink" | cut -f1)"

e7_fn_matched_set() {
  local body="$1" propagates="${2:-0}"
  local sigline direct generic bespoke s set2 g is_generic gset bset
  sigline=$(head -5 <<< "$body" | tr '\n' ' ') || true
  # `RECEIVER.method(...).await?` discharges the error immediately,
  # before anything after it runs at all -- whatever `PortError::X`
  # text appears later in this scope is examining the UNWRAPPED SUCCESS
  # value (an Option, a status field, ...), not this call's own error
  # path, so it must not be read as a literal match on this call.
  # Found live: crates/core/src/tenancy/service.rs::create_organization
  # writes `match tenants.get(tenant_id).await? { Some(_) => return
  # Err(PortError::Conflict), None => return Err(PortError::NotFound)
  # }` -- both are fresh errors synthesised from the tenant's status
  # field on a SUCCESSFUL lookup, not from TenantRepository::get's own
  # error path, which the leading `?` already discharged. The sink
  # check below (keyed to the enclosing function's own return type)
  # still applies on a propagating call -- `?` still invokes that
  # type's own `From<PortError>` -- only the literal-text scan is
  # unsafe here.
  if [ "$propagates" = "1" ]; then
    direct=""
  else
    direct=$(printf '%s\n' "$body" | e7_distinct_variants | tr '\n' ' ')
  fi
  generic=""
  bespoke="$direct"
  for s in $E7_SINK_NAMES; do
    if grep -q "${s}::from(\|: ${s} = \|${s}(" <<< "$body" \
       || grep -q "${s}>" <<< "$sigline"; then
      set2=$(e7_sink_set "$s")
      [ -z "$set2" ] && continue
      is_generic=0
      for g in $E7_GENERIC_SINKS; do [ "$g" = "$s" ] && is_generic=1; done
      if [ "$is_generic" -eq 1 ]; then
        generic="${generic} $(printf '%s' "$set2" | tr ',' ' ')"
      else
        bespoke="${bespoke} $(printf '%s' "$set2" | tr ',' ' ')"
      fi
    fi
  done
  gset=$(printf '%s\n' $generic | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//' || true)
  bset=$(printf '%s\n' $bespoke | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//' || true)
  printf '%s|||%s' "$gset" "$bset"
}

# Bounded to the specific statement/block containing the call, not the
# whole function -- a function calling more than one method of a trait
# (or another trait entirely) must not have a LATER, unrelated match
# credited to an EARLIER call whose own result went somewhere else
# (found live: crates/core/src/deletion.rs's schedule_deletion calls
# both find_pending_by_user, feeding an `if let Ok(Some(_))`, and
# create, whose own Conflict arm is textually later in the same
# function -- the whole-function reading wrongly credited Conflict to
# find_pending_by_user too). A call whose own result is `let _ =`
# discarded contributes nothing, matching this project's own established
# "a dropped Result is not a caller" reading used throughout the census.
e7_call_site_scopes() {
  local body="$1" method="$2" receivers="$3"
  awk -v method="$method" -v receivers="$receivers" '
    { lines[NR] = $0 }
    END {
      pat = "(" receivers ")\\." method "\\("
      for (i = 1; i <= NR; i++) {
        if (lines[i] ~ pat && lines[i] !~ /let _ =/) {
          depth = 0; j = i; cap = i + 20; scope = ""
          while (j <= NR && j <= cap) {
            scope = scope lines[j] "\n"
            depth += gsub(/{/, "{", lines[j]); depth -= gsub(/}/, "}", lines[j])
            if (depth <= 0 && index(lines[j], ";") > 0) { j++; break }
            j++
          }
          print "---SCOPE---"; printf "%s", scope
        }
      }
    }
  ' <<< "$body"
}

E7_CORE_BACKEND_FILES=$(find "$E7_CORE_SRC" "$REPO_ROOT/crates/backend/src" -name '*.rs')

# A candidate FILE matching ${trait}/${struct} somewhere does not mean
# every `.method(` in it is a call on an instance of this trait -- a
# file routinely constructs several different repositories side by
# side (`let tenants = CloudflareTenantRepository::new(...); let orgs
# = CloudflareOrganizationRepository::new(...);`) and both expose a
# `get`/`create`/... of their own. Without binding the match to the
# actual receiver, a call on the WRONG repository (same method name,
# different trait) gets credited to this one -- found live:
# TenantRepository::get was picking up organizations.rs's `orgs.get(`
# (via port_error_response) even though that function never calls
# `tenants.get(` at all. Three receiver shapes, all seen in this
# codebase: (1) a local `let NAME = Struct::new(...)` binding; (2) a
# generic bound `<T: Trait>` paired with a parameter typed `&T` (the
# service-layer style, e.g. `fn soft_delete_tenant<T: TenantRepository>
# (tenants: &T, ...)`); (3) a direct `name: &dyn Trait` / `&impl Trait`
# parameter. A function matching none of these is not treated as a
# caller of this trait at all (RFC 165's "under-reporting is the safer
# failure mode" -- skip it rather than fall back to an unscoped,
# receiver-blind match).
e7_receiver_names() {
  local body="$1" trait="$2" struct="$3"
  local sig_block generic names=""
  sig_block=$(awk '{print} /\{/{exit}' <<< "$body")
  names="${names} $(grep -oE "let[ \t]+[A-Za-z0-9_]+[ \t]*(:[^=]+)?=[ \t]*${struct}::new\(" <<< "$body" \
    | sed -E 's/^let[ \t]+([A-Za-z0-9_]+).*/\1/' | tr '\n' ' ')"
  generic=$(grep -oE "[A-Za-z0-9_]+[ \t]*:[ \t]*${trait}\b" <<< "$sig_block" | head -1 | sed -E 's/^([A-Za-z0-9_]+).*/\1/') || true
  if [ -n "$generic" ]; then
    names="${names} $(grep -oE "[A-Za-z0-9_]+[ \t]*:[ \t]*&?${generic}\b" <<< "$sig_block" \
      | sed -E 's/^([A-Za-z0-9_]+).*/\1/' | tr '\n' ' ')"
  fi
  names="${names} $(grep -oE "[A-Za-z0-9_]+[ \t]*:[ \t]*&?(dyn|impl)[ \t]+${trait}\b" <<< "$sig_block" \
    | sed -E 's/^([A-Za-z0-9_]+).*/\1/' | tr '\n' ' ')"
  printf '%s\n' $names | grep -v '^$' | sort -u || true
}

e7_resolve_callers() {
  local trait="$1" method="$2" struct="$3"
  local candidates f fns fn body scopes scope ms sigline receivers receiver_pat propagates
  local result_g="" result_b="" g_part b_part gset bset
  candidates=$(printf '%s\n' "$E7_CORE_BACKEND_FILES" | xargs grep -lE "[:<,[:space:]]${trait}[>,[:space:]]|${struct}::new\(" 2>/dev/null || true)
  for f in $candidates; do
    fns=$(grep -oE '^[ \t]{0,4}(pub[ \t]+)?(async[ \t]+)?fn[ \t]+[A-Za-z0-9_]+' "$f" | sed -E 's/.*fn[ \t]+//' | sort -u || true)
    for fn in $fns; do
      body=$(e7_method_body "$f" "$fn")
      [ -z "$body" ] && continue
      receivers=$(e7_receiver_names "$body" "$trait" "$struct")
      [ -z "$receivers" ] && continue
      receiver_pat=$(printf '%s' "$receivers" | tr '\n' '|' | sed 's/|$//')
      scopes=$(e7_call_site_scopes "$body" "$method" "$receiver_pat")
      [ -z "$scopes" ] && continue
      sigline=$(head -5 <<< "$body") || true
      scope=""
      while IFS= read -r line; do
        if [ "$line" = "---SCOPE---" ]; then
          if [ -n "$scope" ]; then
            propagates=0
            head -1 <<< "$scope" | grep -qE '\.await[ \t]*\?' && propagates=1
            ms=$(e7_fn_matched_set "$(printf '%s\n%s' "$sigline" "$scope")" "$propagates")
            g_part="${ms%%|||*}"; b_part="${ms#*|||}"
            [ -n "$g_part" ] && result_g="${result_g},${g_part}"
            [ -n "$b_part" ] && result_b="${result_b},${b_part}"
          fi
          scope=""
        else
          scope="${scope}${line}
"
        fi
      done <<< "$scopes"
      if [ -n "$scope" ]; then
        propagates=0
        head -1 <<< "$scope" | grep -qE '\.await[ \t]*\?' && propagates=1
        ms=$(e7_fn_matched_set "$(printf '%s\n%s' "$sigline" "$scope")" "$propagates")
        g_part="${ms%%|||*}"; b_part="${ms#*|||}"
        [ -n "$g_part" ] && result_g="${result_g},${g_part}"
        [ -n "$b_part" ] && result_b="${result_b},${b_part}"
      fi
    done
  done
  gset=$(printf '%s' "$result_g" | tr ',' '\n' | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//' || true)
  bset=$(printf '%s' "$result_b" | tr ',' '\n' | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//' || true)
  printf '%s|||%s' "$gset" "$bset"
}

# ── E7's two exemption lists (RFC 171 §3 Q1 exemptions review) ──────────
#
# `e6ab206`'s check was built exactly as specified -- "build the check"
# and "do not fix anything the check finds," with no exemption
# mechanism named -- and that combination can only produce a red
# release gate forever, which blocks every cut. The project's own
# answer already exists: E6_BEARER_LEGACY_EXEMPT ships E6 with 18
# known-unfixed rows, named, dated, reasoned, staleness-checked, under
# a comment saying the list must shrink as each is actually fixed.
# Copied here, not its absence.
#
# The 31 DEFECTs are not one population -- the review found they
# collapse two shapes the census (§5.4) deliberately kept apart:
#
#   `written`    -- the caller has a DISTINCT outcome for a variant its
#                    adapter cannot produce, and that outcome was
#                    engineered FOR THIS CALLER specifically: a literal
#                    `PortError::X` match it wrote itself, or a bespoke
#                    `impl From<PortError> for X` conversion that exists
#                    to let exactly this caller's domain distinguish
#                    outcomes (ClientOpError's Conflict vs NotFound, a
#                    real 409 vs a real 404). A reader notices the wrong
#                    thing happening.
#   `chokepoint` -- every missing variant passes ONLY through the
#                    shared, ~50-call-site generic dispatcher
#                    (port_error_response / its unwrap_storage alias),
#                    which exists for OTHER callers' genuine needs and
#                    was never engineered for this one. Nothing was
#                    promised here, so nothing distinct is lost.
#
# This is checked per missing variant, not by counting how many
# variants a caller matches (the review's own 5/26 by "matches all
# five" was named as a proxy, not the test): a missing variant backed
# by a bespoke sink or a literal match makes the whole method
# `written`; a method whose missing variants are ALL explained by the
# generic dispatcher is `chokepoint`.
#
# Exempting a name here means "known, not fixed, sized for later" --
# never "the check is wrong." Both lists are keyed by `Trait::method`
# and staleness-checked (RFC 165 §3): an entry matching no DEFECT this
# run is stale and fails the build, the same as a fixed-and-forgotten
# E6 row. A DEFECT found OUTSIDE both lists also fails the build --
# that is the whole point of naming them, not widening them silently.

# `written` -- should shrink first: each is a caller promising an
# outcome (via ClientOpError's bespoke conversion) it cannot deliver.
# Found 2026-11-04, RFC 171 §3 Q1's check (commit e6ab206); sized
# individually per RFC 171 §4, RFC 175 the precedent for how one gets
# handled.
E7_WRITTEN_EXEMPT="ClientRepository::find
ClientRepository::list
ClientRepository::update
ClientRepository::set_secret_hash
ClientRepository::delete"

# `chokepoint` -- the shared dispatcher residual the census left open
# (~50 call sites across 7 files, 3 traced); this check now enumerates
# it fully. Each caller's missing variants are explained only by
# port_error_response/unwrap_storage, which exists for other callers'
# genuine needs and promises this one nothing -- no distinct outcome
# is lost. Found 2026-11-04, RFC 171 §3 Q1's check (commit e6ab206).
E7_CHOKEPOINT_EXEMPT="RoleAssignmentRepository::create
RoleAssignmentRepository::delete
RoleAssignmentRepository::list_for_user
PlanRepository::get
SubscriptionRepository::current_for_tenant
SubscriptionRepository::set_plan
SubscriptionRepository::set_status
SubscriptionHistoryRepository::list_for_subscription
TenantRepository::get
TenantRepository::list_active
TenantRepository::set_status
TenantRepository::update_display_name
OrganizationRepository::get
OrganizationRepository::list_for_tenant
OrganizationRepository::set_status
OrganizationRepository::update_display_name
GroupRepository::delete
MembershipRepository::add_tenant_membership
MembershipRepository::remove_tenant_membership
MembershipRepository::list_tenant_members
MembershipRepository::add_organization_membership
MembershipRepository::remove_organization_membership
MembershipRepository::list_organization_members
MembershipRepository::add_group_membership
MembershipRepository::remove_group_membership
MembershipRepository::list_group_members"

e7_resolved=0
e7_written=0
e7_chokepoint=0
e7_no_caller=0
e7_defect_report=""
e7_written_matched=""
e7_chokepoint_matched=""

while IFS=$'\t' read -r trait method producer; do
  [ -z "$trait" ] && continue
  struct=$(awk -F'\t' -v t="$trait" '$1==t{print $2; exit}' <<< "$(printf '%b' "$e7_struct_names")") || true
  both=$(e7_resolve_callers "$trait" "$method" "$struct")
  generic="${both%%|||*}"; bespoke="${both#*|||}"
  caller=$(printf '%s\n%s\n' "$generic" "$bespoke" | tr ',' '\n' | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//' || true)
  missing="" missing_bespoke=""
  if [ -n "$caller" ]; then
    while IFS= read -r v; do
      [ -z "$v" ] && continue
      case ",${producer}," in
        *",${v},"*) ;;
        *)
          missing="${missing}${v} "
          case ",${bespoke}," in
            *",${v},"*) missing_bespoke="${missing_bespoke}${v} " ;;
          esac
          ;;
      esac
    done <<< "$(printf '%s' "$caller" | tr ',' '\n')"
  fi
  if [ -n "$missing" ]; then
    key="${trait}::${method}"
    if [ -n "$missing_bespoke" ]; then
      e7_written=$((e7_written + 1))
      if grep -Fxq "$key" <<< "$E7_WRITTEN_EXEMPT"; then
        e7_written_matched="${e7_written_matched}${key}\n"
      else
        e7_defect_report="${e7_defect_report}[written, unexempted] ${trait}::${method} -- producer {${producer}}, caller matches {${caller}}, missing: ${missing}\n"
      fi
    else
      e7_chokepoint=$((e7_chokepoint + 1))
      if grep -Fxq "$key" <<< "$E7_CHOKEPOINT_EXEMPT"; then
        e7_chokepoint_matched="${e7_chokepoint_matched}${key}\n"
      else
        e7_defect_report="${e7_defect_report}[chokepoint, unexempted] ${trait}::${method} -- producer {${producer}}, caller matches {${caller}}, missing: ${missing}\n"
      fi
    fi
  elif [ -n "$caller" ]; then
    e7_resolved=$((e7_resolved + 1))
  else
    e7_no_caller=$((e7_no_caller + 1))
  fi
done <<< "$(printf '%b' "$e7_producer_sets")"

e7_defect=$((e7_written + e7_chokepoint))

if [ "$((e7_resolved + e7_defect + e7_no_caller))" -ne "$e7_total" ]; then
  echo "❌  E7 coverage arithmetic does not close: ${e7_total} methods !=" \
       "${e7_resolved} resolved + ${e7_defect} DEFECT + ${e7_no_caller}" \
       "no_caller -- this is a bug in the check itself, not a finding" \
       "about the backend." >&2
  exit_code=1
fi

if [ -n "$e7_defect_report" ]; then
  echo "❌  A caller matches a PortError variant its production adapter" \
       "cannot produce, and it is not a named, dated entry in" \
       "E7_WRITTEN_EXEMPT or E7_CHOKEPOINT_EXEMPT (RFC 171 §3 Q1):" >&2
  printf '%b' "$e7_defect_report" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
  echo "" >&2
  echo "    Either the adapter is missing a classifier it should use" >&2
  echo "    (classify_insert_err, for a real UNIQUE/PRIMARY KEY column)," >&2
  echo "    the caller's match arm is dead, or this is a genuinely new" >&2
  echo "    finding that needs its own named, dated exemption entry --" >&2
  echo "    each is its own sizing decision (RFC 171 §4); do not fix it" >&2
  echo "    here, name it." >&2
  exit_code=1
fi

for name in E7_WRITTEN_EXEMPT E7_CHOKEPOINT_EXEMPT; do
  case "$name" in
    E7_WRITTEN_EXEMPT)    stale=$(exemption_stale_entries "$E7_WRITTEN_EXEMPT" "$(printf '%b' "$e7_written_matched")") ;;
    E7_CHOKEPOINT_EXEMPT) stale=$(exemption_stale_entries "$E7_CHOKEPOINT_EXEMPT" "$(printf '%b' "$e7_chokepoint_matched")") ;;
  esac
  if [ -n "$stale" ]; then
    echo "❌  ${name} entr(y|ies) matching NO DEFECT this run (stale):" >&2
    printf '%s\n' "$stale" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
    echo "" >&2
    echo "    The method behind this entry was fixed, its classification" >&2
    echo "    changed, or it no longer exists -- remove it from ${name}" >&2
    echo "    above, rather than leaving a pre-authorised exemption" >&2
    echo "    nobody is reviewing." >&2
    exit_code=1
  fi
done

# Staleness, same discipline as every other registry in this file: a
# producer-helper that matched nothing this run is a pre-authorised
# entry nobody is reviewing any more.
e7_helper_stale=$(exemption_stale_entries "$E7_PRODUCER_HELPERS" "$(printf '%b' "$e7_helper_matched")")
if [ -n "$e7_helper_stale" ]; then
  echo "❌  E7 producer-helper registry entr(y|ies) matching NO producer" \
       "method this run (stale):" >&2
  printf '%s\n' "$e7_helper_stale" | while IFS= read -r line; do [ -n "$line" ] && echo "    $line" >&2; done
  echo "" >&2
  echo "    The helper was renamed or is no longer called -- remove it" >&2
  echo "    from E7_PRODUCER_HELPERS, rather than leaving a stale entry." >&2
  exit_code=1
fi

if [ "$e7_unwrap_storage_stale" -ne 0 ]; then
  echo "❌  E7's unwrap_storage alias no longer holds: its own body" \
       "(crates/backend/src/routes/api_v1/quota.rs) must call" \
       "port_error_response( directly, verified every run rather than" \
       "assumed once -- it no longer does, or the file moved." >&2
  exit_code=1
fi

echo "ℹ️   E7 coverage: scanned ${e7_total} port method(s) across" \
     "${e7_trait_count} PortResult-returning trait(s) -- ${e7_resolved}" \
     "resolved, ${e7_defect} DEFECT (${e7_written} written + ${e7_chokepoint}" \
     "chokepoint, all exempted-by-name), ${e7_no_caller} no_caller" \
     "(${e7_resolved} + ${e7_defect} + ${e7_no_caller} = ${e7_total})"

if [ "$exit_code" -eq 0 ]; then
  echo "✅  All ${registered_count} routes are documented in route-contracts.md, and every" \
       "handler-shaped fn in routes/ is reachable from lib.rs"
fi

exit "$exit_code"
