#!/usr/bin/env bash
# runtime-smoke-check.sh — RFC 134 T3, extended by C1-134
#
# The first gate in this project's history to boot the Worker runtime and
# issue a request. Every other gate proves compilation, artifact
# production, or documentation consistency; none of them proves the
# router constructs and a request gets a real response. RFC 134 found
# that gap the hard way: `worker`'s router panicked on construction, on
# every request, in eight shipped releases, and nothing noticed.
#
# Boots `wrangler dev`, asserts CONTENT AND HEADERS (never status alone —
# a missing content-security-policy header is invisible to a status
# check, and a panic's 500 looks like any other 500), then tears the
# server down. No `.dev.vars` secrets and no D1 migrations are applied:
# measured (RFC 134 T4) that none of the checks below need them, and a
# gate that requires less setup is a gate more likely to keep running.
#
# C1-134: RFC 134's original six checks proved the *shell* is served —
# 200, text/html, CSP present — while every asset URL the shell itself
# references 404'd (leptos_shell.rs asked for `/assets/...`; the built
# files landed at dist/'s root), so Leptos never mounted. A "the shell
# renders" check cannot see that; the fix is to derive the asset URLs
# from the served HTML — never hardcode them, or this drifts again the
# same way — and assert each one resolves.
#
# Run from the repository root:
#   bash scripts/runtime-smoke-check.sh
#
# Exit codes:
#   0 — all checks passed, no panic in the console output
#   1 — a check failed, or a panic was observed
#   2 — the server never became ready (a different failure than "a check
#       failed" — the build broke, or `wrangler dev` itself errored)

set -uo pipefail
# NOT `set -e`: this script's whole job is to keep going after a failed
# assertion so it can report all six, not stop at the first.

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${SMOKE_PORT:-18787}"
BASE="http://localhost:${PORT}"
LOG="$(mktemp -t cesauth-smoke-XXXXXX.log)"
STATE_DIR="$(mktemp -d -t cesauth-smoke-state-XXXXXX)"

cleanup() {
  if [ -n "${WRANGLER_PID:-}" ]; then
    kill "$WRANGLER_PID" >/dev/null 2>&1 || true
    wait "$WRANGLER_PID" 2>/dev/null || true
  fi
  rm -rf "$STATE_DIR"
}
trap cleanup EXIT

cd "$REPO_ROOT"
( npx wrangler dev --port "$PORT" --persist-to "$STATE_DIR" > "$LOG" 2>&1 & echo $! > "$STATE_DIR/pid" )
WRANGLER_PID="$(cat "$STATE_DIR/pid")"

ready=0
for _ in $(seq 1 60); do
  if grep -qE "Ready on|ERROR|Error:" "$LOG" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 1
done

if [ "$ready" -ne 1 ] || ! grep -q "Ready on" "$LOG"; then
  echo "❌  wrangler dev never became ready:" >&2
  tail -40 "$LOG" >&2
  exit 2
fi

fail=0
ROOT_BODY=""

# Sets $LAST_BODY as a side effect (bash functions can't return strings),
# so the asset-URL extraction below can reuse the same response instead
# of re-fetching.
check_html() {
  local path="$1" name="$2"
  local resp
  resp="$(curl -si "${BASE}${path}" 2>/dev/null)"
  local status ctype csp body
  status="$(printf '%s' "$resp" | head -1 | grep -oE '[0-9]{3}')"
  ctype="$(printf '%s' "$resp" | grep -i '^content-type:' | head -1)"
  csp="$(printf '%s' "$resp" | grep -i '^content-security-policy:' | head -1)"
  body="$(printf '%s' "$resp" | awk 'BEGIN{blank=0} /^\r?$/{blank++; next} blank>0{print}' )"
  LAST_BODY="$body"

  local ok=1
  [ "$status" = "200" ] || { echo "❌  $name: expected 200, got '${status:-<none>}'" >&2; ok=0; }
  printf '%s' "$ctype" | grep -qi 'text/html' || { echo "❌  $name: expected text/html content-type, got '$ctype'" >&2; ok=0; }
  [ -n "$body" ] || { echo "❌  $name: empty body" >&2; ok=0; }
  [ -n "$csp" ] || { echo "❌  $name: no content-security-policy header" >&2; ok=0; }
  if [ "$ok" -eq 1 ]; then
    echo "✅  $name: 200, text/html, non-empty body, CSP present"
  else
    fail=1
  fi
}

check_status() {
  local path="$1" want="$2" name="$3"
  local status
  status="$(curl -s -o /dev/null -w '%{http_code}' "${BASE}${path}" 2>/dev/null)"
  if [ "$status" = "$want" ]; then
    echo "✅  $name: $status"
  else
    echo "❌  $name: expected $want, got '$status'" >&2
    fail=1
  fi
}

# RFC 134 C1-134: every asset URL the served page itself references
# (href="...", src="...", import ... from "...") must resolve. Parsed
# from the response body, never hardcoded — a hardcoded list is exactly
# how this class of drift (leptos_shell.rs asking for a path Static
# Assets does not serve) goes unnoticed a second time.
check_referenced_assets() {
  local body="$1" name="$2"
  # Two shapes: HTML attributes (href="...", src="...", no space before
  # the quote) and JS import statements (`from "..."`, always a space —
  # it's JavaScript syntax, not an HTML attribute, so `from="..."` alone
  # would silently miss every `import ... from "/assets/...";` line).
  local urls
  urls="$( { printf '%s' "$body" | grep -oE '(href|src)="[^"]+"' | sed -E 's/^(href|src)="//; s/"$//'; \
             printf '%s' "$body" | grep -oE 'from[[:space:]]+"[^"]+"' | sed -E 's/^from[[:space:]]+"//; s/"$//'; } \
    | grep -E '^/' \
    | sort -u)"

  if [ -z "$urls" ]; then
    echo "❌  $name: found no asset URLs to check — the extraction pattern may no longer match the shell's markup" >&2
    fail=1
    return
  fi

  local url status
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    status="$(curl -s -o /dev/null -w '%{http_code}' "${BASE}${url}" 2>/dev/null)"
    if [ "$status" = "200" ]; then
      echo "✅  $name: $url -> 200"
    else
      echo "❌  $name: $url -> $status (expected 200)" >&2
      fail=1
    fi
  done <<< "$urls"
}

# RFC 135 W6: the WASM directive, asserted on the served response.
#
# Honest about what this proves: that the directive is *present*, not
# that the bundle mounts. Only a browser can prove the mount (RFC 131
# R5); this is a guard against the directive being silently removed,
# which would return every client surface to a blank page while every
# other check here stayed green — the exact failure RFC 135 fixed.
#
# Both helpers strip `'wasm-unsafe-eval'` before testing for
# `'unsafe-eval'`: the latter is a substring of the former, so a naive
# test would conflate two directives that ADR-007 treats differently.
check_csp_grants_wasm() {
  local path="$1" name="$2"
  local csp stripped
  csp="$(curl -si "${BASE}${path}" 2>/dev/null | grep -i '^content-security-policy:' | head -1)"

  if [ -z "$csp" ]; then
    echo "❌  $name: no content-security-policy header at all" >&2
    fail=1
    return
  fi

  local ok=1
  printf '%s' "$csp" | grep -q "'wasm-unsafe-eval'" || {
    echo "❌  $name: CSP lacks 'wasm-unsafe-eval' — the WASM bundle cannot compile and this surface is a blank page (RFC 135)" >&2
    echo "    $csp" >&2
    ok=0; }

  stripped="$(printf '%s' "$csp" | sed "s/'wasm-unsafe-eval'//g")"
  printf '%s' "$stripped" | grep -q "'unsafe-eval'" && {
    echo "❌  $name: CSP contains 'unsafe-eval' — barred by ADR-007" >&2
    echo "    $csp" >&2
    ok=0; }

  if [ "$ok" -eq 1 ]; then
    echo "✅  $name: CSP grants 'wasm-unsafe-eval', bars 'unsafe-eval'"
  else
    fail=1
  fi
}

# The negative. A server-rendered route must NOT carry the WASM
# directive anywhere — that scoping is RFC 135's design, not a side
# effect, and RFC 135 §8's first risk is the permission leaking to a
# server surface.
#
# Scans the whole header block rather than the CSP line. Deliberate:
# `POST /magic-link/request` is a JSON route, and per ADR-007 JSON
# responses carry the universal header set with **no CSP at all**
# (`json_response_gets_universal_set_only` in security_headers.rs).
# An assertion phrased as "its CSP does not contain the directive"
# would therefore pass without inspecting anything — true of a header
# that does not exist. Scanning the full block asserts a definite
# property of bytes that are actually there, and it catches the
# directive arriving through any header, not only this one.
check_csp_lacks_wasm() {
  local method="$1" path="$2" name="$3"
  local headers csp
  headers="$(curl -si -X "$method" "${BASE}${path}" 2>/dev/null | sed '/^\r*$/q')"

  if [ -z "$headers" ]; then
    echo "❌  $name: no response headers at all" >&2
    fail=1
    return
  fi

  csp="$(printf '%s' "$headers" | grep -i '^content-security-policy:' | head -1)"

  if printf '%s' "$headers" | grep -q "'wasm-unsafe-eval'"; then
    echo "❌  $name: a server-rendered route carries 'wasm-unsafe-eval'; the directive must be scoped to the Leptos shell (RFC 135)" >&2
    printf '%s\n' "$headers" >&2
    fail=1
  elif [ -n "$csp" ]; then
    echo "✅  $name: carries a CSP, and it grants no WASM directive"
  else
    echo "✅  $name: no WASM directive in any response header (this route carries no CSP — JSON surfaces get the universal set only, ADR-007)"
  fi
}

check_html "/"                                                       "GET /"
ROOT_BODY="$LAST_BODY"
check_html "/login"                                                  "GET /login"
check_status "/admin/tenancy/tenants/foo/detail.json"          401  "GET /admin/tenancy/tenants/:tid/detail.json"
check_status "/admin/t/acme/detail.json"                        401  "GET /admin/t/:slug/detail.json"
check_status "/admin/t/acme/organizations/org1/detail.json"    401  "GET /admin/t/:slug/organizations/:oid/detail.json"
check_status "/definitely-not-a-route"                          404  "GET /definitely-not-a-route (unregistered)"
check_referenced_assets "$ROOT_BODY"                                 "GET / referenced assets"
check_csp_grants_wasm "/login"                                       "GET /login CSP (client surface)"
check_csp_lacks_wasm  POST "/magic-link/request"                     "POST /magic-link/request CSP (server surface)"

if grep -qi "Rust panic" "$LOG"; then
  echo "❌  Rust panic observed in the runtime console output:" >&2
  grep -A3 -i "Rust panic" "$LOG" >&2
  fail=1
else
  echo "✅  No Rust panic in the runtime console output"
fi

echo "" >&2
echo "── full console output ──────────────────────────────────" >&2
cat "$LOG" >&2

if [ "$fail" -eq 0 ]; then
  echo "✅  runtime-smoke-check: all checks passed"
  exit 0
else
  echo "❌  runtime-smoke-check: one or more checks failed (see above)" >&2
  exit 1
fi
