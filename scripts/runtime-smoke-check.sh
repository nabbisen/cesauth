#!/usr/bin/env bash
# runtime-smoke-check.sh — RFC 134 T3
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
# measured (RFC 134 T4) that none of the six checks below need them, and
# a gate that requires less setup is a gate more likely to keep running.
#
# Run from the repository root:
#   bash scripts/runtime-smoke-check.sh
#
# Exit codes:
#   0 — all six checks passed, no panic in the console output
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

check_html() {
  local path="$1" name="$2"
  local resp
  resp="$(curl -si "${BASE}${path}" 2>/dev/null)"
  local status ctype csp body
  status="$(printf '%s' "$resp" | head -1 | grep -oE '[0-9]{3}')"
  ctype="$(printf '%s' "$resp" | grep -i '^content-type:' | head -1)"
  csp="$(printf '%s' "$resp" | grep -i '^content-security-policy:' | head -1)"
  body="$(printf '%s' "$resp" | awk 'BEGIN{blank=0} /^\r?$/{blank++; next} blank>0{print}' )"

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

check_html "/"                                                       "GET /"
check_html "/login"                                                  "GET /login"
check_status "/admin/tenancy/tenants/foo/detail.json"          401  "GET /admin/tenancy/tenants/:tid/detail.json"
check_status "/admin/t/acme/detail.json"                        401  "GET /admin/t/:slug/detail.json"
check_status "/admin/t/acme/organizations/org1/detail.json"    401  "GET /admin/t/:slug/organizations/:oid/detail.json"
check_status "/definitely-not-a-route"                          404  "GET /definitely-not-a-route (unregistered)"

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
