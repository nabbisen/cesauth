#!/usr/bin/env bash
# RFC 156 — fails if the workflows GitHub actually triggered for a commit
# don't match .github/release-gate-manifest.json's `release` list.
#
# This is a release-time (post-push) check, not a per-PR one: it needs the
# GitHub Actions API to see what triggered for THIS exact commit, and that
# list is only complete once every push-triggered workflow has started
# (workflows triggered by the same push register asynchronously, so this
# polls briefly rather than trusting the first snapshot).
#
# Needs: `gh` CLI authenticated (GH_TOKEN in the environment), `jq`.
#
# Usage: release-gate-manifest-check.sh <sha> <owner/repo>

set -euo pipefail

SHA="${1:-}"
REPO="${2:-}"
if [ -z "$SHA" ] || [ -z "$REPO" ]; then
  echo "usage: $0 <sha> <owner/repo>" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$REPO_ROOT/.github/release-gate-manifest.json"

if [ ! -f "$MANIFEST" ]; then
  echo "❌ manifest not found: $MANIFEST" >&2
  exit 1
fi

mapfile -t REQUIRED    < <(jq -r '.release[]' "$MANIFEST" | sort)
mapfile -t EXEMPT       < <(jq -r '.not_on_release_path[].workflow' "$MANIFEST" | sort)
# 0.109.0-release-machinery handoff D7/D8: a third, independent list for a
# workflow that DOES run on a release (so `not_on_release_path` would be a
# lie) but is not required on every push to main (so `release` would make
# it a gate, which it must never be). A tag push shares its head SHA with
# the branch push, so this workflow appears in the same `actions/runs?
# head_sha=` query `release` and `not_on_release_path` entries do — D8
# requires it be accounted for whether or not it has registered yet.
mapfile -t ON_TAG_PUSH  < <(jq -r '.on_tag_push[].workflow' "$MANIFEST" | sort)

if [ "${#REQUIRED[@]}" -eq 0 ]; then
  echo "❌ manifest's 'release' list is empty — refusing to pass trivially" >&2
  exit 1
fi

# Every entry in `not_on_release_path` AND `on_tag_push` must carry a
# non-empty reason — the same discipline as E3_EXEMPT / GATE_42_EXEMPT /
# NONCE_EXEMPT in route-contracts-check.sh. An exemption with no reason is
# not an exemption.
unreasoned=$(jq -r '.not_on_release_path[] | select((.reason // "") | length == 0) | .workflow' "$MANIFEST")
if [ -n "$unreasoned" ]; then
  echo "❌ not_on_release_path entries with no reason: $unreasoned" >&2
  exit 1
fi
unreasoned_tag=$(jq -r '.on_tag_push[] | select((.reason // "") | length == 0) | .workflow' "$MANIFEST")
if [ -n "$unreasoned_tag" ]; then
  echo "❌ on_tag_push entries with no reason: $unreasoned_tag" >&2
  exit 1
fi

contains() {
  local needle="$1"; shift
  local x
  for x in "$@"; do
    [ "$x" = "$needle" ] && return 0
  done
  return 1
}

fetch_triggered() {
  gh api "repos/$REPO/actions/runs?head_sha=$SHA" --paginate \
    --jq '.workflow_runs[].path' \
    | xargs -n1 basename \
    | sort -u
}

TRIGGERED=()
for _ in 1 2 3 4 5 6; do
  mapfile -t TRIGGERED < <(fetch_triggered)
  still_missing=0
  for w in "${REQUIRED[@]}"; do
    contains "$w" "${TRIGGERED[@]}" || still_missing=1
  done
  [ "$still_missing" -eq 0 ] && break
  sleep 10
done

MISSING=()
for w in "${REQUIRED[@]}"; do
  contains "$w" "${TRIGGERED[@]}" || MISSING+=("$w")
done

UNEXPECTED=()
for w in "${TRIGGERED[@]}"; do
  if ! contains "$w" "${REQUIRED[@]}" && ! contains "$w" "${EXEMPT[@]}" && ! contains "$w" "${ON_TAG_PUSH[@]}"; then
    UNEXPECTED+=("$w")
  fi
done

if [ "${#MISSING[@]}" -gt 0 ] || [ "${#UNEXPECTED[@]}" -gt 0 ]; then
  echo "❌ release gate manifest mismatch for $SHA" >&2
  if [ "${#MISSING[@]}" -gt 0 ]; then
    echo "  required by the manifest, did not trigger: ${MISSING[*]}" >&2
  fi
  if [ "${#UNEXPECTED[@]}" -gt 0 ]; then
    echo "  triggered, but not in the manifest's release or not_on_release_path lists: ${UNEXPECTED[*]}" >&2
  fi
  exit 1
fi

echo "✅ release gate manifest: ${#TRIGGERED[@]} workflows triggered for $SHA, all ${#REQUIRED[@]} required present, ${#EXEMPT[@]} exempt accounted for, ${#ON_TAG_PUSH[@]} tag-triggered accounted for."
