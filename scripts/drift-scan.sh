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
    # RFC 039: OTP must never appear in audit reason (fixed in v0.50.3 / v0.54.1).
    "dev-delivery handle=	OTP dev-delivery format must not appear in non-runbook docs (RFC 030/039)"
    # RFC 039: nodejs_compat removed in RFC 038 — catch if it re-appears in wrangler.toml
    # (docs/investigations that reference it by name are exempt)
    # Handled by checking wrangler.toml directly rather than pattern scan
    # RFC 039: Box<dyn MagicLinkMailer> replaced by enum dispatcher (RFC 031).
    # Catch new production usage; historical docs/comments that explain the change are exempt.
    # Use specific pattern: -> Box<dyn MagicLinkMailer> (return type, not in comments)
    "-> Box<dyn MagicLinkMailer>	Box<dyn MagicLinkMailer> return type; use CloudflareMagicLinkMailer enum (RFC 031)"
    # RFC 071: hardcoded version-plus-caption strings in UI footers.
    # Pattern: "vX.Y.Z (some phase descriptor)" — the parenthesised text is the giveaway.
    # CHANGELOG, ROADMAP, and docs may reference bare version numbers without parens;
    # those are historical records and are intentionally excluded by this narrow pattern.
    "v0\.[0-9]\+\.[0-9]\+ (	Hardcoded version-with-caption in source (RFC 071) — remove the version string from footers"
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

# ---------------------------------------------------------------------------
# RFC 108: hardcoded URL paths in production UI templates.
#
# Catalog at `crates/core/src/routes.rs` is the single source of truth. UI
# templates must reference `cesauth_core::routes::*` constants and builders
# rather than embed URL string literals. The catalog mirrors what the worker
# actually registers; drift between catalog and worker is caught at the
# worker side (route registration referencing the catalog).
#
# **Exemptions** (intentional — do NOT migrate these):
#   - Any standalone `tests.rs` file: tests assert on rendered URLs by
#     string. If a catalog entry drifts, these tests should fail loudly
#     — that's their job.
#   - Any line at or below a `#[cfg(test)]` or `mod tests` marker in a
#     production .rs file: same reasoning. We assume the convention that
#     `mod tests` is the last item in the file, which holds across the
#     codebase.
#   - `tenant_admin/oidc_clients.rs`: pre-existing orphan UI (RFC 017),
#     worker route not registered. See file's module docstring.
#   - `tenancy_console/forms/membership_add.rs`: pre-existing orphan UI,
#     form action URLs not registered by the worker. See file's module
#     docstring.
# ---------------------------------------------------------------------------

ui_url_matches=()
while IFS= read -r -d '' file; do
    case "$file" in
        */tests.rs)                                continue ;;
        # v0.75.0: test files split out under tests/ subdirs (per the
        # dev guidelines' 500-ELOC threshold). Same exemption rationale
        # as standalone tests.rs files — these are rendering test
        # fixtures, deliberately keeping hardcoded URLs as drift
        # detectors.
        */tests/*.rs)                              continue ;;
        */tenant_admin/oidc_clients.rs)            continue ;;
        */tenancy_console/forms/membership_add.rs) continue ;;
    esac
    while IFS= read -r hit; do
        [[ -n "$hit" ]] && ui_url_matches+=("$hit")
    done < <(awk -v fname="$file" '
        /^#\[cfg\(test\)\]/ { exit }
        /^mod tests/         { exit }
        { print fname ":" NR ":" $0 }
    ' "$file" | grep -E '"/(admin|me|oidc|auth|login|logout|magic-link|\.well-known)/' \
              | grep -v '// RFC 108 exempt' \
              | grep -v 'path!("/' \
              | grep -v 'path="/' \
              || true)
done < <(find "${REPO_ROOT}/crates/frontend/src" -name '*.rs' \
    -not -path '*/pages/*' \
    -not -name 'app.rs' \
    -print0)
# NOTE: crates/frontend/src/pages/** and app.rs are intentionally excluded
# from the RFC 108 check.  These are Leptos CSR component files; their URL
# strings are fetch() calls, form actions, and <Route path=...> declarations.
# RFC 108 was written for SSR template functions where cesauth_core::routes::*
# was the clear alternative.  A follow-up RFC will decide whether to share
# route constants between backend and frontend crates, at which point these
# files can be brought back into scope.

if [[ ${#ui_url_matches[@]} -gt 0 ]]; then
    echo "RFC 108: hardcoded URL paths in production UI templates"
    echo "  (use cesauth_core::routes::* instead; see crates/core/src/routes.rs)"
    if [[ $VERBOSE -eq 1 ]]; then
        for m in "${ui_url_matches[@]}"; do
            echo "  $m"
        done
    else
        echo "  ${#ui_url_matches[@]} hits — re-run with --verbose to list"
    fi
    echo ""
    echo "RFC 108 violations detected (see above)."
    echo "Migrate to cesauth_core::routes::* or add to the exemption list"
    echo "in scripts/drift-scan.sh with a rationale comment."
    exit 1
fi

echo "drift-scan: clean — no stale phrases detected."
