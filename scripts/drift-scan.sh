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
#
# RFC 182: with `pipefail` (below), piping a large variable into a reader
# that can exit before reading all of it -- `grep -q`/`grep -*q`, `head`,
# or an `awk` script with its own `exit` -- risks SIGPIPE on the writer.
# Under load, the writer can be scheduled late enough to still be writing
# when the reader is done, and pipefail then reports the pipeline as
# failed (128+13=141) even though the reader's own match succeeded: a
# real match silently reported as a miss. Fixed throughout this file by
# feeding such readers a here-string (`<<<`) instead of a pipe, which has
# no writer process to kill, or by appending `|| true` to a bare
# assignment whose pipe ends in `head`. New checks in this file should
# follow the same rule rather than reintroduce a `cmd | grep -q`/`| head`
# pipe.
set -euo pipefail

VERBOSE=0
[[ "${1:-}" == "--verbose" ]] && VERBOSE=1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN_PATHS=("${REPO_ROOT}/crates" "${REPO_ROOT}/docs" "${REPO_ROOT}/README.md" "${REPO_ROOT}/ROADMAP.md" "${REPO_ROOT}/.github/workflows" "${REPO_ROOT}/package.json")

# ---------------------------------------------------------------------------
# Coverage (RFC 129 D5).
#
# SCAN_PATHS covers: crates/, docs/, README.md, ROADMAP.md, and — since RFC 138
# D3 — .github/workflows/ and the root package.json, so rules about how CI
# installs tools can see the files that install them.
#
# Deliberately never scanned: lockfiles. They are large, generated, full of
# version strings, and not authored text (RFC 138 §8.5). The root package.json
# is named as a single file rather than reached by recursion, and
# `--exclude="package-lock.json"` keeps any lockfile out of the directory walks.
#
# Reached only locally: generated, gitignored build output under a scanned
# directory — today crates/backend/build/package.json, written by
# `wrangler build`, and absent in CI. No current pattern matches it (RFC 138
# M2). A future pattern that did would pass in CI and fail locally.
#
# Everything else is out by omission: rfcs/, CHANGELOG.md, migrations/, the rest
# of .github/, Makefile, wrangler.toml, scripts/. Nobody has audited these for
# stale phrases or decided whether they belong in SCAN_PATHS — recorded here
# so the next blind spot found in one of them is a known gap, not a surprise.
# A future change that adds one of these to SCAN_PATHS should move it out of
# this list and into the line above.
#
# RFC 028 archive expansion, 2026-10-31: six patterns gained
# `docs/changelog-archive/` in their exclude_regex when the CHANGELOG archive
# grew from v0.49 to v0.84. The root CHANGELOG.md is out of SCAN_PATHS by
# omission (see below), so archiving moves historical text from a file this
# script never reads into a directory it does — and the six entries that fired
# were all *records of removing* the very phrase they matched. The archive is
# immutable history by RFC 028's own policy, so a present-tense claim check over
# it could only ever be satisfied by editing history. That is the same
# reasoning already carried by the patterns at the RFC 114 rename block, now
# applied to six more. **It is a coverage reduction and it is stated here**:
# those six no longer examine the archive, and this registry prints no
# per-pattern coverage figure — a gap recorded for RFC 164's cycle, which is
# already adding checks to this script.
#
# Within docs/, individual PATTERNS entries additionally exclude specific
# historical-record subpaths (ADRs, the changelog archive) via their
# exclude_regex field — see the PATTERNS comment block below. That is a
# per-rule exclusion, distinct from the SCAN_PATHS-level omissions above.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Stale-phrase registry.
# Each entry is "pattern<TAB>reason" or, since RFC 126,
# "pattern<TAB>reason<TAB>exclude_regex" — no literal tabs in the pattern,
# reason, or exclude_regex fields themselves.
# Patterns must be specific enough not to fire on *historical explanations* of
# why something changed (e.g. migration docs legitimately reference "R2 audit").
# Target: present-tense claims about removed behavior.
#
# `exclude_regex` (optional, third field, RFC 126 D3) excludes matches whose
# file path matches the given bash regex. Use it when a pattern is correct
# in a live doc but would also match inside a document that is a deliberate
# historical record — an RFC in `rfcs/done/` or `rfcs/archive/`, an ADR under
# `docs/src/expert/adr/`, or an archived changelog under
# `docs/changelog-archive/`. Those documents describe what was true when they
# were written; rewriting them to match current reality would falsify the
# record (the same principle that keeps `rfcs/done/` and `rfcs/archive/`
# immutable). A pattern with no third field applies everywhere in
# SCAN_PATHS, as before — two-field entries remain fully supported.
# ---------------------------------------------------------------------------
declare -a PATTERNS=(
    # README/intro claim: "all land in R2" — false since v0.32.0.
    "all land in R2	present-tense audit-to-R2 claim (v0.32.0 moved to D1, ADR-010)	docs/changelog-archive/"
    # Binding name removed in v0.32.0.
    "R2_AUDIT	R2_AUDIT binding removed in v0.32.0	docs/changelog-archive/"
    # OTP field naming: v0.50.3 renamed code_plaintext → delivery_payload (RFC 008).
    # Note: the audit/tests.rs denylist file itself references "code_plaintext" as a
    # string to detect — that's intentional and excluded below via grep's -l vs -n.
    # Pattern is specific enough: `code_plaintext:` (field declaration) not a string literal.
    "pub code_plaintext	renamed to delivery_payload in v0.50.3 (RFC 008); field should not re-appear	docs/changelog-archive/"
    # README claim corrected in v0.52.1 (RFC 012).
    #
    # RFC 129 C1-129: excluded on ROADMAP.md. RFC 129 D4 added ROADMAP.md to
    # SCAN_PATHS; this pattern then matched ROADMAP.md:781, which quotes the
    # README's old "No management GUI" claim inside a past-tense description
    # of the RFC 012 fix that corrected it. Rephrasing a quotation of what a
    # doc used to say would falsify the record of what it said — the same
    # reasoning that excludes docs/changelog-archive/ above, applied here
    # because ROADMAP.md's per-release entries are the same kind of
    # historical record, verified by reading all matches in context.
    # Cost: ROADMAP.md's forward-looking planning sections are unprotected
    # from this pattern too — a file-level regex can't isolate the
    # historical entries from the planning ones. Every *other* pattern in
    # this file still scans ROADMAP.md in full; only these five are
    # exempted (see the crates/worker block below for the other four).
    "No management GUI	README claim corrected in v0.52.1 (RFC 012)	ROADMAP\.md|docs/changelog-archive/"
    # RFC 039: OTP must never appear in audit reason (fixed in v0.50.3 / v0.54.1).
    "dev-delivery handle=	OTP dev-delivery format must not appear in non-runbook docs (RFC 030/039)	docs/changelog-archive/"
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
    # RFC 126 D4 / RFC 129 D3: RFC 114 renamed crates/worker -> crates/backend
    # and crates/ui -> crates/frontend. Excluded:
    #   - docs/src/expert/adr/     — historical decision records.
    #   - docs/changelog-archive/  — historical release notes.
    #   - docs/src/expert/tenancy.md — its "## What ships in v0.4.x"
    #     section (roughly lines 351-1099) is a per-subsystem changelog
    #     embedded in a docs/ page, structurally identical to
    #     docs/changelog-archive/: each "### Added in 0.X.0" entry
    #     legitimately names the crate as it was called at that
    #     release. The live content in this file (outside that section)
    #     was manually verified and corrected as of RFC 126; a whole-file
    #     exclusion was used only because this scanner has no way to
    #     exclude a byte range within one file. A future stale reference
    #     introduced in this file's *live* sections will not be caught
    #     by this rule.
    # RFC 129 D3 dropped the former `crates/` exclusion: RFC 129 D1/D2
    # fixed the 19 dead pointers and rephrased the 6 historical
    # statements found under crates/, so the gate now covers it.
    #
    # RFC 129 C1-129: added ROADMAP.md to all four rules below. Same
    # reasoning as the "No management GUI" rule above — ROADMAP.md:154
    # names these exact four patterns while describing RFC 126's fix
    # ("crates/worker / cesauth-ui references... fixed"); rephrasing it
    # would make the entry stop describing what RFC 126 actually did.
    # ROADMAP.md:1262 quotes a TODO that lived at
    # crates/worker/src/flash.rs:215 during the v0.31.0 era — a
    # quotation, not a live claim. Read all eleven matches in context
    # before this exclusion was added (RFC 129 review). Cost and scope:
    # same note as above — ROADMAP.md's planning sections lose coverage
    # from these four patterns only; every other pattern still scans it.
    "crates/worker	RFC 114 renamed crates/worker -> crates/backend	docs/src/expert/adr/|docs/changelog-archive/|docs/src/expert/tenancy\.md|ROADMAP\.md"
    "crates/ui	RFC 114 renamed crates/ui -> crates/frontend	docs/src/expert/adr/|docs/changelog-archive/|docs/src/expert/tenancy\.md|ROADMAP\.md"
    "cesauth-worker	RFC 114 renamed cesauth-worker -> cesauth-backend	docs/src/expert/adr/|docs/changelog-archive/|docs/src/expert/tenancy\.md|ROADMAP\.md"
    "cesauth-ui	RFC 114 renamed cesauth-ui -> cesauth-frontend; the name is wrong in this tree whether it means the crate RFC 114 renamed or the mockup's own crate of the same name — neither belongs here	docs/src/expert/adr/|docs/changelog-archive/|docs/src/expert/tenancy\.md|ROADMAP\.md"
    # RFC 128: audit events moved from R2 objects to D1 rows in v0.32.0
    # (ADR-010), but observability.md described the pre-move architecture
    # until this RFC. Both patterns are specific to the storage-model
    # claim itself, not to "R2" generally — they must not fire on the
    # legitimate `ASSETS` R2 binding references that remain in the same
    # file. Excluded, same as the RFC 126 D3 rules above: ADRs and
    # docs/changelog-archive/ describe the pre-v0.32.0 architecture in
    # the past tense, correctly.
    "Each audit event is one R2 object	audit events have been D1 rows with a hash chain since v0.32.0/ADR-010 (RFC 128)	docs/src/expert/adr/|docs/changelog-archive/"
    "R2 doesn't have SQL	audit-trail query-patterns claim obsoleted by the v0.32.0/ADR-010 move to D1 (RFC 128)	docs/src/expert/adr/|docs/changelog-archive/"
    # RFC 130 M2 pinned the toolchain via rust-toolchain.toml; versioned apt
    # binary names bypass the pin. contributing.md said 1.91 for two releases
    # after CI moved to 1.98.1 (found closing RFC 136). The two excluded files
    # are dated investigation records quoting the commands as they were run.
    # Two rules, not one alternation. Patterns are extended regexes (`grep -E`
    # below), so `\|` is a LITERAL pipe — a first draft written as
    # `cargo-1\.91\|rustc-1\.91` matched only that exact string, i.e. nothing,
    # and the fires/does-not-fire pair caught it before it landed. The dots
    # are escaped for the same reason: `.` is any character under -E.
    "cargo-1\.91	RFC 130 pinned the toolchain in rust-toolchain.toml; use plain cargo, not a versioned apt binary	docs/src/expert/rfc-110-baseline\.md|docs/src/expert/nodejs-compat-investigation\.md|docs/changelog-archive/"
    "rustc-1\.91	RFC 130 pinned the toolchain in rust-toolchain.toml; use plain cargo, not a versioned apt binary	docs/src/expert/rfc-110-baseline\.md|docs/src/expert/nodejs-compat-investigation\.md|docs/changelog-archive/"
    # RFC 138 D3: pins made self-enforcing, by reading the files that install
    # the tools. These are pin guards rather than stale-narrative rules: a hit
    # means an install site no longer names the version DEPENDENCIES.md records.
    #
    # Trunk (RFC 131 C1-R5): `cargo install trunk` without `--version`, with or
    # without `--locked`. `--locked` honours Trunk's own lockfile and still
    # installs its latest release. Anchored at end of line, so it misses both
    # pinned orderings (`--version ... --locked`, `--locked --version ...`) and
    # prose quoting the old command mid-sentence (RFC 138 §11.5, verified).
    "install trunk( --locked)?\s*$	Trunk install without --version; pin it (RFC 131 C1-R5, DEPENDENCIES.md)	docs/changelog-archive/"
    # wrangler (RFC 138 D2): the root package.json must pin wrangler exactly. A
    # range (^, ~, >) lets `npm install` move it and the lockfile moves with it.
    # `npx wrangler` itself is rejected in workflows by the next rule (RFC 138
    # C1-138). The literal quotes are escaped for this bash array. The
    # exclusion scopes it to the root package.json alone -- never a lockfile,
    # never generated output such as crates/backend/build/package.json.
    "\"wrangler\": *\"[\\^~>]	root package.json must pin wrangler exactly, not a range (RFC 138 D2, DEPENDENCIES.md)	crates/|docs/|\.github/|README\.md|ROADMAP\.md"
    # npx wrangler (RFC 138 C1-138): `npx` does not fail when the root install is
    # missing -- it silently runs the npx cache's copy, or in CI fetches the
    # latest release -- so the lockfile protects nothing a job forgets to install.
    # Workflows call node_modules/.bin/wrangler, which fails loudly instead.
    # Scoped by exclusion to .github/workflows: the other scan paths carry prose
    # that names the phrase in order to warn against it.
    # Known limits, recorded: a `#` earlier on the line hides a call, as in
    # `run: echo "#" && npx wrangler`, because comment lines must not match. The
    # Makefile and scripts/ are outside SCAN_PATHS, so this rule does not guard
    # them, and nothing else does automatically.
    "^[^#]*npx wrangler	npx wrangler bypasses the pin when the root install is missing; call node_modules/.bin/wrangler (RFC 138 C1-138)	crates/|docs/|README\.md|ROADMAP\.md|package\.json"
    # RFC 170: credentialed-flows.yml took the release set from thirteen
    # workflows to fourteen. `grep -n "thirteen" scripts/drift-scan.sh`
    # returned nothing before this entry — the count was unguarded prose,
    # this project's signature failure mode, so the next workflow added to
    # the release set would leave contributing.md's "thirteen"/"fourteen"
    # wording stale exactly the way this one just did. No exclude_regex:
    # rfcs/ is out of SCAN_PATHS by omission (see the header comment above),
    # so RFCs 166/168/172's own "thirteen gates" — correct historical
    # statements about the tree on their own dispatch date — are never
    # scanned by this script in the first place, and
    # docs/changelog-archive/'s "twelve ... instead of thirteen" line does
    # not match this pattern's exact wording either way.
    "thirteen (workflows|names|checks)	RFC 170 moved the release workflow set from thirteen to fourteen; contributing.md's three prose counts must track .github/release-gate-manifest.json's release array, not restate a superseded figure"
)

found=0

for entry in "${PATTERNS[@]}"; do
    IFS=$'\t' read -r pattern reason exclude_regex <<< "$entry"

    matches=()
    for path in "${SCAN_PATHS[@]}"; do
        if [[ -e "$path" ]]; then
            while IFS= read -r line; do
                # Match exclude_regex against the file path only (the part
                # before the first `:line_number:` separator) — not the
                # whole line, which also contains the matched *content* and
                # would otherwise spuriously self-exclude (e.g. a pattern
                # for "crates/worker" would match "crates/" inside its own
                # matched text on every hit, everywhere).
                if [[ -n "$exclude_regex" ]]; then
                    hit_path="${line%%:*}"
                    # RFC 129 C1-129: fail loudly if the extraction did not
                    # produce something path-shaped. `grep` omits the filename
                    # prefix for a single bare-file argument (standard
                    # behaviour, GNU and otherwise) — without `-H` above, this
                    # silently yielded the *line number*, so every exclusion on
                    # a bare-file SCAN_PATHS entry matched nothing and looked
                    # configured while doing nothing. `-H` prevents that case;
                    # this guard catches the class, so the next variant is
                    # loud instead of inert.
                    if [[ "$hit_path" != */* ]] && [[ "$hit_path" != *.rs && "$hit_path" != *.md && "$hit_path" != *.toml && "$hit_path" != *.yml && "$hit_path" != *.json ]]; then
                        echo "drift-scan: BROKEN — exclude_regex cannot be applied." >&2
                        echo "  pattern:        $pattern" >&2
                        echo "  extracted path: '$hit_path' (not path-shaped)" >&2
                        echo "  from line:      $line" >&2
                        echo "  grep is not emitting a filename prefix; the exclusion would be inert." >&2
                        exit 2
                    fi
                    if [[ "$hit_path" =~ $exclude_regex ]]; then
                        continue
                    fi
                fi
                matches+=("$line")
            done < <(grep -rHn --include="*.rs" --include="*.md" --include="*.toml" --include="*.yml" --include="*.json" --exclude="package-lock.json" \
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
    -not -path '*/components/*' \
    -not -name 'app.rs' \
    -print0)
# NOTE: crates/frontend/src/pages/**, crates/frontend/src/components/**,
# and app.rs are intentionally excluded from the RFC 108 check.  These are
# Leptos CSR component files; their URL strings are fetch() calls, form
# actions, <A href=...>/<Route path=...> declarations. RFC 108 was written
# for SSR template functions where cesauth_core::routes::* was the clear
# alternative. A follow-up RFC will decide whether to share route constants
# between backend and frontend crates, at which point these files can be
# brought back into scope.
#
# `components/` joined this exclusion at RFC 180 (R2b): it existed before
# only as `components/primitives/`, none of which link anywhere, so this
# gap was latent until R2b's shells/nav files (the first components/ code
# with real href literals) tripped it. Same code, same reasoning as
# pages/ and app.rs above — not a new exemption, a late discovery of an
# existing one's true boundary.

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

# ---------------------------------------------------------------------------
# RFC 169: the book must contain its own pages.
#
# `docs/src/SUMMARY.md` is mdbook's table of contents — a page not reached
# from it by a `(./<relpath>)` entry is never built, never linked from the
# book's own nav, and never shows up for a reader who did not already know
# the exact URL. RFC 169 found eleven such pages, two of them pages a reader
# would reasonably expect to find (route-contracts.md, contributing.md), and
# one live consequence: a page already IN the book linked to one that was
# not, a dead link on the published site.
#
# Two checks, not one, because they are different claims:
#   1. Coverage    -- every docs/src/**/*.md is reachable from SUMMARY.md,
#                      or is a named, dated, reasoned exclusion.
#   2. Link integrity -- no page the book builds links to a .md the book
#                      does not build (which coverage alone cannot catch:
#                      a page can be in-book and still link to one that
#                      is not).
#
# Same discipline as E4's NAMED_NON_HANDLERS and E6's two exemption lists:
# a declared-out entry carries a reason, and one matching no file this run
# is stale -- a pre-authorised exclusion for whatever lands at that path
# next, reviewed by nobody.
# ---------------------------------------------------------------------------

DOCS_SRC="${REPO_ROOT}/docs/src"
SUMMARY_MD="${DOCS_SRC}/SUMMARY.md"

declare -a DOCS_DECLARED_OUT=(
    "expert/rfc-110-baseline.md	a dated audit of the v0.71.0 codebase, taken for RFC 110 -- a record of a moment, not a page a reader navigates to"
    "expert/nodejs-compat-investigation.md	RFC 025 Step 2's investigation record -- same reason as rfc-110-baseline.md"
)

# `(./<relpath>.md)` entries in SUMMARY.md, relpath relative to docs/src/ --
# every entry in this file uses the `./` form (confirmed: 78 of 78 `.md`
# links in SUMMARY.md match this exact shape; a bare-filename or `../` entry
# would need mdbook's own nesting rules anyway, which SUMMARY.md does not use).
docs_inbook_set=$(grep -oE '\]\(\./[^)]+\.md\)' "$SUMMARY_MD" | sed -E 's/^\]\(\.\///; s/\)$//' | sort -u)

docs_scanned=0
docs_inbook_count=0
docs_declared_count=0
docs_unreachable_count=0
docs_unreachable_report=""
docs_declared_matched=""

while IFS= read -r -d '' file; do
    rel="${file#${DOCS_SRC}/}"
    docs_scanned=$((docs_scanned + 1))
    if grep -Fxq "$rel" <<< "$docs_inbook_set"; then
        docs_inbook_count=$((docs_inbook_count + 1))
        continue
    fi
    declared=0
    for entry in "${DOCS_DECLARED_OUT[@]}"; do
        decl_path="${entry%%$'\t'*}"
        if [[ "$rel" == "$decl_path" ]]; then
            docs_declared_count=$((docs_declared_count + 1))
            docs_declared_matched="${docs_declared_matched}${decl_path}\n"
            declared=1
            break
        fi
    done
    [[ $declared -eq 1 ]] && continue
    docs_unreachable_count=$((docs_unreachable_count + 1))
    docs_unreachable_report="${docs_unreachable_report}${rel}\n"
done < <(find "$DOCS_SRC" -name "*.md" ! -name "SUMMARY.md" -print0)

if [[ "$docs_scanned" -ne "$((docs_inbook_count + docs_declared_count + docs_unreachable_count))" ]]; then
    echo "drift-scan: BROKEN -- docs coverage arithmetic does not close:" >&2
    echo "  ${docs_scanned} scanned != ${docs_inbook_count} in-book +" >&2
    echo "  ${docs_declared_count} declared + ${docs_unreachable_count} unreachable." >&2
    exit 2
fi

if [[ "$docs_scanned" -eq 0 ]]; then
    echo "drift-scan: BROKEN -- found ZERO .md files under docs/src; the docs" >&2
    echo "  coverage check would pass vacuously. The scan path is wrong." >&2
    exit 2
fi

echo "ℹ️   docs coverage: scanned ${docs_scanned} page(s) under docs/src -- ${docs_inbook_count} in-book, ${docs_declared_count} declared out, ${docs_unreachable_count} unreachable"

docs_coverage_failed=0

if [[ -n "$docs_unreachable_report" ]]; then
    echo ""
    echo "docs page(s) not reachable from SUMMARY.md and not declared out:"
    printf '%b' "$docs_unreachable_report" | while IFS= read -r line; do [[ -n "$line" ]] && echo "    $line"; done
    echo ""
    echo "  Add a SUMMARY.md entry, or add it to DOCS_DECLARED_OUT in"
    echo "  scripts/drift-scan.sh with a reason."
    docs_coverage_failed=1
fi

docs_declared_stale=""
for entry in "${DOCS_DECLARED_OUT[@]}"; do
    decl_path="${entry%%$'\t'*}"
    if ! grep -Fxq "$decl_path" <<< "$(printf '%b' "$docs_declared_matched")"; then
        docs_declared_stale="${docs_declared_stale}${decl_path}\n"
    fi
done

if [[ -n "$docs_declared_stale" ]]; then
    echo ""
    echo "DOCS_DECLARED_OUT entr(y|ies) matching NO scanned file this run (stale):"
    printf '%b' "$docs_declared_stale" | while IFS= read -r line; do [[ -n "$line" ]] && echo "    $line"; done
    echo ""
    echo "  The file behind this entry was added to SUMMARY.md, renamed, or"
    echo "  removed -- remove it from DOCS_DECLARED_OUT above, rather than"
    echo "  leaving a pre-authorised exclusion nobody is reviewing."
    docs_coverage_failed=1
fi

if [[ "$docs_coverage_failed" -eq 1 ]]; then
    exit 1
fi

# Link integrity: every `.md` link inside an IN-BOOK page must resolve to
# another in-book page, if it resolves under docs/src/ at all. Links that
# resolve OUTSIDE docs/src/ (an RFC under ../../../rfcs/, say) are out of
# scope -- a different, much larger check this one does not attempt.
#
# Each file's newlines are flattened to spaces BEFORE extraction: at least
# one real link wraps its target across two source lines
# (`adr/012-session-hardening.md`'s own
# `[ADR-011: ...](\n  011-....md)`), and grep matches a pattern spanning an
# embedded newline as ONE match either way -- flattening first means `-o`
# still emits exactly one match per link, each on its own output line, so
# the `while read` loop below sees one target per iteration rather than
# that one link's target arriving split across two.
docs_link_scanned=0
docs_link_seen=0
docs_link_absolute=0
docs_link_outside=0
docs_link_unresolvable=0
docs_link_broken=""

while IFS= read -r -d '' file; do
    rel="${file#${DOCS_SRC}/}"
    grep -Fxq "$rel" <<< "$docs_inbook_set" || continue
    dir=$(dirname "$file")
    while IFS= read -r target; do
        [[ -z "$target" ]] && continue
        docs_link_seen=$((docs_link_seen + 1))
        target="${target%%#*}"
        # Trim leading/trailing whitespace left over from a target that
        # wrapped across source lines before the tr/grep flattening above.
        target="${target#"${target%%[![:space:]]*}"}"
        target="${target%"${target##*[![:space:]]}"}"
        # Every `continue` below is a link this check does NOT validate, so
        # each one is counted by name. `docs_link_scanned` counts only what
        # was actually checked: a denominator that includes what a check
        # skipped is the same overstatement E6's census was built to stop
        # (RFC 152 half C cycle 2), and this check is its first caller.
        if [[ "$target" == http://* || "$target" == https://* ]]; then
            docs_link_absolute=$((docs_link_absolute + 1))
            continue
        fi
        resolved=$(realpath -m --relative-to="$DOCS_SRC" "${dir}/${target}" 2>/dev/null) || {
            docs_link_unresolvable=$((docs_link_unresolvable + 1)); continue; }
        case "$resolved" in
            ..*) docs_link_outside=$((docs_link_outside + 1)); continue ;;  # outside docs/src -- out of scope
        esac
        docs_link_scanned=$((docs_link_scanned + 1))
        if ! grep -Fxq "$resolved" <<< "$docs_inbook_set"; then
            docs_link_broken="${docs_link_broken}${rel} -> ${resolved}\n"
        fi
    done < <(tr '\n' ' ' < "$file" | grep -oE '\]\([^)]+\.md(#[^)]*)?\)' | sed -E 's/^\]\(//; s/\)$//')
done < <(find "$DOCS_SRC" -name "*.md" ! -name "SUMMARY.md" -print0)

if [[ "$docs_link_scanned" -eq 0 ]]; then
    echo "drift-scan: BROKEN -- found ZERO .md links across in-book pages; the" >&2
    echo "  link-integrity check would pass vacuously." >&2
    exit 2
fi

docs_link_broken_count=$(printf '%b' "$docs_link_broken" | grep -c . || true)
if [[ $((docs_link_scanned + docs_link_absolute + docs_link_outside + docs_link_unresolvable)) -ne "$docs_link_seen" ]]; then
    echo "drift-scan: BROKEN -- link-integrity census does not close:" \
         "${docs_link_seen} seen != ${docs_link_scanned} checked +" \
         "${docs_link_absolute} absolute + ${docs_link_outside} outside docs/src +" \
         "${docs_link_unresolvable} unresolvable. This is a bug in the check." >&2
    exit 2
fi

echo "ℹ️   docs link integrity: saw ${docs_link_seen} .md link(s) in in-book pages --" \
     "${docs_link_scanned} checked, ${docs_link_absolute} absolute/http," \
     "${docs_link_outside} resolving outside docs/src (out of scope)," \
     "${docs_link_unresolvable} unresolvable; ${docs_link_broken_count} broken"

if [[ -n "$docs_link_broken" ]]; then
    echo ""
    echo "in-book page(s) linking to a .md the book does not build:"
    printf '%b' "$docs_link_broken" | while IFS= read -r line; do [[ -n "$line" ]] && echo "    $line"; done
    echo ""
    echo "  Add the target to SUMMARY.md, or fix the link."
    exit 1
fi

# ---------------------------------------------------------------------------
# RFC 164 — the rfcs/ link sweep.
#
# Every relative-path `.md` link inside rfcs/**/*.md must resolve to a file
# that exists. Unlike the docs/src link check above, this one is NOT bounded
# to rfcs/ itself: a cross-reference may legitimately point into docs/src/
# (an ADR) or docs/changelog-archive/ (a release record), and both are in
# scope. Only a true absolute URL (http/https) is out of scope; everything
# else is a path this check resolves relative to the linking file's own
# directory and tests for existence on disk.
#
# Same discipline as DOCS_DECLARED_OUT above: a declared-out entry carries a
# reason, and one matching no broken link this run is stale.
# ---------------------------------------------------------------------------

RFCS_DIR="${REPO_ROOT}/rfcs"

# One entry. `rfcs/handoffs/.../implementation-handoff.md` quotes RFC 164 §4's
# own example-link shape — the same one de-linked in done/000 and
# archive/019 by this cycle — while describing that fix. The handoff was
# added one commit after cc5329b's own 20-link census, so it was never part
# of that count, and it is prose the dispatching architect wrote about this
# very rule, not a navigational cross-reference anyone follows.
declare -a RFCS_LINK_DECLARED_OUT=(
    # Empty by design, and the staleness check below keeps it honest when it
    # is. The one entry this list held on arrival exempted the dispatching
    # handoff's own quotation of RFC 164 §4's example-link shape; that quote
    # was de-linked instead, which is the same transformation RFC 164 §4
    # chose for the fourteen examples in done/000 and archive/019. An
    # exemption list of one, existing only because a document quotes link
    # syntax, is worse than the de-linking the RFC already settled on.
    #
    # Known limitation, recorded rather than built: the extractor does not
    # skip inline-code spans, so `[text](path.md)` inside backticks is still
    # read as a link. Stripping code spans is the principled fix and is a
    # check of its own; until someone needs it, de-linking is one line and
    # an exemption is a standing one.
)

rfcs_link_seen=0
rfcs_link_absolute=0
rfcs_link_unresolvable=0
rfcs_link_scanned=0
rfcs_link_declared_count=0
rfcs_link_broken=""
rfcs_link_declared_matched=""

while IFS= read -r -d '' file; do
    rel="${file#${REPO_ROOT}/}"
    dir=$(dirname "$file")
    while IFS= read -r target; do
        [[ -z "$target" ]] && continue
        rfcs_link_seen=$((rfcs_link_seen + 1))
        target="${target%%#*}"
        target="${target#"${target%%[![:space:]]*}"}"
        target="${target%"${target##*[![:space:]]}"}"
        if [[ "$target" == http://* || "$target" == https://* ]]; then
            rfcs_link_absolute=$((rfcs_link_absolute + 1))
            continue
        fi
        resolved=$(realpath -m "${dir}/${target}" 2>/dev/null) || {
            rfcs_link_unresolvable=$((rfcs_link_unresolvable + 1)); continue; }
        rfcs_link_scanned=$((rfcs_link_scanned + 1))
        if [[ ! -f "$resolved" ]]; then
            key="${rel} -> ${target}"
            declared=0
            for entry in "${RFCS_LINK_DECLARED_OUT[@]}"; do
                decl_key="${entry%%$'\t'*}"
                if [[ "$key" == "$decl_key" ]]; then
                    rfcs_link_declared_count=$((rfcs_link_declared_count + 1))
                    rfcs_link_declared_matched="${rfcs_link_declared_matched}${decl_key}\n"
                    declared=1
                    break
                fi
            done
            [[ $declared -eq 1 ]] && continue
            resolved_rel="${resolved#${REPO_ROOT}/}"
            rfcs_link_broken="${rfcs_link_broken}${rel} -> ${target} (resolves to ${resolved_rel})\n"
        fi
    done < <(tr '\n' ' ' < "$file" | grep -oE '\]\([^)]+\.md(#[^)]*)?\)' | sed -E 's/^\]\(//; s/\)$//')
done < <(find "$RFCS_DIR" -name "*.md" -print0)

if [[ "$rfcs_link_scanned" -eq 0 ]]; then
    echo "drift-scan: BROKEN -- found ZERO relative .md links across rfcs/; the" >&2
    echo "  rfcs/ link check would pass vacuously." >&2
    exit 2
fi

rfcs_link_broken_count=$(printf '%b' "$rfcs_link_broken" | grep -c . || true)
if [[ $((rfcs_link_scanned + rfcs_link_absolute + rfcs_link_unresolvable)) -ne "$rfcs_link_seen" ]]; then
    echo "drift-scan: BROKEN -- rfcs/ link census does not close:" \
         "${rfcs_link_seen} seen != ${rfcs_link_scanned} checked +" \
         "${rfcs_link_absolute} absolute + ${rfcs_link_unresolvable} unresolvable." \
         "This is a bug in the check." >&2
    exit 2
fi

echo "ℹ️   rfcs/ link sweep: saw ${rfcs_link_seen} .md link(s) across rfcs/**/*.md --" \
     "${rfcs_link_scanned} checked, ${rfcs_link_absolute} absolute/http," \
     "${rfcs_link_unresolvable} unresolvable; ${rfcs_link_broken_count} broken," \
     "${rfcs_link_declared_count} declared out"

rfcs_link_failed=0

if [[ -n "$rfcs_link_broken" ]]; then
    echo ""
    echo "rfcs/ link(s) not resolving to a file that exists:"
    printf '%b' "$rfcs_link_broken" | while IFS= read -r line; do [[ -n "$line" ]] && echo "    $line"; done
    echo ""
    echo "  Fix the link, or add it to RFCS_LINK_DECLARED_OUT in"
    echo "  scripts/drift-scan.sh with a reason."
    rfcs_link_failed=1
fi

rfcs_link_declared_stale=""
for entry in "${RFCS_LINK_DECLARED_OUT[@]}"; do
    decl_key="${entry%%$'\t'*}"
    if ! grep -Fxq "$decl_key" <<< "$(printf '%b' "$rfcs_link_declared_matched")"; then
        rfcs_link_declared_stale="${rfcs_link_declared_stale}${decl_key}\n"
    fi
done

if [[ -n "$rfcs_link_declared_stale" ]]; then
    echo ""
    echo "RFCS_LINK_DECLARED_OUT entr(y|ies) matching NO broken link this run (stale):"
    printf '%b' "$rfcs_link_declared_stale" | while IFS= read -r line; do [[ -n "$line" ]] && echo "    $line"; done
    echo ""
    echo "  The link behind this entry was fixed or removed -- remove it from"
    echo "  RFCS_LINK_DECLARED_OUT above, rather than leaving a pre-authorised"
    echo "  exclusion nobody is reviewing."
    rfcs_link_failed=1
fi

if [[ "$rfcs_link_failed" -eq 1 ]]; then
    exit 1
fi

# ---------------------------------------------------------------------------
# RFC 168 §3.1 — tag <-> CHANGELOG reconciliation, both directions.
#
# Every `X.Y.Z` git tag needs a `## [X.Y.Z]` CHANGELOG entry (root
# CHANGELOG.md or an archive file under docs/changelog-archive/) and vice
# versa. The two directions are named separately, as contributing.md's own
# rule does: "tagged, never documented" and "documented, never tagged" have
# different remedies.
#
# REQUIRES a full git history with tags -- `git tag` returns nothing useful
# against a shallow, tag-less checkout. See the implementation report for
# what this needs from CI; this script does not attempt to detect or work
# around a shallow clone.
#
# The ten historical mismatches are a named, dated exemption, carrying
# contributing.md's own "do not add to this list" as the reason for the
# five already recorded there, plus the five earliest tags researched for
# this cycle. Staleness-checked (RFC 165 §3's pattern), so it cannot quietly
# grow.
# ---------------------------------------------------------------------------

declare -a RELEASE_RECORD_EXEMPT=(
    "tagged-never-documented	0.1.0	predates CHANGELOG record-keeping -- the earliest entry in docs/changelog-archive/CHANGELOG-0.1-to-0.30.md is 0.2.1, and nothing before it was ever documented"
    "tagged-never-documented	0.2.0	predates CHANGELOG record-keeping -- same reason as 0.1.0"
    "tagged-never-documented	0.3.1	tagged ~7 minutes after 0.3.0 on 2026-04-25 with no entry of its own; the archive's own Versioning history note's re-alignment table does not address it either"
    "tagged-never-documented	0.4.0	re-aligned by the archive's Versioning history note: this tarball's content is documented under CHANGELOG heading 0.5.0, not under its own tag"
    "tagged-never-documented	0.50.2	tagged, but its content is narrated inside the surrounding 0.50.1 and 0.50.3 entries' prose (docs/changelog-archive/CHANGELOG-0.50-to-0.59.md) rather than given its own heading"
    "tagged-never-documented	0.79.6	contributing.md's pre-existing ruling: five patch releases (0.79.1-0.79.6) added seventeen registered routes during RFC 115 Phase C with no corresponding CHANGELOG headings -- do not add to this list"
    "documented-never-tagged	0.50.3	contributing.md's pre-existing list -- do not add to this list"
    "documented-never-tagged	0.64.0	contributing.md's pre-existing list -- do not add to this list"
    "documented-never-tagged	0.78.13	contributing.md's pre-existing list: the declared baseline of the governing requirements and external-design specs, so the tree those documents describe cannot be checked out -- do not add to this list"
    "documented-never-tagged	0.79.7	contributing.md's pre-existing list -- do not add to this list"
)

CHANGELOG_FILES=("${REPO_ROOT}/CHANGELOG.md")
while IFS= read -r -d '' f; do CHANGELOG_FILES+=("$f"); done < <(find "${REPO_ROOT}/docs/changelog-archive" -name "*.md" -print0)

release_tag_list=$(git -C "$REPO_ROOT" tag)
release_entry_list=$(grep -hoE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' "${CHANGELOG_FILES[@]}" | sed -E 's/^## \[//; s/\]$//' | sort -u)

release_tags_compared=0
release_entries_compared=0
release_a_violations=""   # tagged, never documented
release_b_violations=""   # documented, never tagged
release_a_matched=""
release_b_matched=""

while IFS= read -r tag; do
    [[ -z "$tag" ]] && continue
    release_tags_compared=$((release_tags_compared + 1))
    if ! grep -Fxq "$tag" <<< "$release_entry_list"; then
        exempted=0
        for entry in "${RELEASE_RECORD_EXEMPT[@]}"; do
            IFS=$'\t' read -r dir ver _ <<< "$entry"
            if [[ "$dir" == "tagged-never-documented" && "$ver" == "$tag" ]]; then
                release_a_matched="${release_a_matched}${tag}\n"
                exempted=1
                break
            fi
        done
        [[ $exempted -eq 1 ]] || release_a_violations="${release_a_violations}${tag}\n"
    fi
done <<< "$release_tag_list"

mapfile -t release_workspace_version_lines < <(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([0-9][0-9.]*\)".*/\1/p' "${REPO_ROOT}/Cargo.toml")
release_workspace_version="${release_workspace_version_lines[0]:-}"
if [[ -z "$release_workspace_version" ]]; then
    echo "drift-scan: BROKEN -- could not read [workspace.package] version from" >&2
    echo "  Cargo.toml; the in-flight-release arm below would silently stop" >&2
    echo "  exempting the release being cut." >&2
    exit 2
fi
release_b_in_flight=""

while IFS= read -r entry_ver; do
    [[ -z "$entry_ver" ]] && continue
    release_entries_compared=$((release_entries_compared + 1))
    if ! grep -Fxq "$entry_ver" <<< "$release_tag_list"; then
        exempted=0
        # The release being cut right now is documented and not yet tagged, by
        # construction: the entry is written in the very commit the tag will
        # point at, so the tag cannot exist when this runs. Without this arm
        # the check fails on every release commit, which would make it
        # impossible to cut a release with a green gate -- found while cutting
        # 0.91.2, the release that added the check.
        #
        # Scoped so it exempts exactly one version and only the right one: the
        # workspace version in Cargo.toml. That makes the arm stricter than a
        # blanket "newest entry" allowance would be -- an entry for any other
        # untagged version still fails, and so does an entry written for a
        # version nobody bumped to.
        if [[ "$entry_ver" == "$release_workspace_version" ]]; then
            release_b_in_flight="$entry_ver"
            exempted=1
        fi
        for entry in "${RELEASE_RECORD_EXEMPT[@]}"; do
            [[ $exempted -eq 1 ]] && break
            IFS=$'\t' read -r dir ver _ <<< "$entry"
            if [[ "$dir" == "documented-never-tagged" && "$ver" == "$entry_ver" ]]; then
                release_b_matched="${release_b_matched}${entry_ver}\n"
                exempted=1
                break
            fi
        done
        [[ $exempted -eq 1 ]] || release_b_violations="${release_b_violations}${entry_ver}\n"
    fi
done <<< "$release_entry_list"

if [[ "$release_tags_compared" -eq 0 || "$release_entries_compared" -eq 0 ]]; then
    echo "drift-scan: BROKEN -- tag/CHANGELOG reconciliation compared ZERO" >&2
    echo "  tags or ZERO entries. git tag likely returned nothing (shallow" >&2
    echo "  clone?) -- this check would otherwise pass vacuously." >&2
    exit 2
fi

release_a_violation_count=$(printf '%b' "$release_a_violations" | grep -c . || true)
release_b_violation_count=$(printf '%b' "$release_b_violations" | grep -c . || true)

echo "ℹ️   release reconciliation: compared ${release_tags_compared} tag(s) against" \
     "${release_entries_compared} CHANGELOG entr(y|ies) -- ${release_a_violation_count}" \
     "tagged-never-documented unexempted, ${release_b_violation_count}" \
     "documented-never-tagged unexempted${release_b_in_flight:+ (plus ${release_b_in_flight}, the release being cut)}"

release_failed=0

if [[ -n "$release_a_violations" ]]; then
    echo ""
    echo "tag(s) with no CHANGELOG entry, and not in RELEASE_RECORD_EXEMPT:"
    printf '%b' "$release_a_violations" | while IFS= read -r line; do [[ -n "$line" ]] && echo "    $line"; done
    release_failed=1
fi

if [[ -n "$release_b_violations" ]]; then
    echo ""
    echo "CHANGELOG entr(y|ies) with no matching tag, and not in RELEASE_RECORD_EXEMPT:"
    printf '%b' "$release_b_violations" | while IFS= read -r line; do [[ -n "$line" ]] && echo "    $line"; done
    release_failed=1
fi

release_exempt_stale=""
for entry in "${RELEASE_RECORD_EXEMPT[@]}"; do
    IFS=$'\t' read -r dir ver _ <<< "$entry"
    if [[ "$dir" == "tagged-never-documented" ]]; then
        grep -Fxq "$ver" <<< "$(printf '%b' "$release_a_matched")" || release_exempt_stale="${release_exempt_stale}${dir}: ${ver}\n"
    else
        grep -Fxq "$ver" <<< "$(printf '%b' "$release_b_matched")" || release_exempt_stale="${release_exempt_stale}${dir}: ${ver}\n"
    fi
done

if [[ -n "$release_exempt_stale" ]]; then
    echo ""
    echo "RELEASE_RECORD_EXEMPT entr(y|ies) matching NO mismatch this run (stale):"
    printf '%b' "$release_exempt_stale" | while IFS= read -r line; do [[ -n "$line" ]] && echo "    $line"; done
    echo ""
    echo "  The tag or entry behind this one was fixed -- remove it from" \
         "RELEASE_RECORD_EXEMPT above, rather than leaving a pre-authorised" \
         "exclusion nobody is reviewing."
    release_failed=1
fi

if [[ "$release_failed" -eq 1 ]]; then
    exit 1
fi

# ---------------------------------------------------------------------------
# RFC 176 §6.1 — colour contrast gate.
#
# e2e/specs/accessibility.spec.ts runs axe over two pages (/ and /login),
# so the tokens actually failing contrast -- rendered in admin/operator
# flash banners, badges and callouts -- are invisible to that gate (same
# shape as RFC 166's finding: a gate whose coverage is narrower than the
# claim a reader takes from it). This is pure arithmetic over the token
# table itself instead, so it needs no browser and runs on every push.
#
# Parses design_tokens.rs ITSELF (never a transcription of it -- a gate
# reading its own copy of the thing it checks is a failure mode this
# project keeps finding) and recomputes the WCAG relative-luminance
# contrast ratio for every semantic pair (RFC 176 §2's reasoning: AAA
# 7:1, not AA 4.5:1, because contrast sensitivity declines with age).
#
# Hex parsing is POSIX-safe (an index() lookup over "0123456789abcdef",
# not gawk's strtonum() -- no script in this repo relies on a gawk
# extension today) even though CI's awk is gawk in practice.
#
# RFC 176 §6.1b: a gate reading only design_tokens.rs was green while
# templates/chrome.rs -- consumed by the magic-link-sent page, the TOTP
# enroll/verify/recovery-codes pages, and generic error pages, all real
# end-user surfaces -- carried the pre-176 values untouched. Same shape
# as §3's own finding about axe, recurring inside the fix for it. Both
# files are parsed now.
#
# Nineteen pairs are checked: `design_tokens.rs`'s four semantic tokens
# (--success/--warning/--danger/--info) against their own --*-bg
# partner, light and dark (8 pairs); `chrome.rs`'s own copy of the same
# four, same shape, no scope tokens (8 pairs, chrome.rs has none per
# design_tokens.rs's own module doc -- "End-user UI has no scope
# badge"); and `design_tokens.rs`'s three scope badge tokens
# (--scope-system/--scope-tenancy/--scope-tenant) against white, the
# background `admin/frame.rs`'s `.scope-badge` rule actually renders
# them on as foreground text (3 pairs). Three more tokens -- the scope
# badges' own dark-mode override -- are declared out rather than
# silently skipped: see design_tokens.rs's module doc for why "white"
# is not an honest claim about what they render on. `unclassified` must
# be 0, the same discipline E4/E6/E7 use.
# ---------------------------------------------------------------------------

DESIGN_TOKENS_RS="${REPO_ROOT}/crates/frontend/src/design_tokens.rs"
CHROME_RS="${REPO_ROOT}/crates/frontend/src/templates/chrome.rs"
CONTRAST_THRESHOLD=7.0

declare -a CONTRAST_DECLARED_OUT=(
    "scope-system (dark)	admin/frame.rs's .scope-badge background has no dark-mode override of its own, so there is no real background this override renders on that a check against white could honestly claim -- see design_tokens.rs's module doc"
    "scope-tenancy (dark)	same reason as scope-system (dark)"
    "scope-tenant (dark)	same reason as scope-system (dark)"
)

contrast_results=$(awk '
    function hex2dec(h,   i, n, c, v) {
        h = tolower(h)
        n = 0
        for (i = 1; i <= length(h); i++) {
            c = substr(h, i, 1)
            v = index("0123456789abcdef", c) - 1
            n = n * 16 + v
        }
        return n
    }
    function lin(c) {
        c = c / 255.0
        if (c <= 0.03928) return c / 12.92
        return ((c + 0.055) / 1.055) ^ 2.4
    }
    function luminance(hex,   r, g, b) {
        r = hex2dec(substr(hex, 1, 2))
        g = hex2dec(substr(hex, 3, 2))
        b = hex2dec(substr(hex, 5, 2))
        return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
    }
    function contrast(h1, h2,   l1, l2, lighter, darker) {
        l1 = luminance(h1); l2 = luminance(h2)
        lighter = (l1 > l2) ? l1 : l2
        darker  = (l1 > l2) ? l2 : l1
        return (lighter + 0.05) / (darker + 0.05)
    }
    # Matches both `r##"..."##;` (design_tokens.rs, pre-escaped for
    # format!() argument position) and `r#"..."#;` (chrome.rs, consumed
    # as a plain value) -- the two constants use different raw-string
    # hash counts, not different token-line shapes.
    {
        if (match($0, /^pub const ([A-Za-z_]+): &str = r#+"/, m)) {
            constname = m[1]; indark = 0; next
        }
        if (constname == "") next
        if ($0 ~ /"#+;/) { constname = ""; next }
        if ($0 ~ /@media \(prefers-color-scheme: dark\)/) { indark = 1; next }
        if (match($0, /--([a-z0-9-]+):[ \t]*#([0-9a-fA-F]{6});/, m2)) {
            val[constname ":" indark ":" m2[1]] = tolower(m2[2])
        }
    }
    END {
        split("success warning danger info", names, " ")
        split("DESIGN_TOKENS_FMT BASE_CSS", consts, " ")
        split("design_tokens.rs chrome.rs", labels, " ")
        for (c = 1; c <= 2; c++) {
            cn = consts[c]; lbl = labels[c]
            for (i = 1; i <= 4; i++) {
                n = names[i]
                fg = val[cn ":0:" n]; bg = val[cn ":0:" n "-bg"]
                if (fg == "" || bg == "") { print lbl " light-" n "\tUNPARSED\t" fg "\t" bg; continue }
                print lbl " light-" n "\t" contrast(fg, bg) "\t#" fg "\t#" bg
            }
            for (i = 1; i <= 4; i++) {
                n = names[i]
                fg = val[cn ":1:" n]; bg = val[cn ":1:" n "-bg"]
                if (fg == "" || bg == "") { print lbl " dark-" n "\tUNPARSED\t" fg "\t" bg; continue }
                print lbl " dark-" n "\t" contrast(fg, bg) "\t#" fg "\t#" bg
            }
        }
        split("scope-system scope-tenancy scope-tenant", snames, " ")
        for (i = 1; i <= 3; i++) {
            n = snames[i]
            fg = val["SCOPE_TOKENS_FMT:0:" n]
            if (fg == "") { print n " (light) vs white\tUNPARSED\t" fg "\t#ffffff"; continue }
            print n " (light) vs white\t" contrast(fg, "ffffff") "\t#" fg "\t#ffffff"
        }
    }
' "$DESIGN_TOKENS_RS" "$CHROME_RS")

contrast_scanned=22
contrast_checked=0
contrast_declared_count=${#CONTRAST_DECLARED_OUT[@]}
contrast_unclassified=0
contrast_violations=""

while IFS=$'\t' read -r pair ratio fg bg; do
    [[ -z "$pair" ]] && continue
    if [[ "$ratio" == "UNPARSED" ]]; then
        contrast_unclassified=$((contrast_unclassified + 1))
        contrast_violations="${contrast_violations}${pair}: could not parse a hex value for this pair out of design_tokens.rs (fg=${fg:-?} bg=${bg:-?})\n"
        continue
    fi
    contrast_checked=$((contrast_checked + 1))
    if (( $(awk -v r="$ratio" -v t="$CONTRAST_THRESHOLD" 'BEGIN { print (r < t) }') )); then
        contrast_violations="${contrast_violations}${pair}: ${fg} on ${bg} is ${ratio}:1, below ${CONTRAST_THRESHOLD}:1\n"
    fi
done <<< "$contrast_results"

if [[ "$contrast_scanned" -ne "$((contrast_checked + contrast_declared_count + contrast_unclassified))" ]]; then
    echo "drift-scan: BROKEN -- contrast gate arithmetic does not close:" >&2
    echo "  ${contrast_scanned} scanned != ${contrast_checked} checked +" >&2
    echo "  ${contrast_declared_count} declared out + ${contrast_unclassified} unclassified." >&2
    exit 2
fi

violation_count=$(printf '%b' "$contrast_violations" | grep -c . || true)

echo "ℹ️   colour contrast: scanned ${contrast_scanned} token(s) -- ${contrast_checked}" \
     "checked against ${CONTRAST_THRESHOLD}:1 (AAA), ${contrast_declared_count} declared" \
     "out, ${contrast_unclassified} unclassified -- ${violation_count} below threshold"

if [[ -n "$contrast_violations" ]]; then
    echo ""
    echo "colour pair(s) below ${CONTRAST_THRESHOLD}:1:"
    printf '%b' "$contrast_violations" | while IFS= read -r line; do [[ -n "$line" ]] && echo "    $line"; done
    exit 1
fi

echo "drift-scan: clean — no stale phrases detected."
