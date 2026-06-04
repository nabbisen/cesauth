#!/usr/bin/env bash
# bundle-bloat.sh — RFC 025
#
# Generate a bundle composition snapshot using cargo-bloat and write
# it to docs/src/expert/bundle-composition-snapshot.md.
#
# Requirements:
#   cargo install cargo-bloat
#   wasm-pack or worker-build toolchain for wasm32-unknown-unknown
#
# Usage:
#   bash scripts/bundle-bloat.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_FILE="$REPO_ROOT/docs/src/expert/bundle-composition-snapshot.md"
TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

echo "Running cargo bloat for wasm32-unknown-unknown…"
cd "$REPO_ROOT"

BLOAT_OUTPUT=$(cargo bloat --release --target wasm32-unknown-unknown \
    -p cesauth-worker --crates 2>&1 || true)

cat > "$OUT_FILE" << MDEOF
# Bundle Composition Snapshot

Generated: ${TIMESTAMP}

See [BUNDLE_SIZE_BUDGET.md](../../../BUNDLE_SIZE_BUDGET.md) for the budget
and investigation guidance.

## Top contributing crates

\`\`\`
${BLOAT_OUTPUT}
\`\`\`

## Dry-run gzip size

To measure the actual deployed gzip size:

\`\`\`bash
wrangler deploy --dry-run --outdir bundled/
gzip -c bundled/*.js | wc -c
\`\`\`
MDEOF

echo "Wrote: $OUT_FILE"
