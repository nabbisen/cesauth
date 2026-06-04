# Worker Bundle Size Budget

This document records the current bundle size, the declared budget, and
guidance for investigating regressions.  It is the companion to
`.github/workflows/bundle-size.yml` (RFC 025).

## Current state

| Metric | Value | Date |
|---|---|---|
| Gzip size | _run `scripts/bundle-bloat.sh` to measure_ | — |
| Budget | 2.5 MiB (2 621 440 bytes) | RFC 025 |
| Plan ceiling (Free) | 3.0 MiB | Cloudflare docs |
| Plan ceiling (Paid) | 10.0 MiB | Cloudflare docs |

> **Note**: The first measurement should be recorded here when the CI job
> runs for the first time on this branch.  Replace the placeholder above
> with the actual numbers from the `Check bundle gzip size` step output.

## Budget rationale

The 2.5 MiB soft cap leaves 500 KiB headroom below the Free-plan ceiling.
This allows one typical feature release to land without immediately hitting
the Free-plan limit.  cesauth targets **Paid plan** deployments
(see `docs/src/deployment/preflight.md`), but we keep the gate conservative
so contributions from developers testing on Free plan surface size regressions
early.

To **raise the budget** deliberately:

1. Update the `BUDGET=...` value in `.github/workflows/bundle-size.yml`.
2. Update the table above with the new budget, the reason, and the date.
3. Include `scripts/bundle-bloat.sh` output showing the top-contributing
   crates so reviewers can make an informed call.

## Investigating a size regression

### Quick path: cargo bloat

```bash
# Requires: cargo install cargo-bloat
cargo bloat --release --target wasm32-unknown-unknown \
    -p cesauth-worker --crates 2>&1 | head -40
```

Look for the largest newcomers in the crate list.  Common causes:
- A new `serde_json` version pulling in a larger set of formatters.
- A dependency that added a proc-macro generating code.
- A `features = [...]` change pulling in more of a large crate.

### Dry-run bundle locally

```bash
# Produces bundled/ without uploading.
wrangler deploy --dry-run --outdir bundled/
gzip -c bundled/*.js | wc -c
```

### Top-N contributing crates snapshot

See `docs/src/expert/bundle-composition-snapshot.md` for the most recent
snapshot.  Re-generate with:

```bash
bash scripts/bundle-bloat.sh
```

## Size history

| Version | Gzip size | Date | Notes |
|---|---|---|---|
| v0.53.x | _TBD_ | — | RFC 025 baseline measurement |
