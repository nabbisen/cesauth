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
    -p cesauth-backend --crates 2>&1 | head -40
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

---

## Frontend CSR bundle (separate budget — RFC 130 S4)

**This is a different artifact from the Worker bundle above.** The table above
is `cesauth-backend`'s Worker script, gated by `bundle-size.yml` against
Cloudflare's *Worker script* size ceiling. The numbers below are the Leptos
CSR browser bundle (`cesauth-frontend`, built by `make build-frontend` /
`trunk build --release`), served from Workers Static Assets and downloaded
by the *browser*, not evaluated as a Worker script. There is currently no
CI budget gate on this bundle — RFC 130 recorded the first real measurement;
introducing a gate is a separate decision.

**These figures are environment-sensitive, not invariants.** RFC 130 S4
recorded 879,980 / 750,151 / 262,744 bytes on one host. Rebuilding the
*identical* commit on a different host (condition C1-0.81.2) produced the
table below instead — a fixed ~1.5 KB shift, not run-to-run noise: three
consecutive builds on the C1-0.81.2 host, including a forced
`cargo clean -p cesauth-frontend`, all produced a byte-identical artifact
(same sha256). The build is **run-reproducible but not
environment-reproducible**; see RFC 133, which owns closing that gap. Do not
treat either host's numbers as the "correct" one — record what the tagged
commit measures on the host that tags it, qualified as below.

Current measurement (0.81.2 tag, C1-0.81.2 correction):

| Artifact | Raw size | Gzip size |
|---|---:|---:|
| `cesauth-frontend_bg.wasm`, pre-`wasm-opt` | 881,519 bytes (860.9 KiB) | — |
| `cesauth-frontend_bg.wasm`, post-`wasm-opt -Oz` | 751,714 bytes (734.1 KiB) | 261,502 bytes (255.4 KiB) |
| `cesauth-frontend.js` (loader/glue) | 49,690 bytes (48.5 KiB) | 8,499 bytes (8.3 KiB) |
| **Total, post-opt, gzip** | — | **270,001 bytes (263.7 KiB)** |

`wasm-opt -Oz` saves **14.7%** raw size (881,519 → 751,714) on this host —
consistent with the RFC 130 S4 measurement's savings ratio even though the
absolute bytes differ, which is more evidence the shift is environmental
rather than a change in what is being compiled.

Measured on: rustc 1.98.1 (`rust-toolchain.toml`, RFC 130 M2), Trunk 0.21.14,
Binaryen `version_123` (fetched by `Makefile`'s `wasm-opt-fetch` target — see
RFC 130 S1 for why Trunk's own `wasm-opt` invocation cannot be used as-is),
Linux 7.2.3. Reproduce with `make build-frontend` then
`ls -la crates/frontend/dist/` / `gzip -c <file> | wc -c` — but expect the
absolute bytes to be host-sensitive per the note above; a differing number is
not by itself evidence of a broken build.
