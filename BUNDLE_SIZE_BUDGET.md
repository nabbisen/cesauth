# Worker Bundle Size Budget

This document records the current bundle size, the declared budget, and
guidance for investigating regressions.  It is the companion to
`.github/workflows/bundle-size.yml` (RFC 025).

## Current state

| Metric | Value | Date |
|---|---|---|
| Gzip size | 811,575 bytes (30% of budget): `index_bg.wasm` 800,877 + `shim.js` 10,698, per-file `gzip -c`, CI run 35930160578 on `f9d450a`. Wrangler's own line for the same upload: `Total Upload: 2190.98 KiB / gzip: 800.32 KiB` | 2026-09-23 |
| Budget | 2.5 MiB (2 621 440 bytes) | RFC 025 |
| Plan ceiling (Free) | 3.0 MiB | Cloudflare docs |
| Plan ceiling (Paid) | 10.0 MiB | Cloudflare docs |

> **Note**: this is the first real measurement. Before RFC 142 the CI gate
> could not run (it needed the frontend's `dist/`), and once it could it
> measured `shim.js` alone (10,698 bytes, "0%"). Replace the row above from the
> `Check bundle gzip size` step output whenever it is re-measured.

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
# The Worker's code is the *_bg.wasm module, not the shim.js loader beside it
# (RFC 142: the CI gate used to gzip only the first .js, ~10 KB of ~800 KB).
# Sum every module; source maps and README.md are not uploaded modules.
for f in bundled/*.js bundled/*.wasm; do gzip -c "$f" | wc -c; done | paste -sd+ | bc
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
table below instead — a fixed ~1.5 KB shift.

**The build is not reproducible, and an earlier version of this section said
it was reproducible from one run to the next. That was false.** The property
that does hold is narrower, and it is about *recompilation*: **a rebuild that
recompiles nothing re-emits the same file; a rebuild that recompiles may not.**
The evidence, from RFC 133:

- **Two clean rebuilds of one commit, minutes apart, in one shell session, on one
  host, differed** (§2.2): after `cargo clean -p cesauth-frontend` and
  `make build-frontend`, 753,093 bytes (`f07a27b0…`), then 753,095 bytes
  (`1b539cd2…`). The C1-0.81.2 observation above, three consecutive builds
  including a forced `cargo clean -p cesauth-frontend` agreeing, was **one
  occasion on which they agreed, not a guarantee**.
- **Four release-scale confirmations at unchanged frontend source** (§11), each
  `du -b` + `gzip -c | wc -c` + `sha256sum`:

  | Between | Size | Result |
  |---|---|---|
  | 0.83.1 cut → 0.84.0 cut (version bump) | 753,095 → 753,094 | −1 byte, different hash |
  | 0.84.0 cut → 0.84.1 cut (version bump) | 753,094 → 753,312 | +218 bytes, different hash |
  | 0.84.1 cut → 0.84.2 readiness (no version change) | 753,312 → 753,312 | byte-identical, `sha256 9f8f0f1c…` |
  | 0.84.1 → 0.84.2 cut (version bump) | 753,312 → 753,092 | −220 bytes, different hash |

  The variable is not the version string (RFC 133 §2.2 reverted it and got the
  same bytes); it is **whether the frontend crate was recompiled**. A workspace
  version bump changes `CARGO_PKG_VERSION`, a fingerprint input, and forces the
  recompile; a rebuild at an unchanged version finds every unit fresh. The deltas
  are not monotonic (−1, +218, −220).

What this means for a reader: **the artifact's hash is not a function of the
source.** Record it; do not compare it as an invariant, and do not treat either
host's numbers as the "correct" one. Record what the tagged commit measures on
the host that tags it, qualified as below.

What is and is not established (RFC 133 half A): the build *step* is now a
function of its input (`dist/` is cleared first, and `wasm-opt` never reads and
writes one path), and `wasm-bindgen` 0.2.128 was measured **deterministic**
(two runs over one `cargo` output gave byte-identical output). So whatever
varies arises **before** `wasm-bindgen`, in what `cargo`/`rustc` emit when the
crate is recompiled. **That cause is not identified**, and making the build
environment-reproducible (a pinned image, path remapping, a fixed epoch) is
deferred to 1.0 hardening; RFC 133 owns both.

Current measurement (0.81.2 tag, C1-0.81.2 correction). **Gzip figures are
`gzip -9 -c <file> | wc -c`** — a gzip size without a stated level is not a
measurement (condition C2-0.81.2):

| Artifact | Raw size | Gzip size (`-9`) |
|---|---:|---:|
| `cesauth-frontend_bg.wasm`, pre-`wasm-opt` | 881,519 bytes (860.9 KiB) | — |
| `cesauth-frontend_bg.wasm`, post-`wasm-opt -Oz` | 751,714 bytes (734.1 KiB) | 261,502 bytes (255.4 KiB) |
| `cesauth-frontend.js` (loader/glue) | 49,690 bytes (48.5 KiB) | 8,499 bytes (8.3 KiB) |
| **Total, post-opt, gzip** | — | **270,001 bytes (263.7 KiB)** |

`wasm-opt -Oz` saves **14.7%** raw size (881,519 → 751,714) on this host —
consistent with the RFC 130 S4 measurement's savings ratio even though the
absolute bytes differ, which is more evidence the shift is environmental
rather than a change in what is being compiled.

**The RFC 130 S4 gzip figures (262,744 / 8,650 / 271,394) used the default
gzip level (`-6`), not `-9`.** Only the raw sizes are directly comparable
across the two measurements — the gzip figures differ partly by host and
partly by method, and conflating the two looks like the bundle compressing
worse when the host changed, which is not what happened. Proof: the js *raw*
size above is unchanged at 49,690 bytes across both measurements; identical
bytes cannot compress to two different sizes under one method, so its
recorded gzip figure moving (8,650 → 8,499) is entirely a level change, not
an environment effect.

Measured on: rustc 1.98.1 (`rust-toolchain.toml`, RFC 130 M2), Trunk 0.21.14,
Binaryen `version_123` (fetched by `Makefile`'s `wasm-opt-fetch` target — see
RFC 130 S1 for why Trunk's own `wasm-opt` invocation cannot be used as-is),
Linux 7.2.3. Reproduce with `make build-frontend` then
`ls -la crates/frontend/dist/` / `gzip -9 -c <file> | wc -c` — but expect the
absolute bytes to be host-sensitive **and recompile-sensitive** per the notes
above; a differing number is not by itself evidence of a broken build.
