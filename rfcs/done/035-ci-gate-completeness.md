# RFC 035 — CI gate completeness

**Status**: Implemented  
**Priority**: P1 (release gate deficit)  
**Size**: Medium (4 new workflows)  
**Depends on**: RFC 029 (fmt workflow already added)

## Problem

Current CI covers: fmt, bundle-size, route-contracts, audit, drift-scan, fuzz.
Missing per the development instructions release gate:

1. `cargo test --workspace --lib` — no host test runner in CI
2. `cargo clippy --workspace --all-targets -D warnings` — no lint gate
3. wasm32 release build / `worker-build` — adapter-cloudflare buildability
4. `cargo deny` — license/advisory check
5. `bundle-size.yml` uses `stable` toolchain, not `rustc-1.91`

## Decision

Add four workflows:

- `.github/workflows/test.yml` — `cargo-1.91 test -p cesauth-core -p cesauth-adapter-test -p cesauth-ui -p cesauth-migrate-test`
- `.github/workflows/clippy.yml` — `cargo-1.91 clippy --workspace -D warnings` (excluding WASM crates)
- `.github/workflows/deny.yml` — `cargo deny check`
- Update `bundle-size.yml` to use `dtolnay/rust-toolchain@1.91.x` or the apt package

WASM build CI is deferred until `MagicLinkMailer` dyn issue is resolved (RFC 031).
