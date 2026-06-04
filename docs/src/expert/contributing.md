# Contributing to cesauth

This document covers the day-to-day mechanics of contributing code or
documentation to cesauth.  For project philosophy and architecture, see
[`architecture.md`](architecture.md).

## Prerequisites

- Rust 1.91 (stable).  The apt package is `rustc-1.91` / `cargo-1.91`.
- For worker builds: `worker-build` (`cargo install worker-build --locked`)
  and `wrangler` (`npm install -g wrangler`).
- For docs: `mdbook` (`cargo install mdbook`).

## Code formatting

cesauth uses `rustfmt` defaults for the Rust 2024 edition.

**There is no `rustfmt.toml`** (RFC 029 confirmed the codebase formats
cleanly under defaults; the config file was removed).

Run before each PR:

```bash
cargo fmt --all
```

CI verifies this via `cargo fmt --all -- --check` (`.github/workflows/fmt.yml`).

If your editor's rustfmt integration produces different output, ensure it
is using the same edition.  In VS Code / rust-analyzer the workspace
edition is read from `Cargo.toml`; no extra configuration is needed.

> **Note on hand-aligned columns** — some struct initializers, match arms,
> and `use` lists use deliberate column alignment for readability alongside
> per-column comments.  `cargo fmt` at default settings preserves this
> alignment (that was validated in RFC 029).  If you add code in an
> alignment-sensitive block, eyeball `git diff` before committing to
> ensure `cargo fmt` didn't collapse the alignment.

## Running tests

```bash
# Host-compilable crates (fastest, no WASM toolchain needed)
cargo-1.91 test -p cesauth-core -p cesauth-adapter-test -p cesauth-ui --lib

# Migration chain integration tests
cargo-1.91 test -p cesauth-migrate-test --test migration_chain

# All host tests (excludes adapter-cloudflare and worker which need WASM)
cargo-1.91 test -p cesauth-core \
                -p cesauth-adapter-test \
                -p cesauth-ui \
                -p cesauth-migrate-test
```

## Adding a new route

When adding a route to `crates/worker/src/lib.rs`, also update
`docs/src/expert/route-contracts.md` with a row covering the six required
fields (actor, audit kind, view, rendering test, CSRF).  The CI check
`scripts/route-contracts-check.sh` (`.github/workflows/route-contracts.yml`)
will fail if the table is missing the new route.

## RFC lifecycle

New design decisions go in `rfcs/proposed/NNN-title.md` (RFC 019 documents
the lifecycle).  Current highest RFC number: 029.  Next RFC: 030.

When an RFC is implemented:
1. Move the file from `rfcs/proposed/` to `rfcs/done/`.
2. Update the RFC header `Status: Proposed` → `Status: Implemented`.
3. Add a CHANGELOG entry referencing the RFC.
4. Update `ROADMAP.md`'s Shipped table if it is a significant feature.
