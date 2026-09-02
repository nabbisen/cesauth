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

**There is no `rustfmt.toml`, and there is no `cargo fmt` CI gate.**
Hand-aligned columns in security-sensitive signatures are house style —
see [Code style: hand-aligned columns](code-style.md) for the full
rationale (RFC 125 §5, amending RFC 029).

Do not run `cargo fmt --all` across the tree; it will collapse the
hand-alignment. If your editor format-on-saves a file you touch, check
`git diff` before committing and restore any alignment it destroyed.

## Running tests

```bash
# Host-compilable crates (fastest, no WASM toolchain needed)
cargo-1.91 test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend --lib

# Migration chain integration tests
cargo-1.91 test -p cesauth-migrate-test --test migration_chain

# All host tests (excludes adapter-cloudflare and backend, which need WASM)
cargo-1.91 test -p cesauth-core \
                -p cesauth-adapter-test \
                -p cesauth-frontend \
                -p cesauth-migrate-test
```

Expect **1,233 passed, 0 failed** (RFC 125; `cesauth-frontend`'s 280
tests were uncounted and had no CI coverage before this release — see
`rfcs/done/125-release-gate-integrity-restoration.md` for how that
was found).

```bash
# wasm32 backend check (the only validation of the Worker build)
cargo check -p cesauth-backend --target wasm32-unknown-unknown

# Clippy — correctness lints are blocking; style is advisory
cargo clippy -p cesauth-core -p cesauth-adapter-test -p cesauth-migrate-test \
             -p cesauth-frontend --all-targets -- -D clippy::correctness

# Dependency advisories, licenses, bans, sources
cargo deny check

# Route-contract and stale-phrase checks (no Rust toolchain required)
bash scripts/route-contracts-check.sh
bash scripts/drift-scan.sh
```

## Adding a new route

When adding a route to `crates/backend/src/lib.rs`, also update
`docs/src/expert/route-contracts.md` with a row covering the six required
fields (actor, audit kind, view, rendering test, CSRF).  The CI check
`scripts/route-contracts-check.sh` (`.github/workflows/route-contracts.yml`)
will fail if the table is missing the new route.

## RFC lifecycle

New design decisions go in `rfcs/proposed/NNN-title.md`. The lifecycle is
**RFC 000**, adopted 2026-09-03 in its 5-folder variant (RFC 000 supersedes
RFC 019, now in `rfcs/archive/`).  Current highest RFC number: 130.
Next RFC: 131.

The folder is the source of truth for an RFC's state; the `Status` field
mirrors it. Four folders carry RFCs:

| Folder | Meaning |
|---|---|
| `proposed/` | Under review. **Do not start implementing.** |
| `accepted/` | Owner approved. Implementation may start. |
| `done/` | Shipped — in a release, or merged to `main`. |
| `archive/` | Withdrawn or superseded. Never deleted. |

Transitions, each landing in a single commit that also updates
`rfcs/README.md` and sweeps inbound links:

1. **Owner accepts** → move `proposed/` → `accepted/`, Status `Accepted`.
2. **Shipped** → move `accepted/` → `done/`, Status `Implemented (vX.Y.Z)`,
   add a CHANGELOG entry, update `ROADMAP.md`'s Shipped table.
3. **Withdrawn or superseded** → move to `archive/`, Status carrying the reason
   or the replacing RFC number, with a reciprocal note in the replacement.

Numbers are permanent and never reused. A companion execution document may
live under `rfcs/handoffs/NNN-slug/`; it has no lifecycle state of its own and
inherits the RFC's. Use `rfcs/handoffs/TEMPLATE.md` as the starting point.

## Cutting a release

### Tag format

Release tags are **bare `X.Y.Z` with no `v` prefix** — `0.81.1`, never
`v0.81.1`. This follows the Rust crates convention and matches every existing
tag in the repository. `CHANGELOG.md` headings use the same bare form:
`## [0.81.0] - YYYY-MM-DD`.

Prose *references* to a version in `ROADMAP.md` and in RFC `Status` fields
conventionally keep the `v` (`Implemented (v0.73.0)`). That is a separate,
established style and is fine; the no-prefix rule is about tags and CHANGELOG
headings.

### Every release must satisfy

- A tag exists **and** a CHANGELOG entry exists, for the same version. Neither
  alone is a release. Historical gaps in both directions exist — `0.79.6` was
  tagged with no entry; `0.78.13`, `0.79.7`, `0.64.0` and `0.50.3` have
  entries but no tag. `0.78.13` is the declared baseline of the governing
  requirements and external-design specs, so the tree those documents describe
  cannot be checked out. Do not add to this list.
- Version numbers are never reused, and a bad release is superseded by a new
  patch rather than re-tagged.
- The full gate set (see [Running tests](#running-tests)) is green, with each
  result captured as redirected command output. A hand-written summary line is
  not evidence — a release bundle once shipped an 80-byte prose
  `cargo-fmt.log` asserting a clean run that no stable `rustfmt` could have
  produced.
- Version bumps require explicit owner confirmation; `1.0.0` requires
  confirmation *and* sufficient test coverage.
