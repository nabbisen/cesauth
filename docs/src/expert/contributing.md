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

# All host tests
cargo-1.91 test -p cesauth-core \
                -p cesauth-adapter-test \
                -p cesauth-frontend \
                -p cesauth-migrate-test

# The Worker crate and the Cloudflare adapter (RFC 136). Run without
# --lib so their doc-tests are covered too.
cargo-1.91 test -p cesauth-backend -p cesauth-adapter-cloudflare
```

Expect **1,233 passed, 0 failed** from the first command (RFC 125;
`cesauth-frontend`'s 280 tests were uncounted and had no CI coverage
before that release — see
`rfcs/done/125-release-gate-integrity-restoration.md` for how that
was found), and **199 passed** plus **1 passed** from the second.

Both of the latter crates were excluded from the gate until 0.83.0+,
with the stated reason that they "need WASM". **That reason was
false**, and RFC 136 is the correction: their tests compile and run on
the host like any other. The backend's 159 tests had accumulated 36
API-drift errors and the adapter's single test module was missing a
`tokio` dev-dependency, so neither crate's tests had been compiled —
let alone run — by anything, for at least two months. **No test in
either crate is wasm-only.** If one ever is, gate that test with
`#[cfg(target_arch = "wasm32")]`; do not re-exclude the crate.

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

### Choosing the version level

The question is **what kind of change this is**, not what part of the tree it
touched:

| Level | Means | In this project |
|---|---|---|
| **Patch** `X.Y.Z+1` | A backwards-compatible **fix**. Something was broken or wrong and now is not | 0.81.1 (four dead CI workflows repaired), 0.81.3 (documentation asserting the wrong storage backend) |
| **Minor** `X.Y+1.0` | Backwards-compatible **added functionality**. Something is now possible that was not | 0.81.0 (new public `core` types), 0.80.0 (Leptos components replacing the template layer), 0.79.0 (workspace restructuring) |
| **Major** | An incompatible change | Not yet reached; `1.0.0` needs owner confirmation *and* sufficient coverage |

cesauth is `0.y.z`, where SemVer formally permits anything to change at any
time. The distinction above is therefore a **project convention** rather than a
SemVer obligation — but the words keep their ordinary meaning, and a release
that adds capability is a minor even when no public type moved.

**The trap, recorded because it was walked into.** 0.81.2 was cut as a patch on
the reasoning that RFC 130 changed no public API. It produced a deployable
frontend bundle for the first time, pinned the toolchain, added a `wasm-opt`
pipeline step and added CI gates — new capability throughout, and no part of it
a fix. It should have been 0.82.0. "No public surface changed" is the
major/minor test; it says nothing about minor versus patch. Ask instead: *was
anything broken before, and is it now fixed?* If the honest answer is "nothing
was broken; this is new," it is a minor.

A release that mixes fixes and new capability takes the **higher** level.

### Every release must satisfy

- A tag exists **and** a CHANGELOG entry exists, for the same version. Neither
  alone is a release. Historical gaps in both directions exist — `0.79.6` was
  tagged with no entry; `0.78.13`, `0.79.7`, `0.64.0` and `0.50.3` have
  entries but no tag. `0.78.13` is the declared baseline of the governing
  requirements and external-design specs, so the tree those documents describe
  cannot be checked out. Do not add to this list.
- Version numbers are never reused, and a bad release is superseded by a new
  patch rather than re-tagged.
- The CHANGELOG heading's date is the **tag** date, not the date the candidate
  was first produced. 0.81.2 took three correction cycles between those two
  points, and the entry initially carried the earlier one.
- The full gate set (see [Running tests](#running-tests)) is green, with each
  result captured as redirected command output. A hand-written summary line is
  not evidence — a release bundle once shipped an 80-byte prose
  `cargo-fmt.log` asserting a clean run that no stable `rustfmt` could have
  produced.
- Version bumps require explicit owner confirmation; `1.0.0` requires
  confirmation *and* sufficient test coverage.

## Publishing to crates.io

**Only the name `cesauth` is published, and it holds nothing.**
[`crates.io/crates/cesauth`](https://crates.io/crates/cesauth) — version
`0.0.0`, Apache-2.0, published 2026-09-10 by the owner. It is a name
reservation with no API. `0.0.0` was chosen over `0.0.1` so the placeholder
reads as one and leaves `0.0.1` free if the name is ever used for real.

**The seven workspace crates are deliberately *not* published and *not*
reserved.** That is a decision, not an oversight:

- Reserving names a project does not intend to use is discouraged on
  crates.io, and a placeholder buys a weaker claim than a real published
  crate — names are first-come-first-served, and an unused name whose holder
  does not respond can be reassigned. Treat reservation as brand assurance,
  not as a security control.
- The name that would actually carry impersonation risk is **`cesauth-core`**
  — a genuine library, referenced throughout these docs, and the one someone
  might plausibly `cargo add`. The real protection for it is publishing it for
  real when there is a reason to, not holding it with a stub.

**Every workspace crate carries `publish = false`.** A crates.io token lives in
`~/.cargo/credentials.toml` on a machine where `cargo publish` is one command
away, and publishing is permanent — crates.io never deletes a version, only
yanks it. The guard makes publishing an explicit act rather than an accident.

If a crate is ever genuinely to be published, flip `publish` for **that crate
only**, deliberately, as part of the change that publishes it — never by
leaving it unset.
- **A readiness report states what would ship; it never contains the steps to
  ship it.** Authorization is the boundary between the two documents, so there
  is nothing executable to run early. 0.82.0 was tagged and pushed before the
  owner was asked, because the readiness report carried a numbered step list
  and a review pointed at it for "the exact steps" — an invitation, however it
  was worded elsewhere. Readiness answers *is it ready and what is outstanding*;
  the steps arrive in a separate dispatch that only exists once the owner has
  said yes.
- **The tag is the one step nobody but the owner authorizes.** Not the commits,
  not the CHANGELOG, not the RFC lifecycle moves — the tag. Say so explicitly
  in every document that discusses cutting, every time; a rule stated once in
  this file did not hold.
- **The version level is decided when the handoff is written, not at the cut,**
  and the handoff states it with its reasoning: which of the changes are fixes,
  which add capability, and therefore which level applies (see
  [Choosing the version level](#choosing-the-version-level)). Deciding it at
  tag time is how 0.81.2 went out as a patch — by then the work is done, the
  number feels settled, and nobody re-derives it. A level asserted without that
  reasoning is sent back.
