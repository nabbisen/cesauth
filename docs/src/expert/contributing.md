# Contributing to cesauth

This document covers the day-to-day mechanics of contributing code or
documentation to cesauth.  For project philosophy and architecture, see
[`architecture.md`](architecture.md).

## Prerequisites

- Rust, pinned by `rust-toolchain.toml` at the repo root (currently 1.98.1 —
  RFC 130 M2). `rustup` honours the pin automatically, so every command
  below is plain `cargo`. Do not install `rustc-1.NN` / `cargo-1.NN` apt
  packages; a versioned binary name bypasses the pin, which is how this
  file said 1.91 for two releases after CI moved to 1.98.1.
- For worker builds, install neither `worker-build` nor `wrangler` by hand
  (RFC 138). `wrangler.toml`'s `[build] command` installs
  `worker-build --version 0.8.4` itself, and `wrangler` is pinned by the
  repository root's `package.json`: run `npm ci` at the root, then invoke it as
  `node_modules/.bin/wrangler`. Use neither `npx wrangler` nor a global
  `npm install -g wrangler`. Without the root install, `npx` silently runs its
  cache's copy or fetches the latest release, and a global resolves whatever is
  installed — on the machine RFC 138 was measured on, 4.97.0 against the pinned
  4.131.2. The local binary does not run at all without the install, which is
  the point (RFC 138 C1-138).
- For docs: `mdbook` (`cargo install mdbook --version 0.5.4 --locked`).

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
# Every host crate — this is the command CI runs (.github/workflows/test.yml).
# No --lib: unit tests, integration targets and doc-tests all count.
cargo test -p cesauth-core \
                -p cesauth-adapter-test \
                -p cesauth-frontend \
                -p cesauth-backend \
                -p cesauth-adapter-cloudflare

# Migration chain integration tests
cargo test -p cesauth-migrate-test --test migration_chain
```

Expect **1,403 passed, 0 failed** from the first command — 789 core,
276 frontend (plus its 4 `acceptance_harness` integration tests), 200
backend, 133 adapter-test, 1 adapter-cloudflare, and 4 ignored
doc-tests. The `migration_chain` command adds **31**.

(RFC 125 found `cesauth-frontend`'s 280 tests uncounted with no CI
coverage — see `rfcs/done/125-release-gate-integrity-restoration.md`.)

**`--lib` was dropped in RFC 136 C2-136.** It had excluded two whole
classes repo-wide: doc-tests, and integration targets such as
`cesauth-frontend`'s `tests/acceptance_harness.rs`. Two doc-tests in
`cesauth-adapter-cloudflare` were failing the entire time — unannotated
` ``` ` fences in a module doc, which rustdoc compiles as Rust.

`cesauth-backend` and `cesauth-adapter-cloudflare` were themselves
excluded from the gate until 0.83.0+, with the stated reason that they
"need WASM". **That reason was false**, and RFC 136 is the correction:
their tests compile and run on the host like any other. The backend's
159 tests had accumulated 36 API-drift errors and the adapter's single
test module was missing a `tokio` dev-dependency, so neither crate's
tests had been compiled — let alone run — by anything, for at least two
months. **No test in either crate is wasm-only.** If one ever is, gate
that test with `#[cfg(target_arch = "wasm32")]`; do not re-exclude the
crate.

```bash
# wasm32 backend check (the only validation of the Worker build)
cargo check -p cesauth-backend --target wasm32-unknown-unknown

# Clippy — correctness lints are blocking; style is advisory
cargo clippy -p cesauth-core -p cesauth-adapter-test -p cesauth-migrate-test \
             -p cesauth-frontend -p cesauth-backend -p cesauth-adapter-cloudflare \
             --all-targets -- -D clippy::correctness

# Dependency advisories, licenses, bans, sources
cargo deny check

# Route-contract and stale-phrase checks (no Rust toolchain required)
bash scripts/route-contracts-check.sh
bash scripts/drift-scan.sh
```

### CI gate parity

The gates above, and the ones handoffs require for a release, are the
**described** gate set. What CI runs is a separate set of workflow files. Where
the two differ, the difference is recorded here as a decision rather than
discovered later (RFC 138). **No check blocks anything, by design.** CI runs
thirteen workflows on every push to `main` and reports; a fourteenth
(`fuzz.yml`) never triggers on a push at all, so it is not among them — see
*CI gate parity* below and RFC 156, which also checked in the list these
thirteen names are the `release` entries of (`.github/release-gate-manifest.json`)
and a check that fails if a future push's triggered set stops matching it.
Enforcing any of this would require a pull-request workflow this project does
not want, for the reasons in *How a change reaches `main`* below. Inspect what is
actually in effect with
`gh api repos/{owner}/{repo}/rules/branches/main`, which reports the rules from
every source — **not** `…/branches/main/protection`, which sees only legacy
branch protection and answers `404` even when a ruleset governs the branch
(RFC 142 §12).

| Gate (as described) | Where CI runs it | Difference |
|---|---|---|
| Host tests — the five-crate `cargo test` above | `test.yml` | none |
| `cargo test -p cesauth-migrate-test --test migration_chain` | `test.yml` | none |
| `cargo check -p cesauth-backend --target wasm32-unknown-unknown` | **no job of its own** | **Deliberate.** Covered in substance, and more strongly, by `worker-build.yml`'s `wrangler build`, which compiles the backend for wasm32 and builds the Worker |
| `cargo check -p cesauth-frontend --features csr --target wasm32-unknown-unknown` | `csr-bundle-check.yml` | none |
| `cargo clippy` over core, adapter-test, migrate-test, frontend, backend, adapter-cloudflare | `clippy.yml` | none. RFC 138 C1-138 added `cesauth-backend` and `cesauth-adapter-cloudflare` to both, closing a gap the two sets had shared |
| `unused_imports` / `unused_variables` denied in **`cesauth-backend` only** | none — it is a `#![deny(...)]` **crate attribute** at `crates/backend/src/lib.rs:30`, not a CI flag | **deliberate (RFC 157).** A command-line `-D unused_imports` on a `cargo clippy -p …` invocation denies the lint in that crate's workspace *dependencies* too, and `cesauth-core` carries pre-existing warnings this gate does not claim. The crate attribute reaches only the backend's own source — and travels with it, so a local `cargo build` enforces it as CI does. **Listed here because it is the one gate with no workflow of its own**, which is exactly the kind of gap RFC 138 exists to record |
| `cargo deny check` | `deny.yml` | Run through `EmbarkStudios/cargo-deny-action@v2.1.1` |
| `cargo audit` | `audit.yml` | Run through `rustsec/audit-check@v2.0.0`; also on a schedule |
| `bash scripts/drift-scan.sh` | `drift-scan.yml` | Runs with `--verbose`, on every pull request, no path filter |
| `bash scripts/route-contracts-check.sh` | `route-contracts.yml` | none |
| `mdbook build docs` | `docs.yml` | **Ran in no workflow before RFC 138.** `create-missing = false` makes a broken chapter link fail it |
| `make build-frontend` | `trunk-release-build.yml`; also a step in `worker-build.yml` and `browser-tests.yml` | CI adds an assertion that the built filenames match what `leptos_shell.rs` requests |
| `node_modules/.bin/wrangler build` | `worker-build.yml` (`worker-build` job) | none. **Runs and passes in CI** (first measured on `a0d49fa`, 2026-09-23; RFC 142). Reported, not enforced, not an enforced gate |
| `bash scripts/runtime-smoke-check.sh` | `worker-build.yml` (`runtime-smoke` job) | none. **Runs and passes in CI** (first measured on `3a88c20`, 2026-09-23; RFC 142); reported, not enforced. Its workflow builds the Worker in its own step before `wrangler dev` starts, because a cold compile outlasts the readiness deadline |
| `npx playwright test` in `e2e/`, against `node_modules/.bin/wrangler dev` | `browser-tests.yml` | **Blocking in intent since 0.84.0** (RFC 131 R5f) and **it runs on every push and passes** — but nothing is a required status check in this repository, so a failure reports rather than blocks (RFC 142 §14). The workflow carries no `continue-on-error` and must not. **Running it locally needs `npx playwright install` first** (`e2e/`); without it every test fails instantly with "browserType.launch: Executable doesn't exist …", and `browser-tests.yml` runs the install step itself, so CI is unaffected |
| — | `bundle-size.yml` | **CI-only.** A gzip budget on a `wrangler deploy --dry-run` bundle; not in the described set. Before RFC 142 it could not run (it needed the frontend's `dist/`) and, once it could, measured only the ~10 KB `shim.js` loader; it now sums every uploaded module (811,575 bytes gzip on `3a88c20`, 30% of the budget) |
| — | `release-gate-manifest.yml` | **CI-only, RFC 156.** Runs `scripts/release-gate-manifest-check.sh` against the Actions API for the pushed commit and fails if the triggered workflow set doesn't match `.github/release-gate-manifest.json`'s `release` list — the check for everything else in this section silently stopping |
| — | `fuzz.yml` | **CI-only, deliberately outside the release gate set (RFC 156 §4.1, recorded in the manifest's `not_on_release_path`).** Nightly-toolchain libFuzzer pass; runs on pull requests touching `crates/core/src/jwt/**` or `fuzz/**`, on a weekly schedule (added by RFC 156), or by manual dispatch — **never on a push**, so no release commit is covered by it. A fuzz run is non-deterministic; a release gate that can fail for reasons unrelated to the change under release would be a bad one |

**Not yet covered — local entry points that bypass the wrangler pin.**
`make build-backend` and `make dev-backend` (the `Makefile`), and
`scripts/bundle-bloat.sh`, call a bare `wrangler`, which resolves whatever is on
`PATH` rather than the root `package.json`'s pin. None of them is a CI gate. They
are recorded here, not changed: RFC 138's scope is the gates CI runs.

### Pinning tools in CI

A gate is only as reproducible as the tool it runs. The convention
(RFC 138 §11.8):

- **Actions that only orchestrate take a major tag** — `actions/checkout`,
  `actions/upload-artifact`, `actions/cache`, `actions/setup-node`. Their
  version does not decide any gate's verdict.
- **Actions that install and run a tool whose version decides a verdict take an
  exact version** — `rustsec/audit-check@v2.0.0`,
  `EmbarkStudios/cargo-deny-action@v2.1.1`, `cloudflare/wrangler-action@v3.15.0`
  (which also sets `wranglerVersion`). A moving major tag there can change a
  verdict with no commit to this repository.
- **`dtolnay/rust-toolchain@1.98.1` is a toolchain selector**, governed by
  `rust-toolchain.toml` (RFC 130). `@nightly` in `fuzz.yml` is deliberate.
- **Tools installed by command are pinned by version** — `cargo install … --version
  X --locked`, never `--locked` alone, which honours the *tool's* lockfile and
  still installs its latest release. Versions live in `DEPENDENCIES.md`.
- **npm-installed tools are pinned by a committed lockfile, and invoked from
  `node_modules/.bin/`.** Run `npm ci` at the root, then call
  `node_modules/.bin/wrangler`. Never `npx wrangler`: without the root install it
  does not fail — it silently runs the npx cache's copy, or in CI fetches the
  latest release (RFC 138 C1-138). The local binary does not exist without the
  install, so a forgotten `npm ci` fails loudly.

## How a change reaches `main`

**Commit on `main` and push. The default is no branch and no pull request.**

**A branch is not forbidden — it has to earn its cost.** The owner relays
between the architect and the implementer and never runs them concurrently, so
there is normally no concurrent work for a branch to isolate: it buys no
coordination while costing a push, a merge, and — depending on the merge method
— the commit's signature. Reach for one when it genuinely pays: work that must
not touch `main` until it is proven, or something the owner has said will run
alongside other work. Otherwise share `main`, which is what both the architect
and the implementer do.

**The gates are run before the push, not after.** Whoever makes the change runs
the set above and records the output; the reviewer re-runs the release-critical
ones independently. CI then runs all thirteen checks on the push and **reports**
the result. That is the honest description: CI is an independent second opinion,
not a gate that blocks.

**GitHub cannot enforce these gates in this workflow, and the reason is
structural.** A required status check can only pass on a commit that already
exists, so requiring checks on `main` means every change must arrive as a pull
request. That was tried on 2026-10-24 and reverted the same day: it bought no
coordination, and because a rebase merge rewrites commits without re-signing
them, it **replaced signed commits with unsigned ones** — a security property
traded for ceremony (RFC 142 §14). One unsigned commit remains in the history
from that experiment.

**What the rulesets do protect**, none of which needs a branch:

| Rule | Effect |
|---|---|
| Restrict deletions, block force pushes (on `main`) | `main` cannot be deleted or rewritten |
| Require linear history | No merge commits reach `main` |
| Restrict deletions, updates and force pushes (on **all tags**) | A tag cannot be moved or deleted, which makes "versions are never reused, and a bad release is superseded rather than re-tagged" enforced rather than merely documented |

**A convention that is *not* enforced:** tag names. Metadata rules
(`tag_name_pattern`, `commit_message_pattern`) are unavailable on this
repository — measured, not assumed — so "bare `X.Y.Z`, no `v` prefix" rests on
discipline. A tag-triggered workflow asserting the pattern would close that gap
(RFC 142 §13.1).

## Adding a new route

When adding a route to `crates/backend/src/lib.rs`, also update
`docs/src/expert/route-contracts.md` with a row covering the six required
fields (actor, audit kind, view, rendering test, CSRF).  The CI check
`scripts/route-contracts-check.sh` (`.github/workflows/route-contracts.yml`)
will fail if the table is missing the new route.

The same script's **E4** check (RFC 159) runs the other direction: every
handler-shaped `pub async fn` under `crates/backend/src/routes/` must be
reachable from `lib.rs`, either directly or through one level of
re-export (`pub use`, brace or renaming form) in the file that declares
`mod <leaf>;` for it. A handler written and never wired up fails the
check rather than sitting dead and undetected, which is what let nine
(then a tenth) slip through before this existed. E4 also asserts its own
coverage: a `pub async fn` under `routes/` that matches neither of the
two known handler signature shapes, and isn't named on
`NAMED_NON_HANDLERS` in the script with a reason, fails loudly instead of
being silently skipped — adding a genuinely new helper there means adding
it to that list, not just making the function compile.

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
- **The dev team runs the gate set for readiness; the architect re-runs the
  release-critical ones and any gate where a claim could hide.** Not the whole
  set twice. Owner's correction, 2026-09-12: the architect had run all fifteen
  gates by hand for 0.83.0's readiness while the implementer had already run
  most of them. Independent verification earns its keep by being aimed, not by
  being duplicated.
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
