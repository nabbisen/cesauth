# RFC 138 — The gate set we describe is not the gate set CI runs

**Status.** Proposed — needs owner authorization.
**Author.** Architect · **Date.** 2026-09-12
**Priority.** P1. No user-facing impact; it is the integrity of every claim this
project makes about being green.
**Target release.** After 0.83.0.
**Found by.** Surveying CI's tool installs in answer to a dev-team question
during RFC 131 C1-R5.

---

## 1. Summary

Every handoff in this programme lists a gate set, every review checks it, and
every release report asserts it green. **That list and CI's contents differ**,
and nobody had compared them. Two differences matter:

1. **`mdbook build docs` is in no workflow.** Twelve workflows, zero mentions.
   It has never run in CI.
2. **`npx wrangler` is unpinned** — no root `package.json` — at three sites,
   including the deploy-path gate.

This RFC makes the two sets equal, or makes each difference a recorded decision.

## 2. What is established

**The survey** (`grep` over `.github/workflows/*.yml` for install commands):

| Command | Sites | State |
|---|---|---|
| `cargo install trunk --version 0.21.14 --locked` | 4 | pinned (RFC 131 C1-R5) |
| `npm ci` | 1 | pinned by committed lockfile |
| `uses: rustsec/audit-check@v2.0.0` | 1 | **exactly** pinned |
| `uses: actions/*@v4`, `wrangler-action@v3`, `cargo-deny-action@v2` | 8 | major only |
| `cargo install cargo-fuzz --locked` | 1 | **unpinned** |
| `npx wrangler` | 2 (+1 in `scripts/`) | **unpinned** |

**Gate-set parity**, each gate grepped against the workflow directory:

| Gate (as handoffs list it) | In CI |
|---|---|
| `cargo test` host crates | `test.yml` |
| `cargo check --features csr` | `csr-bundle-check.yml`, `trunk-release-build.yml` |
| `cargo clippy -D clippy::correctness` | `clippy.yml` |
| `cargo deny` / `cargo audit` | `deny.yml` / `audit.yml` |
| `route-contracts-check.sh` | `route-contracts.yml` |
| `drift-scan.sh` | `drift-scan.yml` |
| `make build-frontend` | `worker-build.yml`, `trunk-release-build.yml`, `browser-tests.yml` |
| `runtime-smoke-check.sh` | `worker-build.yml` |
| `wrangler build` | `worker-build.yml` |
| `npx playwright test` | `browser-tests.yml` (non-blocking until 0.84.0) |
| **`mdbook build docs`** | **absent** |
| `cargo check -p cesauth-backend --target wasm32` | no dedicated job; covered in substance by `wrangler build` → `worker-build --release crates/backend` |

**`npx wrangler`'s sites:** `worker-build.yml:75` (`wrangler build` — the
deploy path), `browser-tests.yml:97` (`wrangler dev`, what R5's 20 tests run
against), `scripts/runtime-smoke-check.sh:55` (the runtime smoke gate, locally
and in CI). Local wrangler is **4.131.1**; nothing pins it.

## 3. Why each matters

**`mdbook` absent.** RFCs 128, 129, 132, 136 and RFC 131's cycles all landed
documentation whose only structural check was `mdbook build docs`, run by the
implementer and by the reviewer on their own machines. A `SUMMARY.md` entry
pointing at a deleted file, or a broken include, would reach `main` and no gate
would say so. It is the single most-invoked gate in this programme's paperwork
and the only one with no CI existence.

**`npx wrangler` unpinned.** Worse than the Trunk gap in one specific way:
**wrangler governs Workers Static Assets' default behaviour**, and a Static
Assets default is exactly what produced RFC 131 C1-131's finding that `/` was
served from `dist/index.html` ahead of the Worker. The fix — deleting that file
in `make build-frontend` — is a bet on behaviour that an unpinned tool may
change. It is also the tool that would perform a real deploy.

**The Actions convention.** `rustsec/audit-check@v2.0.0` is exactly pinned;
eleven others float within a major. Either is defensible; having both by
accident is not, and a floating major-version action is a supply-chain surface.

**The `wasm32` nuance, stated precisely:** the backend *is* compiled for wasm32
in CI, but only by `worker-build.yml` — a job that could not start before RFC
131 C1-R5. So that compilation has never actually happened in CI. Not a missing
gate; a gate whose first run is still ahead.

## 4. Non-goals

- Not adding gates that do not exist locally. This is parity, not expansion.
- Not pinning every GitHub Action to a SHA. §5 D4 asks for a *stated
  convention*; SHA-pinning is a bigger decision and its own RFC if wanted.
- Not `cargo-fuzz` beyond recording it: `fuzz.yml` is nightly by design and
  outside the gate set.
- Not re-litigating `browser-tests.yml`'s non-blocking window (RFC 131 R5 §8;
  it flips at 0.84.0).

## 5. The change

**D1 — Add the `mdbook` gate.** A workflow (or a step in an existing one)
running `mdbook build docs`, blocking. Pin `mdbook`'s version the way Trunk is
pinned, and add it to `DEPENDENCIES.md`'s pin table.

**D2 — Pin wrangler.** A root `package.json` with `wrangler` at an exact
version and its `package-lock.json` **committed**, so `npx wrangler` resolves
locally rather than fetching latest. Measure the installed version first and
pin what was measured (currently 4.131.1) — do not pin a version nobody has
built with. Record it in the pin table.

*Report before acting if a root `package.json` interferes with
`crates/frontend`'s Trunk build or `e2e/`'s own package — that is a layout
question and it is mine.*

**D3 — Make the pins self-enforcing.** Drift-scan rules that fire on the
regression rather than describing it:

- `cargo install trunk` **without** `--version`
- `npx wrangler` once D2 lands (should be plain `wrangler` via the lockfile, or
  `npx` with a pinned local install)

A pin recorded in a table rots; a pin a gate checks does not. This is the same
move as RFC 136's scanner self-check.

**D4 — State the Actions-pinning convention** in `contributing.md`: major-tag
or exact, with a reason, applied consistently. Then make the eleven match it.

**D5 — Put the parity table in `contributing.md`**, beside the gate list it
corresponds to, so "the gate set" has one definition and a reader can see which
gates run where. Where a gate is deliberately local-only, say so and why.

Order: **D1 → D2 → D3 → D4 → D5.** D3 after D1/D2 so it lands green.

## 6. Testing strategy

1. **D1 fires:** break the book (a `SUMMARY.md` entry pointing at a missing
   file) → the new gate red; restore → green.
2. **D3 fires:** remove `--version` from one Trunk install → drift-scan red;
   restore → green. Both rules, both halves.
3. `wrangler --version` reports the pinned version after D2, from a clean
   `npm ci`.
4. The existing gate set stays green.

## 7. Risks

| Risk | Mitigation |
|---|---|
| A root `package.json` disturbs the frontend or `e2e/` build | D2's report-first condition |
| The pinned wrangler is older than the tree was built with | Measure first, pin what was measured |
| The parity table becomes another rotting claim | D3 makes the pins checked; D5's table is small and sits beside the commands it describes |
| Pinning `mdbook` diverges from what contributors have | Same pattern as Trunk: record, and provide the bumping procedure |

## 8. Acceptance criteria

1. `mdbook build docs` runs in CI, blocking, with a fires/does-not-fire pair.
2. `npx wrangler` resolves a pinned version from a committed lockfile at all
   three sites; the version is the one measured, and it is in the pin table.
3. Drift rules for both pins, each with a pair.
4. The Actions-pinning convention is stated in `contributing.md` and the
   workflows match it.
5. The parity table is in `contributing.md`, and every difference between the
   described set and CI's set is either removed or recorded as deliberate.
6. Full gate set green.

## 9. Release level

**Patch.** Every item closes a gap between what is claimed and what runs;
nothing new becomes possible.

## 10. Open questions

1. **Should `mdbook` be blocking from the first run?** It has never run, so its
   first CI execution may find pre-existing breakage. My recommendation:
   **land it blocking anyway** — the local runs have been green every cycle, so
   a failure would be genuine news about the runner, not flake, and this project
   does not merge gates red. If it does fail, that is the finding.
2. **Is a root `package.json` acceptable** in a repository whose Node surface is
   otherwise confined to `e2e/`? It is the standard way to pin `npx`. The
   alternative — `npm install -g wrangler@<version>` in each workflow — pins
   equally but leaves `scripts/runtime-smoke-check.sh` unpinned for local runs.
   My recommendation is the root `package.json`; the owner may prefer the
   surface stay confined.
