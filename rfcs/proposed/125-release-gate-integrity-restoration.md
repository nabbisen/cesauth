# RFC 125 — Release-gate integrity restoration

**Status.** Proposed
**Tier.** P0 · Category A (blocks the assurance track)
**Size.** Small–Medium (mechanical; no domain logic)
**Tracks.** Architect review of the v0.81.0 handoff bundle. Amends the
conclusion of RFC 029; repairs the gates RFC 035 introduced and the
route-contract gate from RFC 027.
**Touches.** `.github/workflows/{fmt,test,clippy}.yml`,
`scripts/route-contracts-check.sh`, `deny.toml`, root `Cargo.toml`
(comment), `crates/core/src/types/ids.rs` (module doc only),
`crates/core/src/migrate/tests/import_pipeline.rs`, `Cargo.lock`,
`rfcs/` (portfolio state), release-evidence policy.
**Depends on.** Nothing. Everything below is independent of RFCs 117–124.
**Blocks.** RFC 117 and every later assurance RFC, all of which name
"full host suite green" as the gate between steps.

## 1. Summary

Restore the project's automated release gates to a state where they run,
reflect declared policy, and produce reproducible evidence. Four of nine
workflows currently fail at invocation or enforce a rule the codebase has
never satisfied. Until they run, the acceptance criteria of RFCs 117–124
are unenforceable, and the v0.81.0 evidence bundle contains one claim that
could not have been produced by the toolchain it names.

## 2. Motivation

The assurance track (116→124) is built on a stated discipline: *"a full
`cargo test` pass on `cesauth-core`, `cesauth-adapter-test`, and
`cesauth-migrate-test` is the gate between steps"* (audit report §5). That
gate is not running in CI, and has not since the v0.79/v0.80 crate rename.
Adding nine RFCs' worth of security-critical type and lifecycle work on top
of a dead gate inverts the intent of the whole track.

Separately, `evidence/cargo-fmt.log` in the v0.81.0 handoff bundle is an
80-byte prose sentence asserting `exit 0, no diffs (clean)` under rustc
1.96.0, while its sibling logs are genuine multi-thousand-line captured
output. The assertion is not merely unverified — it is not reproducible
under any stable rustfmt (see §5). Workflow policy §11.1 forbids reporting
unexecuted checks as successful; this RFC fixes the underlying gate and
closes the process hole that let a hand-written claim enter an evidence
bundle.

## 3. Background

Measured on this tree (rustc 1.98.0, working tree clean):

| Gate | Declared | Actual |
|---|---|---|
| `test.yml` | host tests | **fails at invocation** — `-p cesauth-ui` |
| `clippy.yml` | lint | **fails at invocation** — `-p cesauth-ui` |
| `route-contracts.yml` | RFC 027 contract | **exit 2** — reads `crates/worker/src/lib.rs` |
| `fmt.yml` | `cargo fmt --all --check` | **exit 1** — 4,568 hunks, 447/498 files |
| `deny.yml` | advisories | **advisories FAILED** — RUSTSEC-2026-0190 |
| `audit.yml`, `drift-scan.yml`, `bundle-size.yml`, `fuzz.yml` | — | not contradicted |

`cesauth-ui` was renamed `cesauth-frontend` and `cesauth-worker` renamed
`cesauth-backend` by the RFC 114 workspace restructure. The rename did not
reach the workflows, `scripts/`, `deny.toml`, or the root `Cargo.toml`
comment block.

Consequence: `cesauth-frontend` — 15,468 lines and **280 passing tests** —
has had no CI coverage at all since the rename, and is also absent from the
gate list documented in the handoff's `ops-security.md`. The real host suite
is **1,233 tests**, not the 953 the bundle reports.

## 4. Target code areas

- `.github/workflows/test.yml` — package list.
- `.github/workflows/clippy.yml` — package list and severity policy.
- `.github/workflows/fmt.yml` — removal (see §6, D1).
- `scripts/route-contracts-check.sh` — input path + missing-input diagnostic.
- `deny.toml` — `[graph] exclude` crate name.
- Root `Cargo.toml` — stale test-command comment.
- `crates/core/src/types/ids.rs` — module doc (§6, D6).
- `crates/core/src/migrate/tests/import_pipeline.rs` — `never_loop`.
- `Cargo.lock` — `anyhow` ≥ 1.0.103.
- `crates/ui/`, `crates/worker/` — empty rename skeletons.
- `rfcs/proposed/116-…` → `rfcs/done/` + `rfcs/README.md`.

## 5. The formatting decision, with evidence

RFC 029 deleted `rustfmt.toml` on a measurement that the codebase formatted
identically to rustfmt defaults. That measurement no longer holds, and
restoring the file does **not** recover it:

| Configuration | Diff hunks |
|---|---|
| No `rustfmt.toml` (current) | 4,568 |
| `use_small_heuristics = "Max"` restored | 4,347 (−4.8 %) |

The residual is hand-aligned columns — `_env:  Env`,
`family_id:     &crate::types::FamilyId`. The only rustfmt option that emits
column alignment is `struct_field_align_threshold`, which is **nightly-only**;
stable rustfmt refuses it (`unstable features are only available in nightly
channel`). Therefore no stable rustfmt, at any version, can produce or accept
this tree. This is not toolchain drift, and it is not configurable away.

The choice is binary: reformat 447 of 498 files, or stop enforcing a rule the
project does not follow.

## 6. Proposed design

**D1 — Remove `fmt.yml`; record hand-alignment as house style.**
Column alignment is load-bearing in the port signatures and in RFC 116's own
new code, where aligned parameter lists are what make a transposition visible
to a reviewer. A gate that has never once passed provides no signal. Document
the choice in `docs/src/expert/` and amend RFC 029's conclusion by reference.
*Reversal path:* if the owner prefers uniformity, a single mechanical
reformat commit replaces this decision; §9 keeps that option open.

**D2 — `-p cesauth-ui` → `-p cesauth-frontend`** in `test.yml` and
`clippy.yml`. Add `-p cesauth-migrate-test` to the clippy list for parity.

**D3 — `route-contracts-check.sh`:** point `LIB_RS` at
`crates/backend/src/lib.rs`; add an explicit existence check that fails with
a named diagnostic rather than a raw `grep:` error, so a future rename
produces an actionable message instead of exit 2.

**D4 — Align clippy CI with declared policy.** `ops-security.md` declares
clippy advisory; `clippy.yml` enforces `-D warnings`. Reconcile in the
direction of the declared policy, but keep real defects blocking: drop
`-D warnings`, add `-D clippy::correctness`. Fix the one deny-level hit
(`never_loop`, `crates/core/src/migrate/tests/import_pipeline.rs:87`). The
remaining 106 style warnings become a tracked cleanup, not a release blocker.

**D5 — Add `-p cesauth-frontend`** to `test.yml` and to the documented gate
list, and correct the stated suite size to 1,233.

**D6 — Correct `crates/core/src/types/ids.rs` module doc.** Lines 11 and 22
describe `mint()` and `from_storage()` as `pub(crate)`; both are `pub`. The
same bullet then states "adapters use this at the read boundary," which
`pub(crate)` would forbid — the doc contradicts itself as well as the code.
This matters because `from_storage()` **skips validation**: a reviewer
trusting the doc concludes the unvalidated constructor is unreachable from
`crates/backend` route code. It is not. Describe both as `pub` and state
plainly why.

**D7 — `deny.toml`:** `cesauth-worker` → `cesauth-backend`, so the WASM-only
crate is actually excluded as intended.

**D8 — `cargo update -p anyhow`** to ≥ 1.0.103 (RUSTSEC-2026-0190,
unsoundness in `Error::downcast_mut`). Reached only via `cesauth-migrate`, a
host-only CLI; not in the Worker binary. Low exposure, trivial fix, red gate.

**D9 — Delete the empty `crates/ui/` and `crates/worker/` skeletons.**

**D10 — Refile RFC 116** to `rfcs/done/` with `Status. Implemented (v0.81.0)`
and update `rfcs/README.md`. Portfolio maintenance; performed by the
architect, not the implementer.

**D11 — Evidence policy.** Every file under a release bundle's `evidence/`
must be redirected command output (`cmd > log 2>&1`), never authored prose.
A bundle containing a hand-written result is rejected at review.

## 7. Non-goals

- Rewriting RFC 110a and 112 against the current crate layout (both reference
  paths and files that no longer exist; separate work).
- Mockup / `cesauth-ui` integration.
- RFC 000 vs 019 supersession and the `accepted/`/`archive/` folders.
- Adopting `ports::repo` newtypes or tenant scoping — that is RFC 119.
- Any change to domain logic, wire formats, storage, or public API.

## 8. Data model / API impact

None. No wire format, D1 schema, DO payload, cookie, or public `core` type
changes. `ids.rs` changes are documentation only.

## 9. Testing strategy

1. `cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-migrate-test -p cesauth-frontend`
   — expect **1,233 passed, 0 failed**.
2. `cargo check -p cesauth-backend --target wasm32-unknown-unknown` — clean.
3. `cargo clippy … -- -D clippy::correctness` — zero errors.
4. `cargo deny check` — all four sections `ok`.
5. `bash scripts/route-contracts-check.sh` — exits 0 **and** prints a
   non-zero route count. A zero count is a failure, not a pass.
6. Every log in §9 captured by redirection and attached as evidence.

Item 5 is deliberate: the current script would have reported success on an
empty input had `set -e` not aborted it first. The count assertion removes
that failure mode permanently.

## 10. Migration / rollout

Single patch release **v0.81.1**, internal-only, no consumer-visible change.
Ordering: D2/D3/D5 (make gates runnable) → D4/D8 (make them green) → D1/D6/D7/D9
→ D10. Land as one reviewable unit; each step is independently revertible.

## 11. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Dropping `fmt.yml` reads as lowering standards | Perception; future drift | Record the rationale in `docs/`; §5 evidence makes the alternative explicit; reversible by one reformat commit |
| Turning gates on reveals further breakage | Schedule slip before RFC 117 | Preferable to discovering it during an assurance RFC; all failures are surfaced by §9 before merge |
| `anyhow` bump shifts transitive deps | Build churn | Host-only crate; `Cargo.lock` committed; §9 item 1 covers it |
| `clippy::correctness` blocks a future PR | Friction | That is the intent; correctness lints are defects, not style |

## 12. Acceptance criteria

1. All nine workflows pass on a push to a branch off `main`.
2. `route-contracts-check.sh` exits 0 with a non-zero route count.
3. `cargo deny check` reports `advisories ok, bans ok, licenses ok, sources ok`.
4. Host suite reports 1,233 passed, 0 failed; wasm32 check clean.
5. No package-name or crate-path string in `.github/`, `scripts/`,
   `deny.toml`, or root `Cargo.toml` refers to `cesauth-ui`, `cesauth-worker`,
   `crates/ui`, or `crates/worker`.
6. `ids.rs` module doc matches declared visibility.
7. RFC 116 is in `done/` with a version-stamped Status; `rfcs/README.md` agrees.
8. Every evidence file is captured output.

## 13. Open questions

1. ~~**`fmt.yml`: remove or reformat?**~~ **Resolved — owner decision:
   remove.** `fmt.yml` is deleted and hand-alignment is recorded as house
   style; no source file is reformatted. Rationale as recorded at decision
   time: a gate that has never once passed provides no signal, and the
   alignment it would destroy is load-bearing in the port signatures where
   argument transposition is the very bug class RFC 116 exists to prevent.
   This amends RFC 029's conclusion — that RFC deleted `rustfmt.toml` on a
   measurement of "codebase formats identically to defaults" which §5 shows
   no longer holds and cannot be recovered by configuration. Reversal path
   stays open: one mechanical reformat commit plus restoring the workflow.
2. **Release-record reconciliation.** `0.79.6` is tagged with no CHANGELOG
   entry; `0.78.13`, `0.79.7`, `0.64.0`, `0.50.3` have entries but no tag.
   `0.78.13` is the declared baseline of *both* governing specs, so the tree
   those documents describe cannot currently be checked out. Retro-tagging
   needs owner confirmation of which commit is authoritative; deferred out of
   this RFC rather than guessed.
3. Should the 106 residual clippy warnings get a numbered cleanup RFC, or be
   absorbed opportunistically?
