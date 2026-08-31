# Developer Handoff — RFC 125, Release-gate integrity restoration

**Governing RFC.** [`rfcs/proposed/125-release-gate-integrity-restoration.md`](../../proposed/125-release-gate-integrity-restoration.md)
**Target release.** v0.81.1 (patch; internal-only; no consumer-visible change)
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. RFC 125 §13 Q1 is resolved (owner decision: remove
`fmt.yml`; do **not** reformat).

---

## 1. Purpose

Make the project's CI gates run, agree with declared policy, and emit
reproducible evidence. No domain logic changes.

## 2. Background

The RFC 114 workspace restructure renamed `cesauth-ui` → `cesauth-frontend`
and `cesauth-worker` → `cesauth-backend`. The rename did not reach the CI
workflows, `scripts/`, `deny.toml`, or the root `Cargo.toml` comment. Four
of nine workflows have been failing ever since, and `cesauth-frontend`
(15,468 lines, 280 tests) has had no CI coverage at all.

## 3. T1 — the formatting decision, already made

The owner has ruled: **delete `.github/workflows/fmt.yml`. Do not reformat
any source file.**

T1 is therefore two actions:

1. `git rm .github/workflows/fmt.yml`.
2. Add a short house-style note under `docs/src/expert/` recording that
   cesauth uses hand-aligned columns in security-sensitive signatures; that
   stable rustfmt cannot express this (`struct_field_align_threshold` is
   nightly-only, and `use_small_heuristics = "Max"` recovers only 4.8 % of
   the diff); and that this amends RFC 029's conclusion. Link RFC 125 §5.

**Do not** run `cargo fmt` anywhere in this work. If you believe a file needs
reformatting, that is a change request to the architect, not a local call.

## 4. Change scope

| # | Task | Files |
|---|---|---|
| T1 | Delete the fmt workflow + add house-style note (see §3) | `.github/workflows/fmt.yml` (removed), `docs/src/expert/` (new note) |
| T2 | `-p cesauth-ui` → `-p cesauth-frontend`; add `-p cesauth-migrate-test` to clippy | `.github/workflows/test.yml:27`, `clippy.yml:31` |
| T3 | Add `-p cesauth-frontend` to the host-test job | `.github/workflows/test.yml` |
| T4 | `LIB_RS` → `crates/backend/src/lib.rs`; add named existence check | `scripts/route-contracts-check.sh:21` |
| T5 | Assert non-zero route count before printing success | `scripts/route-contracts-check.sh` (success branch) |
| T6 | Drop `-D warnings`; add `-D clippy::correctness` | `.github/workflows/clippy.yml` |
| T7 | Fix `never_loop` | `crates/core/src/migrate/tests/import_pipeline.rs:87` |
| T8 | `cargo update -p anyhow` (≥ 1.0.103) | `Cargo.lock` |
| T9 | `cesauth-worker` → `cesauth-backend` | `deny.toml` `[graph] exclude` |
| T10 | Fix stale test-command comment | root `Cargo.toml` (~line 19) |
| T11 | Correct module doc: `mint()` / `from_storage()` are `pub`, not `pub(crate)` | `crates/core/src/types/ids.rs:11,22` |
| T12 | Delete empty rename skeletons | `crates/ui/`, `crates/worker/` |
| T13 | Update documented gate list + suite size (1,233) | `docs/src/expert/` gate documentation |

RFC 116 refiling (RFC 125 D10) is **already done** by the architect — do not
repeat it.

## 5. Explicit non-change scope

Do **not** touch, in this unit of work:

- Any file under `crates/core/src/{oidc,service,authz,session,audit}/` beyond
  T7 and T11.
- Wire formats, D1 schema, DO payloads, cookies, public `core` types.
- `ports::repo` — its `&str` signatures and missing tenant scoping are
  **RFC 119**, not this RFC. Leave them.
- The secret-newtype call-site adoption (RISK-001). Separate follow-up.
- RFC 110a / 112 path staleness. Separate work.
- Any mockup / `cesauth-ui` integration.
- `rfcs/` state beyond what §4 lists.

## 6. Task detail worth stating explicitly

**T5.** The current script would have printed `✅ All 0 routes are documented`
on an empty input had `set -euo pipefail` not aborted it first at the missing
`grep` target. Removing only the path bug re-arms that failure mode. The
success branch must fail when the extracted route count is zero.

**T11.** This is a security-boundary doc fix, not cosmetics. `from_storage()`
**bypasses validation**. The doc currently tells a reviewer it is `pub(crate)`
and therefore unreachable from `crates/backend` route code — it is `pub` and
fully reachable. The same bullet also says "adapters use this at the read
boundary," which `pub(crate)` would forbid; the doc contradicts itself. State
the real visibility and say why it must be `pub` (adapters and backend routes
are separate crates).

**T6.** The intent is to match declared policy (`ops-security.md`: clippy is
advisory) while keeping genuine defects blocking. `clippy::correctness` lints
are bugs, not style. The 106 residual style warnings are out of scope here.

## 7. Required tests and evidence

Run all of these and capture each by redirection:

```sh
cargo test -p cesauth-core -p cesauth-adapter-test \
           -p cesauth-migrate-test -p cesauth-frontend  > evidence/cargo-test.log 2>&1
cargo check -p cesauth-backend --target wasm32-unknown-unknown > evidence/wasm32-check.log 2>&1
cargo clippy -p cesauth-core -p cesauth-adapter-test -p cesauth-migrate-test \
             -p cesauth-frontend \
             --all-targets -- -D clippy::correctness      > evidence/cargo-clippy.log 2>&1
cargo deny check                                          > evidence/cargo-deny.log 2>&1
bash scripts/route-contracts-check.sh                     > evidence/route-contracts.log 2>&1
bash scripts/drift-scan.sh                                > evidence/drift-scan.log 2>&1
```

Expected: **1,233 passed, 0 failed**; wasm32 clean; zero clippy errors;
`cargo deny` reports all four sections `ok`; route-contracts exits 0 **with a
non-zero count**.

**Evidence policy (RFC 125 D11).** Every file in `evidence/` must be redirected
command output. A hand-written summary line is not evidence and will be
rejected at review — this rule exists because the v0.81.0 bundle shipped an
80-byte prose `cargo-fmt.log` asserting a result that no stable rustfmt could
have produced.

## 8. Prohibited shortcuts

- Do not `#[allow(...)]` the `never_loop` lint to make T7 pass. Fix the loop.
- Do not add `continue-on-error: true` to make a workflow appear green.
- Do not narrow a package list to dodge a failure.
- Do not run `cargo fmt` or reformat files opportunistically anywhere in this
  work. The owner has ruled against reformatting (§3); a stray `cargo fmt`
  would silently reverse that decision across 447 files.
- Do not mark a gate green in the review request without an attached log.

## 9. Acceptance criteria

RFC 125 §12, items 1–8. In particular: no string in `.github/`, `scripts/`,
`deny.toml`, or root `Cargo.toml` may still refer to `cesauth-ui`,
`cesauth-worker`, `crates/ui`, or `crates/worker`. Verify with:

```sh
grep -rn 'cesauth-ui\|cesauth-worker\|crates/ui\|crates/worker' \
     .github/ scripts/ deny.toml Cargo.toml
```

Expected: no matches. (`.github/CONTRIBUTING.md:35` also carries a stale
`cd crates/worker` — include it.)

## 10. Known risks

Turning gates on may reveal further breakage that has been masked since the
rename. That is the point; report what surfaces rather than working around it.
If a newly-live gate fails for a reason outside §4, stop and file an issue
report — do not expand scope to fix it.

## 11. Review request must include

Implementation summary · changed files · any deviation from §4 · the six logs
from §7 · the §9 grep output · unresolved issues · anything you want reviewed
closely.
