# Developer Handoff — RFC 129, drift-scan coverage

**Governing RFC.** [`rfcs/done/129-drift-scan-coverage.md`](../../done/129-drift-scan-coverage.md)
**Target release.** 0.83.0 — **and why that level:** RFC 129 is a **patch**
(every item is a fix; nothing new becomes possible). It ships inside 0.83.0,
which is **minor**, because RFC 131 R5 adds the browser harness. This RFC is not
the reason for the level.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing.

---

## 1. Purpose

`drift-scan.sh`'s four crate-rename rules all exclude `crates/`, so the gate
that catches stale names cannot see them in the source. After this, it can — and
what the scan does and does not cover is a written decision instead of an
accident.

## 2. Why this matters

Not the stale text. **A gate reported clean while the thing it guards was
drifting.** Two instances were caught by hand in the last two releases (RFC 129
§2), both of which would otherwise have shipped. That is the same shape as every
serious defect found recently — `cargo check` proved compilation while the
router panicked; a 200 with headers proved the shell was served while its assets
404'd.

## 3. Resolved decisions — do not re-open

**`rfcs/` is not scanned. `CHANGELOG.md` is not scanned.** RFC 129 §11, both
ruled on acceptance: they are historical records, the same argument that
excludes ADRs. Record them in D5 as deliberate rather than leaving them out by
omission.

**`migrations/` is not scanned** (§4). `0008_audit_chain.sql` cites
`cesauth_worker::audit::EventKind` and that is **correct** for the version it
describes.

**The `cesauth-ui` rule is not re-scoped — it gets stronger** (§6). Remove its
hedge about the mockup's crate name and state that the name is wrong in this
tree under either meaning.

## 4. Facts already measured — do not re-derive

RFC 129 §2 is measured ground. The classifying command:

```sh
grep -rnE 'crates/worker|crates/ui|cesauth-worker|cesauth-ui' crates/
```

**25 hits, 24 files** — 19 dead pointers, 6 true historical statements, 1
broken command (counted within the 19).

*If your run differs, that is a finding — report the new count with the command
rather than adjusting silently. A count in prose is a measurement.*

## 5. The six are the whole job. Do not sweep them

The other nineteen are a rename. **These six are currently true**, and a
blanket substitution would make them false — inventing a history rather than
recording one:

```
crates/frontend/src/tenant_admin/tests/page_level.rs
crates/frontend/src/tenant_admin/tests/affordance_gating.rs
crates/frontend/src/tenant_admin/tests/mutation_forms.rs
crates/frontend/src/tenant_admin/tests/frame_invariants.rs
crates/frontend/src/tenant_admin/tests/design_tokens.rs
crates/frontend/src/tenant_admin/tests/membership_forms.rs
```

Each opens *"Originally part of `crates/ui/src/tenant_admin/tests.rs`. Split…"*
— accurate when written. Rephrase so the statement stays true **and** carries no
stale token:

> *Originally part of the pre-RFC-114 UI crate's `tenant_admin/tests.rs`,
> before it was renamed to `crates/frontend`.*

Confirm each of the six is genuinely this shape before rephrasing. If one turns
out to be a dead pointer wearing historical phrasing, treat it as Kind A and say
so.

## 6. Change scope

| # | Task | Files |
|---|---|---|
| D1 | Rename the 19 dead pointers; includes `crates/backend/Cargo.toml:19`'s `cargo test -p cesauth-worker` | ~18 files under `crates/` |
| D2 | Rephrase the 6 historical statements (§5) | the six named above |
| D4 | Add `ROADMAP.md` to `SCAN_PATHS` | `scripts/drift-scan.sh` |
| D5 | Document coverage: scanned, excluded-and-why, out-by-omission | `scripts/drift-scan.sh` |
| D3 | Drop `crates/` from all four rules' exclusion lists; de-hedge the `cesauth-ui` reason string | `scripts/drift-scan.sh` |

Order: **D1 → D2 → D4 → D5 → D3.** The gate widens **last**, so it lands green.

Run `bash scripts/drift-scan.sh` after D2 and before D3 — it must still be clean
with the old exclusions in place. If it is not, D1/D2 missed something.

## 7. Explicit non-change scope

- No behaviour changes. Doc comments, one `Cargo.toml` comment, and the scan
  script. **If your diff changes a line of executable Rust, something is wrong.**
- Do not add `migrations/`, `rfcs/`, or `CHANGELOG.md` to the scan (§3).
- Do not change the four rules' *patterns*, or their `docs/` exclusions.
- Do not touch RFC 131's work, RFC 133, or the assurance track.
- No `cargo fmt`. No route-string changes.

## 8. Assert the machine-checkable parts mechanically

```sh
# 1. no stale token remains anywhere under crates/ — the whole point
grep -rnE 'crates/worker|crates/ui|cesauth-worker|cesauth-ui' crates/ \
  && echo "FOUND — must be empty" || echo "clean"

# 2. crates/ is gone from every exclusion list
grep -n 'crates/' scripts/drift-scan.sh | grep -c 'exclude\|\\|crates/'   # state what this shows

# 3. no executable Rust changed
git diff --stat -- 'crates/**/*.rs' | tail -1     # and confirm by eye the diff is comments only
```

Attach all three. #1 must be empty, and it is the acceptance criterion.

## 9. Required tests and evidence

```sh
bash scripts/drift-scan.sh            > evidence/drift-scan.log 2>&1
bash scripts/route-contracts-check.sh > evidence/route-contracts.log 2>&1
mdbook build docs                     > evidence/mdbook.log 2>&1
cargo test -p cesauth-core -p cesauth-adapter-test \
           -p cesauth-migrate-test -p cesauth-frontend > evidence/cargo-test.log 2>&1
cargo check -p cesauth-backend --target wasm32-unknown-unknown > evidence/wasm32-check.log 2>&1
cargo check -p cesauth-frontend --features csr --target wasm32-unknown-unknown > evidence/csr-check.log 2>&1
cargo clippy -p cesauth-core -p cesauth-adapter-test -p cesauth-migrate-test \
             -p cesauth-frontend --all-targets -- -D clippy::correctness > evidence/cargo-clippy.log 2>&1
cargo deny check   > evidence/cargo-deny.log 2>&1
cargo audit        > evidence/cargo-audit.log 2>&1
bash scripts/runtime-smoke-check.sh   > evidence/runtime-smoke.log 2>&1
```

Expected: **1,233 passed, 0 failed**; route contracts **188**; runtime smoke
**all 10 checks**; everything else exit 0. Doc comments do not change the
bundle, so `make build-frontend` is not required — say so rather than omitting
it silently.

Plus, per RFC 129 §7:

- **D3 fires:** plant `crates/ui` in a `crates/` source file → red; remove →
  green. **This is the half that has never once happened** — the gate has never
  fired inside `crates/`.
- **D4 fires:** plant a stale phrase in `ROADMAP.md` → red; remove → green.
- Both halves each. Copy-based restore, never `git checkout` on a file with
  uncommitted work.

## 10. What must NOT be claimed

That documentation in `crates/` is now correct. This removes one *class* of
staleness — four renamed names — from one directory. `leptos_shell.rs` alone has
carried three different false claims across three cycles, none of which any of
these four patterns would have caught. The honest sentence is: "the four
crate-rename rules now cover `crates/`, and the 25 existing violations are
fixed."

## 11. Prohibited shortcuts

- No re-adding an exclusion to make the gate pass. If D3 surfaces hits §4 did
  not count, that is a finding — **report it**.
- No blanket `sed` across the 25. §5 exists because six of them must not be
  substituted.
- No `#[allow(...)]`, no `continue-on-error: true`.
- No `cargo fmt`.

## 12. Acceptance criteria

RFC 129 §9, items 1–7. Checked hardest: **item 2** (the six rephrased
statements are accurate — a human reads these; no command can check it) and
**item 6** (D3's pair, the first time this gate will ever have fired inside
`crates/`).

## 13. Known risks

RFC 129 §8. The one to watch: a Kind B statement renamed into a falsehood. §5
names all six explicitly so they cannot be swept by accident.

**If the work turns out materially larger than scoped, stop and report.**
Re-scoping is mine.

## 14. Review request

Write the package to `.git-exclude/review-request/`. It must include:

Implementation summary · changed files · the §4 count from **your** run with
its command · the six rephrased statements quoted in full, before and after ·
every log from §9 · the three §8 assertions · D3's and D4's fires/does-not-fire
pairs, all four halves · what remains unverified (§10) · requested review focus.

**Do not cut a release, bump a version, or create a tag.** This is
implementation only; 0.83.0 is cut separately, and the tag is the owner's
alone.

Report the path only.
