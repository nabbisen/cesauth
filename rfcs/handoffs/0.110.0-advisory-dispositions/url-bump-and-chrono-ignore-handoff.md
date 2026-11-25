# Developer Handoff — the two advisories get dispositions, and `audit.yml` stops claiming a file it has

**Target**: `0.110.0`, slice C of three · **Level**: minor (ships with A and B)
**Why now**: `0.109.0` shipped with `audit.yml` red for both of these.
A red check that stays red becomes a check nobody reads.
**Baseline**: `228eed1` / tag `0.109.0`

---

## 1. Purpose

`audit.yml` reports two things on every run and neither has a
disposition:

- **RUSTSEC-2026-0592** — `url` 2.5.8, stack overflow in
  `Url::origin()` on deeply-nested `blob:` URLs. A **vulnerability**.
- **RUSTSEC-2026-0543** — `chrono` 0.4.44 is unmaintained, dated
  **2026-09-14**, so it has been red for over two months. A
  **warning**, which is exactly why nobody rowed it until the
  `0.109.0` cut read the whole check output.

## 2. Resolved decisions — do not re-open

- **D1. `url`: take the patch bump.** `cargo update -p url --precise
  2.5.9` — verified by dry run to move exactly two crates, `url 2.5.8 →
  2.5.9` and `form_urlencoded 1.2.2 → 1.2.3`, inside the same minor.
  **My own ROADMAP row had this wrong** and called it *"a dependency
  bump with its own blast radius"* behind a reachability
  investigation; reading the advisory's own text corrected it, and the
  row now says so.
- **D2. The reachability investigation is dropped, not deferred.**
  `Url::origin()` is called nowhere in this codebase, and neither is
  `url::quirks::origin()` (the advisory's second entry point). The
  behavioural change in 2.5.9 — a `blob:` URL whose inner scheme is not
  `http`/`https`/`file` now returns an **opaque** origin instead of a
  tuple one — cannot affect code that never calls either. The right gate
  for an expensive fix is disproportionate for a cheap one.
- **D3. `chrono`: a dated ignore with a reason, not a bump.** `chrono`
  is a transitive dependency of **`worker` alone** — verified against
  `Cargo.lock` — so there is nothing here to upgrade and the fix is
  upstream or nothing. `.cargo/audit.toml` **already exists, is tracked,
  and already carries three dated ignores** (`RUSTSEC-2024-0436`,
  `RUSTSEC-2026-0173`, `RUSTSEC-2026-0387`), each with a reasoning
  block. This is the fourth, in the same shape.
- **D4. `audit.yml`'s header comment is stale and gets fixed in the same
  commit.** It says *"we add it to the `ignore` list in
  `.cargo/audit.toml` with a one-line justification (we don't have one
  yet; create it only when the first ignore is actually needed)"* — the
  file has existed with three ignores for a month. A workflow comment
  that misdescribes the repository is the defect class this programme
  keeps closing.

## 3. Change scope

| file | change |
|---|---|
| `Cargo.lock` | T1 — `cargo update -p url --precise 2.5.9` (two crates move; nothing else) |
| `.cargo/audit.toml` | T2 — the fourth ignore, `RUSTSEC-2026-0543`, same shape as the three above it |
| `.github/workflows/audit.yml` | T3 — the stale comment (D4) |
| `docs/src/expert/security-review-2026-q4.md` | T4 — **only if** you judge either advisory belongs there; see §4 |
| `DEPENDENCIES.md` | T5 — only if it pins `url`; check, do not assume |

## 4. Task detail worth stating explicitly

- **T2's reasoning block must say what the other three say**: the
  advisory id, the crate and version, that it is *unmaintained* rather
  than a vulnerability, **that `worker` is the only dependant and the
  fix is upstream**, the date it was accepted, and the condition that
  would retire the ignore (`worker` dropping `chrono`, or a maintained
  fork becoming the recommended path). An ignore without a retirement
  condition is a permanent silence.
- **T4 is a judgement, and I am not making it for you**: the security
  review is a *findings* document, and an ignored unmaintained-crate
  warning may not belong in it. My view: **`url` does not** (it is fixed
  in this cut and the CHANGELOG records it), and **`chrono` does not
  either** — an accepted ignore with a retirement condition belongs in
  `.cargo/audit.toml`, which is where a reader looking for ignores will
  be. If you disagree, say why in the report; do not add a row to both
  places.
- **Prove the ignore works**: run the gate set and show `cargo audit`
  (or `cargo deny`, whichever you can run locally) reporting the
  remaining set, and state in the report **which tool you ran** —
  `0.109.0` found that `cargo deny check` and `cargo audit` disagree on
  this tree, and that disagreement is itself rowed.
- **Do not add a third tool, do not change `deny.toml`, do not touch any
  other dependency.** `cargo update -p url --precise 2.5.9` and nothing
  else: a bare `cargo update` would move 150 crates and make this slice
  unreviewable.

## 5. Required tests and evidence

No new tests — this slice changes a lockfile, an ignore list and two
comments. **The gate set is the evidence**, with paths written in full
under `.git-exclude/review-request/0.110.0c-evidence/`:

```bash
cargo test -p cesauth-core \
           -p cesauth-adapter-test \
           -p cesauth-frontend \
           -p cesauth-backend \
           -p cesauth-adapter-cloudflare \
           --features cesauth-frontend/csr > .git-exclude/review-request/0.110.0c-evidence/host-tests.log 2>&1

cargo test -p cesauth-migrate-test --test migration_chain > .git-exclude/review-request/0.110.0c-evidence/migrate.log 2>&1
cargo check -p cesauth-backend --target wasm32-unknown-unknown > .git-exclude/review-request/0.110.0c-evidence/wasm32.log 2>&1
cargo deny check > .git-exclude/review-request/0.110.0c-evidence/cargo-deny.log 2>&1
bash scripts/route-contracts-check.sh > .git-exclude/review-request/0.110.0c-evidence/route-contracts.log 2>&1
bash scripts/drift-scan.sh > .git-exclude/review-request/0.110.0c-evidence/drift-scan.log 2>&1
```

Baseline: host **1,779 / 0 / 4 across 12 lines** (slices A and B will
raise it — say which tree you measured on), migrate **39**, **197
routes**, drift clean.

**The real proof is on the next push**: `audit.yml` green. Quote its run
URL and conclusion in the report. If it is still red for a third thing
nobody has seen yet, **that is the finding** — report it rather than
chasing it.

## 6. What must NOT be claimed

- **Not that `url`'s advisory was unreachable here** — it was
  *uncalled*, which is a stronger claim than unreachable and a weaker
  one than impossible: a dependency could have called it, which is why
  the bump is the right answer rather than the analysis.
- **Not that `chrono` is fixed.** It is accepted, with a retirement
  condition, because we cannot act on it.
- **Not that `audit.yml` green means the dependency tree is clean** — it
  means nothing unignored is outstanding, and the ignore list is now
  four entries long.

## 7. Acceptance criteria

1. `url` at 2.5.9, exactly two crates moved, nothing else in the
   lockfile.
2. `RUSTSEC-2026-0543` ignored with a reasoning block matching the
   file's existing three, **including a retirement condition**.
3. `audit.yml`'s stale comment corrected.
4. `audit.yml` green on the next push, with its run quoted.
5. Gates as in §5.

## 8. Review request

`.git-exclude/review-request/0.110.0c-report.md`, evidence under
`.git-exclude/review-request/0.110.0c-evidence/`. No G1 — there is no
copy and no population to rule on. Entry-point path only.
