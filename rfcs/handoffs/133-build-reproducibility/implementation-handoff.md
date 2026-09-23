# Developer Handoff — RFC 133 half A, the build step and one measurement

**Governing RFC.** [`rfcs/accepted/133-build-reproducibility.md`](../../accepted/133-build-reproducibility.md) — read **§12 and §13**, and **§12.1's correction** before anything else. It withdraws an overstatement that the rest of the RFC still carries.
**Target release.** The next one. **Level: patch** — a build-step fix, one
measurement, and a documentation correction. No product behaviour changes.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. 0.84.2 is tagged; no cut is pending.

---

## 1. Purpose

After this, `make build-frontend` cannot read and write one path in the same
step, cannot depend on what `dist/` already held, and cannot leave a stale
artifact behind a failed Trunk. Separately, we learn whether `wasm-bindgen` is
deterministic — the last cheap candidate for the residual delta §2.2 found.

## 2. Read this first: the risk is smaller than §2.3 says

§2.3 says any path where Trunk does not overwrite "silently ships a
doubly-optimized bundle". **§12.1 corrects that**, and the correction is why
this is hardening rather than an incident:

- the optimized wasm is **moved** to `dist/assets/` two lines later, so the next
  run's `dist/*_bg.wasm` glob does not match it;
- `make` aborts on the first failing line, so a failed `trunk build` stops the
  target before the optimizer runs.

**No measurement in RFC 133 was produced by a doubly-optimized bundle**, and the
review package must not claim one was. What is true is narrower and still worth
fixing: the step reads and writes the same path, and its output depends on that
path's prior contents. It holds today by luck of Trunk's behaviour, not by
construction.

## 3. Resolved decisions — do not re-open

| Decision | Ruling |
|---|---|
| Which fix | **Both.** §5's F1a and F1b are not alternatives, as §5's "Either … or" implies: one removes the aliasing, the other removes the history dependence |
| Scope | **Half A only** (RFC §13). No container, no `--remap-path-prefix`, no `SOURCE_DATE_EPOCH` — half B is deferred to 1.0 |
| The experiment | **Report and stop** after the `wasm-bindgen` comparison. No further M1 step starts on its result without a ruling |
| What this achieves | **Not reproducibility.** §2.2's finding is untouched. Say so |

## 4. Facts already measured — do not re-derive

| Fact | Where |
|---|---|
| The recipe, in order: `trunk build` → in-place `wasm-opt` loop → `rm -f dist/index.html` → `mkdir -p dist/assets` → `mv dist/*.js dist/*_bg.wasm dist/assets/` → `cp static/*` | `Makefile:147-170` |
| `wasm-opt -Oz` is not idempotent: 753,095 → 752,485 → 752,414 over three passes | RFC §2.3 |
| Five builds (three from an absent `dist/`, two over a populated one) all produced `753,095 / 1b539cd2…` | RFC §2.3 |
| Two clean rebuilds of one commit, minutes apart, produced different bytes | RFC §2.2 — **the finding this does not fix** |
| A rebuild that recompiles nothing re-emits the same file; a recompile may not | RFC §11 |
| `make clean` already removes `crates/frontend/dist` | `Makefile:213-218` — reuse that idiom rather than inventing one |
| `BUNDLE_SIZE_BUDGET.md` says the build is "run-reproducible but not environment-reproducible" | the paragraph beginning "**These figures are environment-sensitive**" |

*If any of this fails to reproduce, that is a finding. Report it.*

## 5. Change scope

| # | Task | Where |
|---|---|---|
| T1 | **F1a — no read–write aliasing.** The optimizer writes to a distinct path; the result is then moved into place. An interruption must never leave a partially written file where the input was | `Makefile`, the `build-frontend` recipe |
| T2 | **F1b — no history dependence.** Clear `crates/frontend/dist` before `trunk build`, using the same idiom as `clean`. A failed Trunk then leaves **no** artifact rather than a stale one | same recipe |
| T3 | **The glob must not silently match nothing.** With `dist/` cleared, a Trunk that emits no wasm would leave the loop with an unmatched pattern. Make that loud — the target fails with a message naming the missing artifact, not a confusing `wasm-opt` error about a file called `*_bg.wasm` | same recipe |
| T4 | **M1's first experiment.** Run `wasm-bindgen` **twice** over identical `cargo` output; compare both outputs by `sha256sum`. State the exact commands and the wasm-bindgen version. **Report and stop** | evidence only; no tree change |
| T5 | **The documentation correction.** `BUNDLE_SIZE_BUDGET.md`'s "run-reproducible" is false (§2.2). State the property in terms of **recompilation**: a rebuild that recompiles nothing re-emits the same file; a rebuild that recompiles may not. Cite §11's four release figures. Keep the environment-sensitivity paragraph, which is still true | `BUNDLE_SIZE_BUDGET.md` |

**Order: T1 + T2 + T3 together** (they are one recipe), **then T4, then T5.** T4
measures the tree as it will ship.

## 6. Explicit non-change scope

- **No container, no build image, no `SOURCE_DATE_EPOCH`, no
  `--remap-path-prefix`.** Half B, deferred (RFC §13).
- **No change to `wasm-opt`'s flags**, to the Binaryen pin, to Trunk's pin, or to
  `[profile.release]`.
- **No CI gate on the bundle hash.** RFC §12.5: it would fail on every version
  bump, which is the behaviour under investigation.
- No change to the `assets/` layout (RFC 131 C2-131 owns why it exists).
- No `cargo fmt`. No route strings.

## 7. The traps

**7.1 "Fixing" it by removing the optimizer.** The `-Oz` pass is what keeps the
bundle inside its budget. It stays; only how it is applied changes.

**7.2 Clearing the wrong thing.** `dist/` is the frontend's output directory.
Clearing `target/` or the Binaryen download would make every build slow and is
not asked for. `wasm-opt-fetch` is a prerequisite of this target — make sure
clearing `dist/` does not force a re-download.

**7.3 A `mv` that can leave nothing behind.** If the optimizer fails, the
distinct output path may not exist; the `mv` must not then destroy the input.
Sequence it so a failure leaves the *unoptimized but valid* wasm in place, or
fails before touching it.

**7.4 Measuring with a warm `dist/`.** T4 compares two `wasm-bindgen` runs over
**identical `cargo` output** — not two `make` runs. Establish the `cargo` output
once, then invoke `wasm-bindgen` twice against it.

**7.5 Reporting a size without its command.** RFC §9 criterion 4: every figure
states the command that produced it, and a gzip size states the full pipe.

## 8. Mechanical assertions

```sh
# the optimizer no longer reads and writes one path
grep -n -A8 '^build-frontend:' Makefile | grep -n 'wasm-opt' -A3

# dist/ is cleared before trunk build, with the same idiom as clean
grep -n -A4 '^build-frontend:' Makefile | grep -E 'rm -rf|trunk build'

# the false claim is gone
grep -rn 'run-reproducible' BUNDLE_SIZE_BUDGET.md docs/src || echo "clean"
```

## 9. Required evidence

**T1–T3, the acceptance test from RFC §5:**

1. **Three builds from a cleared tree agree** — size, gzip and `sha256sum` each
   time, with the commands.
2. **A build immediately following another agrees with them.**
3. **The failure path is loud:** make Trunk fail (or stage the tree so it emits
   no wasm) and show the target failing with a message that names the missing
   artifact. This is T3's fires half; without it T3 is unverified.
4. **An interruption does not corrupt the input**: show that the input wasm is
   intact if the optimizer does not complete. If you cannot interrupt it
   reliably, say so and show the ordering in the recipe instead — do not claim a
   test you did not run.

**T4:** both hashes, the commands, the `wasm-bindgen` version, and a one-line
conclusion: deterministic, or not, or inconclusive with the reason.

**Gate set:** host tests (baseline **1,509**, with the command and its summed
`test result` lines), `make build-frontend`, `make build-backend`, the runtime
smoke check and the browser suite — this touches the build, so the
wrangler-driven gates **are** in scope this time — plus clippy over six crates,
`mdbook build docs` and `drift-scan --verbose` for T5. Name anything you skip.

I re-run the three-build agreement and T4 myself.

## 10. What must NOT be claimed

- **Not that the build is reproducible.** §2.2 stands: recompiling the same
  source can still produce different bytes. Half A does not address it.
- **Not that a doubly-optimized bundle ever shipped**, or that any recorded
  figure came from one (§2).
- **Not that the residual delta is explained**, unless T4 finds it — in which
  case report it rather than acting on it.

## 11. Prohibited shortcuts

- No `#[ignore]`, no `cargo fmt`, no weakening a gate.
- No `rm -rf` outside `crates/frontend/dist` — and use the `clean` target's
  existing idiom, not a new one.
- No "it looks the same" in place of a `sha256sum`.

## 12. Acceptance criteria

RFC 133 §13's four items, and §9's acceptance test. Checked hardest: **the
three-build agreement**, **T3's loud failure**, and **T5 saying something true**
— the sentence it replaces has been wrong since RFC 130.

## 13. Review request

To `.git-exclude/review-request/`: implementation summary, changed files, the §8
assertions, §9's four evidence items with their commands, T4's result and its
conclusion, the gates you ran and any you skipped, and §10's list.

**Do not cut a release, bump a version, or create a tag.**

Report the path only.
