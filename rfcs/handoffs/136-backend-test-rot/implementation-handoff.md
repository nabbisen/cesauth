# Developer Handoff — RFC 136, backend test rot

**Governing RFC.** [`rfcs/done/136-backend-test-rot.md`](../../done/136-backend-test-rot.md)
**Target release.** After 0.83.0 — the first release after it, whatever its
number. **And why that level: patch.** Repairing tests that exist and putting
them in the gate is a fix; nothing new becomes possible for a user. If it ships
alone, it is a patch release.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** 0.83.0 shipping first — not technically, but by sequencing: R5
is the whole of 0.83.0 and this must not displace it.

---

## 1. Purpose

`cesauth-backend` has 159 `#[test]` functions in 18 modules and none of them
compile. After this, they compile, they run, they are in the gate, and the
exclusion comment in `test.yml` says something true.

## 2. Why this matters

The Worker crate — the thing that is deployed — has had a dead test suite for
at least two months, including the tests for `me/totp/verify` and
`me/totp/recover`. The assurance track (RFC 117 onward) is about to add tests
to this crate. It cannot build on tests that do not build.

## 3. Resolved decisions — do not re-open

**The exclusion's stated reason is false and gets corrected, not deleted.**
`test.yml:4-5` and `contributing.md:34` say the backend needs wasm32 and
worker-build. After this RFC the comment says what is actually true — which
tests, if any, remain wasm-only, and why.

**Tests are repaired to the current signatures, never rewritten to pass.** If
a test's intent no longer matches the code's behaviour, that is a finding —
report it (§7).

**`cesauth-adapter-cloudflare` is folded in** (D5), because the measurement
turned out to be trivial — §4. This expands RFC 136's D5 from "report" to
"act" by one dev-dependency. Architect's scope ruling, bounded to that.

## 4. Facts already measured — do not re-derive, but do correct one

```sh
cargo test -p cesauth-backend --lib --no-run 2>&1 | tee bt.log | tail -1
#   error: could not compile `cesauth-backend` (lib test) due to 36 previous errors
grep -oE '^error(\[E[0-9]+\])?: [^`]{0,60}' bt.log | sort | uniq -c | sort -rn
#   28 E0308 mismatched types · 5 E0277 trait bound · 2 E0063 missing field · 1 E0599 no method
```

Per-file counts are in RFC 136 §2. **159 test fns / 18 modules**:
`grep -rcE '^\s*#\[test\]' crates/backend/src | awk -F: '{s+=$2} END{print s}'`.

**A correction to RFC 136 §2, mine.** It says "lines mentioning
`worker`/`wasm`: 2" and §5 D3 treats those as two wasm-boundary *errors*. They
are two *lines* in the error output — `leptos_shell.rs:74` (`use worker::{…}`)
and `:95` (`env: &worker::Env`) — which appear as *context* inside type-mismatch
messages, not as errors of their own. The backend lib compiles on the host; every
route file imports `worker::Request` and none of them errors. **Expect D3 to be
empty.** D1 classifies per error and says so with the command.

**`cesauth-adapter-cloudflare`, pre-measured:**

```sh
cargo test -p cesauth-adapter-cloudflare --lib --no-run 2>&1 | tail -1
#   error: could not compile `cesauth-adapter-cloudflare` (lib test) due to 1 previous error
#   error[E0433]: cannot find module or crate `tokio` — mailer/unconfigured.rs:33: #[tokio::test]
```

One `#[cfg(test)]` module, blocked by **a missing dev-dependency**, not by
wasm. The "requires wasm32" reason is false there too. The `#[test]` count is
**0** only because the tests are `#[tokio::test]` — count those.

*If any of this fails to reproduce, that is a finding — report it.*

## 5. Change scope

| # | Task | Files |
|---|---|---|
| D1 | Classify all 36 by cause: drift vs. genuine wasm/host boundary. **Report the split before D2.** | none (measurement) |
| D2 | Repair the drift — tests updated to current signatures | the 18 test modules under `crates/backend/src/` |
| D3 | Any genuine wasm-boundary test: `#[cfg(target_arch = "wasm32")]` with a comment naming this RFC — **report before doing it**; expected empty | as found |
| D5 | `tokio` as a dev-dependency of `cesauth-adapter-cloudflare` (match the version the workspace already resolves); compile; count; run | `crates/adapter-cloudflare/Cargo.toml` |
| D4 | Both crates into `test.yml`'s `cargo test` line and `contributing.md`'s command list; correct the exclusion comment in both to say what is true | `.github/workflows/test.yml`, `docs/src/expert/contributing.md` |

Order: **D1 → report → D2 → D3 → report → D5 → D4.** Gate last, so it lands
green.

## 6. Explicit non-change scope

- **No changes to non-test code** to make a test pass. If a test can only pass
  by changing the code it tests, that is a finding (§7).
- No new tests. Repair what exists.
- No `wasm-bindgen-test` / `wasm-pack test` harness — RFC 136 §4.
- Nothing from RFC 131 (R5 is 0.83.0's), 117, 133, or 135.
- No `cargo fmt`. No route strings.

## 7. Report-and-stop: when a test disagrees with the code

Drift repair has one trap. A test that fails to compile because a signature
changed is mechanical. A test that, once compiling, **fails at runtime** is
information: either the test's expectation was wrong, or the code's behaviour
changed and the test was the only thing that knew. **Do not decide which.** For
each runtime failure after D2, report: the test, what it expected, what the code
does, and the commit that changed the code. Especially for anything under
`me/totp/`. Re-scoping — and deciding whether a behaviour change was intended —
is mine.

## 8. Assert the machine-checkable parts mechanically

```sh
# 1. every backend test compiles
cargo test -p cesauth-backend --lib --no-run 2>&1 | tail -1          # "Finished", not "error"

# 2. the count — state it with this command, before and after
grep -rcE '^\s*#\[(tokio::)?test\]' crates/backend/src crates/adapter-cloudflare/src | awk -F: '{s+=$2} END{print s}'

# 3. no non-test code changed
git diff --stat -- 'crates/**/*.rs' | grep -vE 'tests?\.rs|/tests/' ; echo "(anything above needs §7's report)"

# 4. the exclusion comment no longer states the false reason
grep -n 'wasm32-unknown-unknown target and worker-build' .github/workflows/test.yml docs/src/expert/contributing.md && echo "STALE REASON STILL PRESENT" || echo "clean"
```

## 9. Required tests and evidence

Full gate set (RFC 129 handoff §9 list), **plus** the two crates now in it:

```sh
cargo test -p cesauth-backend           > evidence/cargo-test-backend.log 2>&1
cargo test -p cesauth-adapter-cloudflare > evidence/cargo-test-adapter-cloudflare.log 2>&1
```

Expected: existing **1,233 passed** unchanged, plus the backend and adapter
counts stated with their commands. **The new gate fires:** break one repaired
test → red; restore → green.

**Counts in prose are measurements** — attach the command for every number.

## 10. What must NOT be claimed

- **Not that the backend is well-tested.** 159 tests compiling and passing says
  they match today's code; it says nothing about coverage.
- **Not that runtime failures were "fixed."** Per §7 they are reported, and
  their resolution is a separate decision.

## 11. Prohibited shortcuts

- No `#[ignore]` to get a red test out of the way. Report it.
- No editing non-test code to satisfy a test.
- No `continue-on-error: true`; no landing the gate red.
- No `cargo fmt`.

## 12. Acceptance criteria

RFC 136 §6, plus D5's counts. Checked hardest: **§7's reports** — the runtime
failures, if any, are the only place this RFC can produce a security finding —
and **§8.3**, that no non-test code moved.

## 13. Known risks

| Risk | Mitigation |
|---|---|
| A test is rewritten to pass rather than repaired | §6, §7, §8.3 |
| A runtime failure hides a real behaviour change under `me/totp/` | §7 — report, do not resolve |
| Repairing 159 tests is larger than it looks | D1's report gives the size before D2 starts. **If materially larger than scoped, stop and report.** |

## 14. Review request

Write the package to `.git-exclude/review-request/`. D1's classification
**first**, then §7's reports (even if "none"), then: implementation summary ·
changed files · deviations from §5 · every log from §9 · the four §8 assertions
· the gate's fires/does-not-fire pair · before/after counts with commands ·
what remains unverified (§10).

**Do not cut a release, bump a version, or create a tag.** The tag is the
owner's alone.

Report the path only.
