# RFC 136 — Backend test rot: 159 tests that do not compile, behind a false exclusion

**Status.** Accepted — approved by the owner 2026-09-12.
**Author.** Architect · **Date.** 2026-09-12
**Priority.** **P1.** Nothing user-facing; but the Worker's own tests — including
the TOTP second-factor and recovery-code paths — do not build, and nothing has
noticed.
**Target release.** After 0.83.0. **Ahead of RFC 117** in the assurance track:
assurance tests cannot be added to a crate whose existing tests do not compile.
**Found by.** RFC 135 W3, which tried to add one test to `cesauth-backend` and
discovered none of them run. First reported by the dev team in the RFC 129
package; characterised here.

---

## 1. Summary

`cargo test -p cesauth-backend --lib` fails with **36 errors**. The crate has
**159 `#[test]` functions across 18 modules**, and none of them has been
compiled — let alone run — by any gate. The exclusion is documented in
`test.yml:4-5` and `contributing.md:34` with a reason that does not describe
what broke.

## 2. What is established

**The errors are API drift, not target mismatch:**

| Kind | Count |
|---|---|
| `E0308` mismatched types | 28 |
| `E0277` trait bound not satisfied | 5 |
| `E0063` missing struct field | 2 |
| `E0599` no such method | 1 |
| lines in the error output mentioning `worker`/`wasm_bindgen`/`js_sys`/`web_sys` | **2** |

(`cargo test -p cesauth-backend --lib --no-run 2>&1`, deduplicated by kind.)

**Corrected 2026-09-12, before dispatch.** The "2" above is two *lines*, not
two errors — `leptos_shell.rs:74` (`use worker::{…}`) and `:95`
(`env: &worker::Env`), appearing as context inside type-mismatch messages. The
backend lib compiles on the host. **All 36 are test drift; D3 is expected to be
empty.** The handoff has D1 confirm that per error rather than inherit my
miscount.

**Where they are** (errors per file, top eight):

```
14  crates/backend/src/routes/me/totp/verify/tests.rs
10  crates/backend/src/routes/me/totp/recover/tests.rs
10  crates/backend/src/routes/admin/tenant_admin/role_assignments.rs
 9  crates/backend/src/routes/admin/tenancy_console/tenant_detail.rs
 8  crates/backend/src/routes/admin/tenant_admin/organization_detail.rs
 8  crates/backend/src/routes/admin/tenancy_console/subscription.rs
 8  crates/backend/src/routes/admin/console/overview.rs
 8  crates/backend/src/routes/admin/console/cost.rs
```

**The exclusion, and its stated reason:**

> `test.yml:4-5` — *"Excludes cesauth-adapter-cloudflare and cesauth-backend
> which require the wasm32-unknown-unknown target and worker-build toolchain."*

> `contributing.md:34` — *"excludes adapter-cloudflare and backend, which need
> WASM"*

That reason covers two of thirty-six errors. The other thirty-four are test code
that stopped matching the code it tests.

**How long.** The worst file was last touched by `69106bd` (2026-07-07, RFC 114
restructuring). The exclusion comment was carried into `test.yml` by `7cdf8cb`
(2026-08-31, RFC 125). Nothing establishes when the tests last compiled, because
nothing ever compiled them.

## 3. Why it matters

Two things, and the second is the one to keep.

**The tests.** 159 of them, covering route handlers — including
`me/totp/verify` and `me/totp/recover`, the second factor and the recovery
path. On a product whose commissioned theme is the security-assurance track
(RFCs 116–124), the Worker crate's own test suite has been dead weight for at
least two months, and the assurance track was about to build on it.

**The exclusion.** A gate excluded a crate for a stated reason, and the crate
rotted for a different one. The exclusion looked like a decision and functioned
as a blind spot. RFC 125 — whose purpose was to find gates reporting less than
they appear to — found the frontend's 280 uncounted tests and accepted this
exclusion's rationale at face value. This is that finding, one crate over, and
the architect missed it.

## 4. Non-goals

- Not making the backend's tests run on wasm32 (`wasm-bindgen-test`,
  `wasm-pack test`). Whether that is wanted is a separate question; this RFC
  makes the *existing* host tests compile and run, which the two wasm-touching
  errors may make partially impossible — see §5 D3.
- Not `cesauth-adapter-cloudflare`, excluded by the same sentence. Its tests
  are a separate measurement (§7 q1).
- Not adding tests. Repairing the ones that exist.

## 5. The change

**D1 — Measure precisely before touching anything.** For each of the 36: is it
drift (the test is wrong about a signature that legitimately changed) or a
genuine wasm/host boundary? The count in §2 says 34/2; confirm per error, with
the command.

**D2 — Repair the drift.** Update the test code to the current signatures. If a
test's *intent* no longer matches the code's behaviour, that is a finding —
report it, do not rewrite the test to pass.

**D3 — The two wasm-boundary errors.** Either gate the affected tests behind
`#[cfg(target_arch = "wasm32")]` with a comment naming this RFC, or restructure
so the host-testable logic is separable. **Report which, before doing it** —
the choice affects how much of the crate is host-testable at all.

**D4 — Put `cesauth-backend` in the gate.** `cargo test -p cesauth-backend` in
`test.yml` and in `contributing.md`'s command list. Correct the exclusion
comment in both places to say what is actually true: which tests (if any)
remain wasm-only, and why.

**D5 — `cesauth-adapter-cloudflare`.** Pre-measured before dispatch: its test
target fails on **one** error — `E0433: cannot find module or crate tokio` at
`mailer/unconfigured.rs:33`, a `#[tokio::test]` with no `tokio` dev-dependency.
Not wasm. One `#[cfg(test)]` module. The stated exclusion reason is false there
too. **Scope expanded from "report" to "act"** — add the dev-dependency, compile,
count, run, gate — an architect's ruling bounded to that one line, made because
the measurement turned out trivial.

Order: **D1 → report → D2 → D3 → report → D4.** Gate last, so it lands green.

## 6. Testing strategy

1. `cargo test -p cesauth-backend` compiles and runs; state the count.
2. The gate fires: break one repaired test → red; restore → green.
3. The full existing gate set stays green.
4. **A count in prose is a measurement.** The 159 and the 36 are stated with
   their commands; the after-figures must be too.

## 7. Open questions

1. ~~**`cesauth-adapter-cloudflare`** — how many tests, do they compile?~~
   **Answered before dispatch:** one test module, blocked by a missing `tokio`
   dev-dependency. Folded into D5.
2. **Should any backend tests run on wasm32?** Route handlers take
   `worker::Request`; some behaviour may only be testable in the Workers
   runtime. Out of scope here, but D3's report will say how much.

## 8. Release level

**Patch.** Repairing tests that exist and putting them in the gate is a fix.
Stated per `contributing.md` §"Choosing the version level".
