# RFC 183 — Verus narrow pilot: one proof obligation on the TOTP truncation

**Governing RFC.** [`rfcs/accepted/183-verus-narrow-pilot.md`](../../accepted/183-verus-narrow-pilot.md)
— **read §4 and §5 before writing any code.** §4 is the pilot's real risk; §5 is
why "reject" is a legitimate result.

**Builds on.** `main` at tag **`0.95.0`** (`c251345`).

**Target release.** **Minor** — RFC 181's default. No patch argument offered.
**Held until `0.95.0` was tagged** so its `verification/` directory did not land
in a cut whose reviewed scope did not describe it; that tag now exists.

**Tier.** **P3.** Nothing is broken. This is a time-boxed assurance experiment
that may be rejected.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-10.**
**Time-box: five working days.** §7 of the RFC. **Report at the box whatever the
state** — "abandoned, toolchain would not build the harness" is a result.

**On 1.0:** not declared, not scoped, not dated.

---

## 1. The target, and the two obligations

`crates/core/src/totp.rs:242-260`, `compute_code` — RFC 4226 §5.3:

```rust
let result = mac.finalize().into_bytes();          // GenericArray<u8, U20>
let offset = (result[19] & 0x0f) as usize;         // 0..=15
let bin_code = ((result[offset]     & 0x7f) as u32) << 24
             | ((result[offset + 1] & 0xff) as u32) << 16
             | ((result[offset + 2] & 0xff) as u32) << 8
             |  (result[offset + 3] & 0xff) as u32;
```

Prove, for **all** 2^160 HMAC outputs:

1. **`offset + 3 < 20`** — no index can panic.
2. **`bin_code < 2^31`** — the high bit is clear, which is what `& 0x7f` is for
   and which nothing currently states.

**There is no bug here.** `& 0x0f` bounds `offset` to ≤ 15 so the max index is
18. Do not report one. What is true is that the indices are runtime-checked
through `GenericArray`'s slice semantics, the invariant is written nowhere, and
`routes/me/totp/verify.rs:343` → `totp.rs:340` calls this **once per candidate
skew step**, so a panic would 500 every TOTP verification.

**`util::constant_time_eq_bytes` is NOT the target** and must not be substituted
for looking easier. Its purpose is a **timing** property and Verus cannot express
timing at all.

## 2. Where it goes

`verification/`, out-of-workspace, the way `fuzz/` already is. **No production
code changes** — not an attribute, not a `cfg`, nothing. If the only way to
discharge an obligation is to annotate `crates/core`, **stop and report that**:
it is the finding that decides §5's question 4.

## 3. §4's risk is a deliverable, not a caveat

Verus needs `verus!{}`-annotated code, so the pilot verifies a **copy**. **A copy
that drifts verifies fiction**, and this project has paid for that class already
— RFC 171 Q1 found a caller matching a `PortError` the real adapter could never
produce, with a green suite.

**So: a drift check, in `scripts/drift-scan.sh`, that fails when the copy and
`crates/core/src/totp.rs`'s truncation block diverge.** Byte-comparison of the
extracted statements is enough; it does not need to understand Rust.

- **RFC 182's rule applies**: no `cmd | grep -q`, no `| head`, no
  `awk '…exit'` pipe. Use a here-string or `mapfile`. The file's header states
  the rule and §2 of `route-contracts-check.sh` shows the shape.
- **It must be seen to fail.** Force a one-character divergence, show the
  failure naming both files, restore, show it pass. `diff` the restore.
- **It must be green on arrival.** The copy will match at the moment you write
  it, so this is free — but it is the E7 / RFC 178 lesson and it is not
  optional.

**If the drift check cannot be built cheaply, the honest verdict is reject** —
an unverifiable copy reads as assurance, which is worse than no proof.

## 4. The verdict is comparative — and "reject" is the result I expect to be defensible

**Verus will almost certainly discharge both obligations.** That is not the
question. RFC 124 already proposes **Kani** for small pure functions, a 20-byte
array is well inside bounded model checking's reach, and **Kani works on
unmodified Rust with no copy and therefore no drift check.**

Answer these four in writing. They are the deliverable:

1. **Did the proof find anything**, or confirm what reading the code already
   showed?
2. **What did the copy plus drift check cost**, in lines and in hours?
3. **Would Kani have done this without a copy?** If you can try it cheaply
   inside the box, do; if not, reason about it and say which. **Do not install
   Kani if it costs more than an hour** — that is a different RFC's budget.
4. **Does `verus!{}` mean adoption implies annotating production code** — and if
   so, is that acceptable for a `wasm32` Worker build?

**A verdict of "reject Verus for this class, prefer Kani" is a success.** Say it
plainly if that is what you find. A pilot that cannot reach that conclusion was
designed to succeed, and I would rather have a clean rejection than a proof
nobody will maintain.

## 5. Do not

- **No second target**, however tempting once the harness exists.
- **No Verus in CI.** The toolchain is owner-installed, unpinned, and an upgrade
  is intended. The drift check goes in CI; Verus does not.
- **No production code change** (§2).
- **No claim about timing, side channels, or the cryptography.**
- **Do not extend the box.** Five days, then report.
- **Do not change `compute_code`'s behaviour**, even if the proof suggests a
  tidier formulation. A behaviour change here is a separate RFC with RFC 6238
  vector tests as its gate.

## 6. Evidence required

1. Both obligations discharged, or shown not to hold, with the Verus output.
2. **The drift check: forced failure, restore, pass** (§3).
3. §4's four questions answered, with a verdict of **adopt narrowly / defer /
   reject**.
4. The Verus version used, and whether it is the owner-installed
   `0.2026.07.27.31579f0` or a later one.
5. **Hours actually spent**, against the five-day box.
6. Existing gates unchanged — host **1,687 / 0 / 4, 12 lines**;
   `migration_chain` **35**; `route-contracts-check.sh` exit 0 with
   `All 195 routes`; `drift-scan.sh` exit 0 **plus the new check**; `mdbook`
   **82 pages**. Worker bundle with `sha256sum` and the gzip level — it should
   **not** move, since `verification/` is out-of-workspace.
7. The route-surface census should read **`195 pairs — 0 added, 0 removed`**.
   If it does not, something reached the Worker that should not have.

## 7. Stop conditions

- The toolchain will not build the harness inside the box. **Report, do not
  extend.**
- The drift check cannot be built cheaply (§3).
- An obligation can only be discharged by annotating production code (§2).
- **The proof fails** — i.e. Verus cannot establish `offset + 3 < 20`. That
  would be the most important outcome this pilot could produce and it needs its
  own report, immediately, not at the end of the box.

## 8. Baselines at `c251345` (tag `0.95.0`)

| | value | command |
|---|---|---|
| host tests | **1,687 / 0 / 4**, 12 lines | canonical five-crate command, awk-summed |
| `migration_chain` | **35** | `cargo test -p cesauth-migrate-test` |
| `route-contracts-check.sh` | exit 0, **All 195 routes**, E7 `156 = 8 + 31 + 117` | its own output |
| `drift-scan.sh` | exit 0; `route surface vs 0.95.0: 195 pairs -- 0 added, 0 removed` | `./scripts/drift-scan.sh` |
| `mdbook` | **82 pages** | `mdbook build docs` |
| Worker bundle | **893,600 B** gzip-default, sha256 `cfc32f9f73138d98` / `d4809d0a6a5638b2` | `wrangler deploy --dry-run`; empty `crates/frontend/dist/assets/` required, sound because `LEPTOS_JS`/`LEPTOS_WASM` are hardcoded consts |
| `verus` | `/home/nabbisen/.local/bin/verus`, `0.2026.07.27.31579f0` | `verus --version` |
| RFC 6238 vector tests | 3 known-answer vectors | `crates/core/src/totp/tests/rfc6238_vectors.rs` |
