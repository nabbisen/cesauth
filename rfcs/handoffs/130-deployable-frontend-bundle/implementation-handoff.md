# Developer Handoff — RFC 130, Deployable frontend bundle

**Governing RFC.** [`rfcs/proposed/130-deployable-frontend-bundle.md`](../../proposed/130-deployable-frontend-bundle.md)
**Target release.** v0.81.4
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing, but see §3 — this task has **two report-and-stop
points** before its design work begins.

---

## 1. Purpose

RFC 127 made the frontend crate compile and gated it. This makes the bundle
**deployable**. Until it lands, `/me/security`, the session list and the TOTP
gates still render an empty root div in any deploy from this tree.

## 2. Everything already measured — do not re-derive it

RFC 130 §2 is a table of facts established by running the tools on this tree.
Read it before touching anything. In particular:

- `trunk build` (dev) **succeeds**; only `--release` fails, at `wasm-opt`.
- Trunk emits **no `manifest.json`**. `leptos_shell.rs:41` claims otherwise and
  is wrong — correcting that comment is acceptance criterion 6.
- Optimization is worth ~15 % (876 KB → ≈748 KB), not an order of magnitude.
- Binaryen 123 *does* accept the module with `--enable-bulk-memory
  --enable-bulk-memory-opt`; Trunk just cannot pass them.
- Default artifact names carry package name **plus a content hash**, so the
  hardcoded constants cannot match in any spelling.

If any of these turns out to be false on your run, that is a finding — report
it rather than working around it silently.

## 3. Two report-and-stop gates

These are not formalities and not to be batched through.

**M1 — Binaryen version.** Test whether a newer `wasm-opt` pin makes
`trunk build --release` succeed with no flag plumbing at all. Trunk caches
wasm-opt per version under `~/.cache/trunk/wasm-opt-version_<N>/`; the current
pin resolves to 123. Newer Binaryen reads the module's target-features section
and enables matching features itself.

**Stop and report the M1 result before implementing S1.** If M1 succeeds, S1
does not exist and you have saved the whole workaround.

**M2 — toolchain version.** Do not pin a version you have not verified.
Measure, on the candidate: the full gate set, **plus** `--features csr`,
**plus** `trunk build --release`. Report which version you pinned and what
passed on it.

Start with **1.98** — it is what RFC 127's code was written on, and pinning the
newest that works keeps the pin from becoming the thing holding the project
back. Only fall back if 1.98 fails something.

RFC 029 was marked Implemented on a measurement that had stopped being true;
that is what produced the 4,568-hunk `cargo fmt` surprise. Do not repeat the
pattern.

## 4. Change scope

| # | Task | Files |
|---|---|---|
| M1 | Measure: newer Binaryen pin vs `trunk build --release` | none (measurement) |
| S1 | **Only if M1 fails.** Preference order in RFC 130 §S1: (1) run `wasm-bindgen` + `wasm-opt` from the `Makefile` with the enabling flags; (2) `data-wasm-opt="0"`, accepting ~15 % size, recorded in `BUNDLE_SIZE_BUDGET.md` with M1 as its exit | `Makefile` and/or `crates/frontend/index.html` |
| M2 | Measure and add the toolchain pin | new `rust-toolchain.toml` |
| M2b | Reconcile **every** CI toolchain reference to the pin — enumerated in §6 | `.github/workflows/*.yml` |
| S2 | `--filehash false` in the Trunk directive; correct the two filename constants to what Trunk actually emits | `crates/frontend/index.html`, `crates/backend/src/routes/leptos_shell.rs` |
| S2b | Correct or remove the false `manifest.json` comment | `crates/backend/src/routes/leptos_shell.rs:41` |
| S3 | `trunk build --release` CI gate, once capable of passing | `.github/workflows/` |
| S4 | Record the first real bundle numbers, with the frontend/Worker distinction | `BUNDLE_SIZE_BUDGET.md` |

Order: **M1 → (S1) → M2 → M2b → S2 → S2b → verify → S3 → S4.**

The S2 follow-on (restore hashing; generate a manifest from `dist/index.html`)
is in RFC 130 §S2 but is **not** in this unit of work. Land S2 first and
confirm it deploys.

## 5. `crates/backend/` is in scope this time

RFC 127's handoff forbade touching `crates/backend/`. **That restriction is
lifted for `leptos_shell.rs` only**, and only for:

- the two filename constants at `leptos_shell.rs:43-44`
- the false `manifest.json` comment at `:41`

Nothing else under `crates/backend/` changes. No route handler, no shell
structure, no CSP or nonce logic.

## 6. Every toolchain reference M2b must reconcile

Miss one and the pin is decorative:

```
clippy.yml:24          sudo apt-get install -y rustc-1.91 cargo-1.91
clippy.yml:26          clippy-driver-1.91 --version || cargo-1.91 clippy --version
clippy.yml:30          cargo-1.91 clippy \
test.yml:21            sudo apt-get install -y rustc-1.91 cargo-1.91
test.yml:25            cargo-1.91 test -p cesauth-core \
test.yml:32            cargo-1.91 test -p cesauth-migrate-test --test migration_chain
csr-bundle-check.yml:33  uses: dtolnay/rust-toolchain@1.91
bundle-size.yml:18       uses: dtolnay/rust-toolchain@1.91
Cargo.toml:27            rust-version = "1.85"
```

`fuzz.yml` uses `nightly` deliberately (cargo-fuzz) — **leave it alone**.

`Cargo.toml`'s `rust-version` is the *minimum supported* version, a different
thing from the pin. Decide deliberately whether to raise it, and say which you
did and why.

## 7. Explicit non-change scope

- No Leptos 0.9.x migration; pins stay `=0.8.19` / `=0.8.13`.
- No mockup / `cesauth-ui` adoption — still an open owner decision.
- No `format!` template layer removal.
- No bundle-size optimization work beyond what `wasm-opt` gives. Record 748 KB;
  do not attack it.
- Nothing from RFC 126, 128, or 129.
- Do not pin an older `rustc` to dodge the wasm32 target-feature default.
  Freezing the compiler to satisfy a post-processor gets harder to leave every
  release.
- Do not run `cargo fmt`.

## 8. Assert the filename match mechanically

Acceptance criterion 2 is the one RFC 127 proved humans miss. Do not eyeball
it:

```sh
cd crates/frontend && trunk build --release && cd ../..
for f in $(grep -oP '^const LEPTOS_\w+:\s*&str\s*=\s*"\K[^"]+' \
           crates/backend/src/routes/leptos_shell.rs); do
  test -f "crates/frontend/dist/$f" \
    && echo "OK      $f" \
    || { echo "MISSING $f"; exit 1; }
done
```

Attach that output. Every constant must resolve to a real file.

**Note on the working tree:** I left `crates/frontend/dist/` populated from my
own `--filehash false` experiments while drafting the RFC. It is `.gitignore`d,
but the contents are not what a default build produces — rebuild before
measuring anything.

## 9. Required tests and evidence

```sh
cd crates/frontend && trunk build --release > ../../evidence/trunk-release.log 2>&1; cd ../..
cargo check -p cesauth-frontend --features csr --target wasm32-unknown-unknown > evidence/csr-check.log 2>&1
cargo test -p cesauth-core -p cesauth-adapter-test \
           -p cesauth-migrate-test -p cesauth-frontend  > evidence/cargo-test.log 2>&1
cargo check -p cesauth-backend --target wasm32-unknown-unknown > evidence/wasm32-check.log 2>&1
cargo clippy -p cesauth-core -p cesauth-adapter-test -p cesauth-migrate-test \
             -p cesauth-frontend --all-targets -- -D clippy::correctness > evidence/cargo-clippy.log 2>&1
cargo deny check   > evidence/cargo-deny.log 2>&1
cargo audit        > evidence/cargo-audit.log 2>&1
bash scripts/route-contracts-check.sh > evidence/route-contracts.log 2>&1
bash scripts/drift-scan.sh            > evidence/drift-scan.log 2>&1
```

Expected: `trunk build --release` **exit 0**; csr check 0 errors; 1,233 passed
/ 0 failed; wasm32 clean; zero clippy errors; deny all-ok; audit exit 0.

Plus:

- The §8 filename assertion output.
- **M1 result** and **M2 result**, each stated plainly.
- **S3 fires:** revert S2's constants, show the new gate red, restore, show
  green. Capture both. Fourth time this project has asked for a
  fires/does-not-fire pair — it has caught something real every time.
- Measured artifact sizes for S4.

Evidence policy unchanged: redirected output only, never an authored result
line.

## 10. What you must NOT claim

Every check above is a **build-time** check. A bundle can build, be named
correctly, be served, and still fail to mount in a browser.

Do not write, and do not imply, that `/me/security` works. The honest claim is
"the bundle builds, is correctly named, and is addressable by the shell."
Whether the app mounts is unverified until someone opens it in a browser, and
this project currently has no browser-level verification of any kind (RFC 130
§10 item 3 raises that as an open question for the owner).

If you find a way to check mounting headlessly and it is cheap, report it as a
recommendation — do not implement it here.

## 11. Prohibited shortcuts

- No `#[allow(...)]`, `continue-on-error: true`, or weakened gate commands.
- Do not merge S3 red.
- Do not change a route string (26 of them, verified byte-identical in RFC
  127 — keep it that way).
- Do not skip M1 or M2 and go straight to the fix.
- Do not silence the `wasm-validator` error by disabling validation.

## 12. Known risks

RFC 130 §8. The one to watch: pinning the toolchain may turn a currently-green
gate red on a version difference nobody has exercised. That is why M2 measures
the full set *before* the pin lands. If the candidate fails something outside
this scope, **stop and report** — choosing between "pin an older version" and
"fix the failure" is a scoping decision, and it is mine.

## 13. Review request

Write the package to `.git-exclude/review-request/`. It must include:

Implementation summary · M1 and M2 results · changed files · deviations from
§4 · the nine logs from §9 · the §8 filename assertion · the S3
fires/does-not-fire pair · measured sizes · what remains unverified (§10) ·
requested review focus.
