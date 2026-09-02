# RFC 130 — Deployable frontend bundle

**Status.** Accepted — approved for implementation by the owner 2026-09-03;
dispatched. Not yet started.
**Tier.** P0 · Category A (the user-facing security screens are still broken)
**Size.** Small–Medium, but with two measurement gates before the design fixes
**Tracks.** RFC 127 acceptance criterion 3, formally not met; findings 4a/4b in
`.git-exclude/reviewed/127-csr-bundle-buildability-review.md` §4.
**Touches.** `crates/frontend/index.html`, `crates/backend/src/routes/leptos_shell.rs`,
`Makefile`, a new `rust-toolchain.toml`, `.github/workflows/`,
`BUNDLE_SIZE_BUDGET.md`.
**Depends on.** RFC 127 (the crate must compile before the bundle can ship).
**Sequenced before.** RFC 128 and RFC 129 — numbers are assignment order, not
priority (RFC 000: never reused, never renumbered).
**Target release.** v0.81.2 (the next release after 0.81.1).

## 1. Summary

RFC 127 made the frontend crate compile and gated it. The bundle still cannot
be **deployed**: `trunk build --release` fails, and even when it succeeds the
backend cannot locate the artifacts it produces. `/me/security`, the session
list and the TOTP gates therefore still render an empty root div. This RFC
closes that.

## 2. What is now measured, not assumed

Everything below was established by running the tools on this tree
(rustc 1.98.0, trunk 0.21.14, Binaryen 123):

| Fact | Evidence |
|---|---|
| `trunk build` (dev) **succeeds** | exit 0. **4a is a `--release`-only failure** — RFC 127 §4a did not distinguish this |
| `trunk build --release` fails at `wasm-opt` | `[wasm-validator error] memory.fill / memory.copy operations require bulk memory [--enable-bulk-memory-opt]` |
| Root cause | `rustc --print cfg --target wasm32-unknown-unknown` on 1.98.0 reports `target_feature="bulk-memory"` (also `multivalue`, `nontrapping-fptoint`, `reference-types`, `sign-ext`) |
| The flags do fix it, on the **pinned** Binaryen | `wasm-opt --enable-bulk-memory --enable-bulk-memory-opt -Oz` → exit 0. Trunk exposes no way to pass them (`data-wasm-opt` takes a level; the `WASM_OPT` positional pins a version) |
| Release artifact size | 876,297 bytes after `wasm-bindgen`, ≈748 KB after `-Oz`. Optimization is worth ~15 %, not an order of magnitude |
| Dev artifact size | 20,961,557 bytes (debuginfo) — unshippable, so "just use the dev build" is not an option |
| **Trunk emits no `manifest.json`** | `trunk build --help` has no such flag; `dist/` contains only the `.js`, `_bg.wasm`, and `index.html` |
| Default artifact names | `cesauth-frontend-<16-hex-hash>.js` / `…_bg.wasm` — package name (hyphenated) plus a content hash |
| With `--filehash false` | deterministic `cesauth-frontend.js` / `cesauth-frontend_bg.wasm` |
| What the backend hardcodes | `cesauth_frontend.js` / `cesauth_frontend_bg.wasm` — **underscored** (`leptos_shell.rs:43-44`) |

### 2.1 A false comment must be corrected

`leptos_shell.rs:41` reads:

> Phase B hardcodes these. Phase C will read `dist/manifest.json` so
> content-hashed names are used automatically.

**Trunk does not produce `dist/manifest.json`.** I said in the RFC 127 review
that reading the manifest was "the designed fix already written down"; that was
wrong, and I am correcting it here rather than leaving it in the record. The
plan cites a file that has never existed. Left in place, this comment sends the
next implementer after a nonexistent artifact — it is worse than no comment.
What Trunk *does* emit is `dist/index.html`, containing
`href="/cesauth-frontend-<hash>.js"`, which can serve the same purpose if
parsed.

## 3. Non-goals

- Leptos 0.9.x migration.
- Adopting the mockup's `cesauth-ui` — still an open owner decision.
- Removing the `format!` template layer.
- Reducing bundle size beyond what `wasm-opt` gives. 748 KB is recorded as a
  baseline, not attacked.
- RFC 128 (observability) and RFC 129 (source doc-comments).

## 4. Proposed design

### M1 — Measurement gate: Binaryen version (do this first)

Trunk pins `wasm-opt` by version and caches it at
`~/.cache/trunk/wasm-opt-version_<N>/`. Newer Binaryen releases read the
module's target-features section and enable matching features automatically.
**Test whether a newer pin removes 4a without any flag plumbing** — set
`data-wasm-opt` to a newer version through Trunk's version-pin mechanism and
run `trunk build --release`.

If it succeeds: 4a is closed by a one-line pin, and S1 below is unnecessary.
Report the result before implementing S1.

### S1 — Fallback for 4a, only if M1 fails

In preference order:

1. **Bypass Trunk for the optimize step.** Run `wasm-bindgen` and `wasm-opt`
   from the `Makefile` with explicit `--enable-bulk-memory
   --enable-bulk-memory-opt`. Verified to work on Binaryen 123. Costs us
   Trunk's orchestration for this stage.
2. **Ship unoptimized release.** `data-wasm-opt="0"` → 876 KB instead of
   748 KB. A 15 % size cost that unblocks deployment today, recorded in
   `BUNDLE_SIZE_BUDGET.md` as a known regression with M1 as its exit.

**Do not** pin an older `rustc` to avoid the target-feature default. That
inverts the dependency — freezing the compiler to satisfy a post-processor is a
trap that gets harder to leave every release.

### M2 — Measurement gate: toolchain pin

Add a `rust-toolchain.toml`. This project currently runs **four** toolchain
numbers with nothing pinning them: workspace `rust-version = "1.85"`, CI
installing 1.91, the v0.81.0 handoff verified on 1.96, and 1.98 locally. RFC 127's
new gate compiles on 1.91 while the code was written on 1.98 — the gate and the
developer are not building the same thing, and 4a exists *because of* a
version difference.

**Measure before choosing the version**: confirm the tree passes the full gate
set, *and* `--features csr`, *and* `trunk build --release`, on the candidate.
Do not assert a version without that evidence — RFC 029 was marked Implemented
on a measurement that had stopped being true, and that is what produced the
4,568-hunk `cargo fmt` surprise.

Once pinned, CI's four separate version references must be reconciled to it.

### S2 — Fix 4b: artifact naming

**Now:** `--filehash false` in the Trunk directive, and correct
`leptos_shell.rs:43-44` to the hyphenated names Trunk actually emits. Two
constants, deterministic, unblocks deployment.

**Cost, stated:** no content hashing, so a deployed bundle update relies on
whatever cache policy Workers Static Assets applies. Acceptable short-term;
not acceptable indefinitely.

**Follow-on (same RFC, after S2 verifies):** restore hashing and stop
hardcoding. A `Makefile` step parses the `href=` values out of
`dist/index.html` and writes `dist/manifest.json`; the backend reads it at
build time. This is what §2.1's comment *should* have said, and it removes the
whole class of defect rather than the current instance.

### S3 — A `trunk build --release` CI gate

Only meaningful once M1/S1 make it capable of passing. This is the gate that
would have caught 4a and 4b, and its absence is why RFC 127 could be complete
and the product still broken. Needs Trunk plus a Binaryen cache on the runner,
so it is slower than the RFC 127 `cargo check` gate and complements rather than
replaces it.

### S4 — Record the first real bundle measurement

`BUNDLE_SIZE_BUDGET.md` still carries `_run scripts/bundle-bloat.sh to
measure_` as its current value — it has never held a number. Record the
frontend figures (876 KB pre-opt, ≈748 KB post-opt) and note explicitly that
this budget is **separate** from the Worker bundle's 2.5 MiB gzip ceiling.

## 5. Data model / API impact

None. `leptos_shell.rs` changes are two string constants plus, in the
follow-on, a build-time read. No wire format, schema, DO payload, or cookie
change. The `<script src>` URL a browser fetches does change — that is the
point.

## 6. Testing strategy

1. `trunk build --release` exits 0.
2. `dist/` contains exactly the filenames `leptos_shell.rs` references.
   **Assert this mechanically** — grep the constants out of the Rust source and
   test each against `ls dist/`. RFC 127 proved that eyeballing a name mismatch
   is exactly what gets missed.
3. Full RFC 125 gate set, plus `--features csr`, green on the pinned toolchain.
4. S3's gate demonstrated to fail on a reintroduced defect (revert S2's
   constants, observe red, restore). Third time this project has required a
   fires/does-not-fire pair; it keeps finding real problems.
5. Record the measured sizes.

**Not verifiable here, and must be stated as such:** that a browser actually
loads the bundle and mounts the app. Every check above is a build-time check. A
bundle can build, be correctly named, be served, and still fail to mount. Until
someone loads `/me/security` in a browser and sees the Security Centre render,
this RFC has restored *buildability and addressability*, not confirmed
function. Say so in the release notes rather than implying the screens are
fixed.

## 7. Migration / rollout

Order: **M1 → (S1 if needed) → M2 → S2 → verify → S3 → S4**, then the S2
follow-on for hashing.

Both measurement gates report back before their dependent work starts. Neither
is a formality: M1 may delete S1 entirely, and M2 chooses a version that
everything else is then verified against.

## 8. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Pinning the toolchain breaks a gate that passes today on a different version | CI red on unrelated work | M2 requires the full gate set green on the candidate *before* pinning |
| `--filehash false` causes a stale bundle to be served after deploy | Users get old JS against a new backend | Accepted short-term and disclosed; the S2 follow-on restores hashing |
| A newer Binaryen changes optimization output | Behavioural difference in shipped wasm | M1's success criterion is a *working* release build, then the gate set re-run |
| Bundle builds, is named right, and still does not mount | Product looks fixed, is not | §6 states this explicitly; release notes must not claim the screens work until a browser check is done |

## 9. Acceptance criteria

1. `trunk build --release` exits 0 on the pinned toolchain.
2. Every filename constant in `leptos_shell.rs` matches a file in `dist/`,
   asserted mechanically (§6.2).
3. `rust-toolchain.toml` exists; CI's version references reconcile to it; the
   full gate set and `--features csr` pass on it, with evidence.
4. S3's gate is present, blocking, and demonstrated to fire.
5. `BUNDLE_SIZE_BUDGET.md` carries real numbers with the frontend/Worker
   distinction stated.
6. `leptos_shell.rs:41`'s `manifest.json` comment is corrected or removed.
7. Release notes state that browser-level function is unverified.

## 10. Open questions

1. **Does a newer Binaryen close 4a on its own?** M1 answers this, and the
   answer determines whether S1 exists.
2. **Which toolchain version?** M2 measures rather than assumes. My expectation
   is the newest that passes everything, so the pin does not become the thing
   holding the project back.
3. **Is a browser smoke check in scope for this project at all?** The mockup
   repo already carries a Playwright harness (`e2e/`, RFC 035 there) whose
   specs include a hydration smoke test. If the mockup is adopted, that harness
   arrives with it. If not, cesauth has no browser-level verification of any
   kind — worth an explicit decision rather than a permanent gap, and it
   interacts with the open UI-strategy question.
