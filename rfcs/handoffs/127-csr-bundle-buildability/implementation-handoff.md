# Developer Handoff — RFC 127, CSR bundle buildability

**Governing RFC.** [`rfcs/proposed/127-csr-bundle-buildability.md`](../../proposed/127-csr-bundle-buildability.md)
**Target release.** v0.81.2 (patch; no consumer-visible surface change)
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. RFC 127 §11 items 2 and 3 are resolved below.

---

## 1. Purpose

Make the Leptos CSR browser bundle build, make Trunk actually build it, and
add the gate whose absence let this ship.

## 2. Why this is urgent

`leptos_html_shell` is called from live routes — `/me/security`,
`/me/security/sessions`, `/me/security/totp/verify`,
`/me/security/totp/disable`, plus invitations, deletion requests, and the
tenant-admin / operator JSON shells. It emits a page that loads
`cesauth_frontend.js` and `cesauth_frontend_bg.wasm`.

That bundle cannot be produced, and **there is no server-rendered fallback** —
those handlers return the shell unconditionally after session verification.
A deploy built from this tree serves the post-login landing page, the session
list, and the TOTP gate as an empty `<div id="root">`.

## 3. Resolved decisions — do not re-open

**RFC 127 §11 item 2 — is a `trunk build` CI gate wanted in addition to R5?**
Not in this release. R5 (`cargo check --features csr --target
wasm32-unknown-unknown`) catches all three defects in RFC 127 §3 at a fraction
of the cost, and it belongs in the same workflow family as the existing wasm32
backend gate. A full `trunk build` gate needs the Trunk toolchain on the
runner and is the only thing that would catch R4-class defects and artifact-name
drift — worth doing, but as its own scoped change, not smuggled in here. Note
it in the review request as a recommended follow-up; do not implement it.

**RFC 127 §11 item 3 — is there a template fallback?** Resolved: no. Settled
during drafting; see RFC 127 §2. Do not re-investigate.

## 4. Change scope

| # | Task | Files |
|---|---|---|
| R1 | Add `wasm-bindgen = { workspace = true, optional = true }` and `dep:wasm-bindgen` to the `csr` feature | `crates/frontend/Cargo.toml` |
| R2 | Convert 31 `<Route path="…"/>` to `path=path!("…")`; import `leptos_router::path` | `crates/frontend/src/app.rs` |
| R3 | Re-check and resolve whatever remains after R1+R2 | `crates/frontend/src/pages/**` likely |
| R4 | Add `data-cargo-features="csr"` to the `data-trunk` link; correct the false comment at line 16 | `crates/frontend/index.html` |
| R5 | New blocking CI job: `cargo check -p cesauth-frontend --features csr --target wasm32-unknown-unknown` | `.github/workflows/` |

Order matters: R1 → R2 → R3 (iterate to zero) → R4 → R5. **R5 last**, so it is
introduced green rather than merged red.

## 5. Explicit non-change scope

- No change to `crates/backend/` — including `leptos_shell.rs`. If the bundle
  builds and the artifact names match, the backend needs nothing.
- No Leptos 0.9.x migration. The pins stay `=0.8.19` / `=0.8.13`.
- No adoption of the mockup's `cesauth-ui`. That is an open owner decision and
  would replace this crate's architecture rather than repair it.
- Do not remove the surviving `format!` template layer (RFC 115 Phase C
  residue), even though R3 may make it look redundant.
- Nothing from RFC 126 (the 19-file docs sweep, the drift-scan rule).
- Do not run `cargo fmt`. Unchanged standing rule.

## 6. Task detail worth stating explicitly

**R2 — the route strings are a user-visible contract.** All 31 are production
URLs. A typo converts a working screen into a 404 with **no compile error to
catch it** — `path!("/me/securty")` compiles perfectly. Before/after, extract
the literals and diff them:

```sh
grep -oP 'path(?:=|!\()"\K[^"]+' crates/frontend/src/app.rs | sort > /tmp/paths-before.txt
# ... after R2 ...
grep -oP 'path(?:=|!\()"\K[^"]+' crates/frontend/src/app.rs | sort > /tmp/paths-after.txt
diff /tmp/paths-before.txt /tmp/paths-after.txt   # must be empty
```

Attach that diff (empty) as evidence. This is the single highest-risk step in
the release.

**R3 — do not batch-fix from the current error list.** The 79 errors include
notes pointing into `gloo-net`, `js-sys`, and `leptos_server` internals. Those
are probably cascades from R2 and will vanish. Re-run the check after R1+R2 and
work from the *new* list. Fixing a cascade at its symptom site is how real
drift gets papered over.

**R4 — without this, R1–R3 are unobservable.** Trunk currently builds with
default features, so `app`, `pages`, and `leptos_start` are all compiled out by
their `#[cfg(feature = "csr")]` gates and the bundle has no
`wasm_bindgen(start)` export. Also fix `index.html:16`, which claims the
directive already enables `csr`.

**R5 — the artifact names are load-bearing.** `leptos_shell.rs:43-44`
hardcodes `cesauth_frontend.js` and `cesauth_frontend_bg.wasm`. A build that
succeeds but emits different names is still a broken product.

## 7. Required tests and evidence

```sh
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

Expected: csr check **0 errors**; 1,233 passed / 0 failed; wasm32 clean; zero
clippy errors; deny all four sections ok; audit exit 0; route-contracts and
drift-scan per whatever C1 left them at.

Plus:

- The empty `paths-before`/`paths-after` diff from §6.
- If Trunk is available: `trunk build --release`, and a listing of
  `crates/frontend/dist/` showing the two filenames from §6/R5. If Trunk is not
  installable in your environment, say so explicitly — do not claim R4 verified
  when only R1–R3 were.
- **R5 fires:** temporarily drop `dep:wasm-bindgen`, show the new job red,
  restore, show green. Capture both. A gate that cannot be shown to fail is not
  a gate — this is the whole lesson of RFC 125.

Evidence policy unchanged: redirected output only, never an authored result
line.

## 8. Prohibited shortcuts

- No `#[allow(...)]`, `#[cfg(...)]`, or feature-gate trickery to make an error
  disappear rather than fixing it.
- Do not weaken R5's command to something that passes (dropping `--features
  csr` would make it vacuous — precisely the route-contracts failure mode from
  RFC 125).
- Do not merge R5 red "to be fixed next release."
- Do not change a route string to make a test or a path macro cooperate.
- No `continue-on-error: true`.

## 9. Acceptance criteria

RFC 127 §10, items 1–6. The two that will be checked hardest: the route-literal
diff is empty (§6), and R5 has a captured fires/does-not-fire pair (§7).

## 10. Known risks

R3 may uncover deeper Leptos 0.8.x drift than the 79 errors suggest. If the
residual after R1+R2 is not a short mechanical list, **stop and report** rather
than absorbing an open-ended migration into a patch release — R1/R2/R5 still
deliver value on their own, and re-scoping is my call, not yours.

## 11. Review request must include

Implementation summary · changed files · deviations from §4 · the eight logs
from §7 · the route-literal diff · the R5 fires/does-not-fire pair · whether
Trunk was actually exercised · unresolved issues · requested review focus.
