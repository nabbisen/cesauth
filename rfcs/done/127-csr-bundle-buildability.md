# RFC 127 — CSR bundle buildability and its missing gate

**Status.** Implemented (v0.81.1). R1–R5 landed.
**Acceptance criterion 3 was NOT met**: `trunk build --release` still fails and
the backend cannot locate the artifacts. Continued by RFC 130 — the frontend
screens remain non-functional until that ships.
**Tier.** P0 · Category A (user-facing authentication surfaces are affected)
**Size.** Medium (one repeated idiom + one dependency + one gate)
**Tracks.** Discovered during the RUSTSEC issue triage (GitHub #4–#7),
2026-09-02. Completes the verification RFC 115 Phase C and the v0.80.2 Leptos
bump both deferred; `DEPENDENCIES.md` predicted this explicitly.
**Touches.** `crates/frontend/Cargo.toml`, `crates/frontend/src/app.rs`,
`crates/frontend/index.html`, `.github/workflows/` (new gate), `Makefile`.
**Depends on.** RFC 125 (gate discipline). **Sequenced before RFC 126.**
**Target release.** Shipped in 0.81.1 (see Status).

## 1. Summary

The Leptos CSR browser bundle **cannot be built**, and no CI gate covers it.
`cargo check -p cesauth-frontend --features csr --target wasm32-unknown-unknown`
fails with **79 errors**. Independently, the Trunk directive that is supposed
to build it does not actually enable the `csr` feature, so even a "successful"
Trunk build produces a bundle with no entry point. Live production routes serve
an HTML shell that loads this bundle.

## 2. Motivation — this is not dead code

`crates/backend/src/routes/leptos_shell.rs::leptos_html_shell` emits a shell
referencing `cesauth_frontend.js` and `cesauth_frontend_bg.wasm`
(`leptos_shell.rs:43-44`). It is called from live routes, including:

- `/me/security` (`routes/me/security.rs:67`)
- `/me/security/sessions` (`routes/me/sessions.rs:58`)
- `/me/security/totp/verify` (`routes/me/totp/verify.rs:145`)
- `/me/security/totp/disable` (`routes/me/totp/disable.rs:154`)
- invitations, deletion requests, tenant-admin and operator JSON API shells

These are the user-facing security surfaces — the post-login landing page that
requirements §14.4 designates as the default destination, the session list, and
the TOTP gate. Any deploy built from this tree serves those pages a shell whose
script cannot exist: `crates/frontend/dist/` is absent and cannot be produced.
The rendered result is the empty `<div id="root">` plus the `<noscript>` notice.

**There is no server-rendered fallback.** `routes/me/security.rs:58-70`
verifies the session and then returns the Leptos shell unconditionally; the
component is expected to fetch its state from `GET /me/security.json` after the
bundle loads. The former `security_center_page_for` template is never called —
the file's only remaining reference to the template layer is a type import for
the JSON handler. The sessions and TOTP handlers follow the same pattern. So
these screens do not degrade to server-rendered HTML; they render nothing.

*Scope of the claim:* this is established from the tree, not from observing a
running deployment — I have no access to the live environment. What is certain
is that a deploy built from this source cannot produce a working bundle.

`DEPENDENCIES.md` called this in advance, under "Leptos (partially resolved)":

> **Host-side** `cargo check` passes with `leptos =0.8.19`. The wasm32/Trunk
> build still needs end-to-end verification. **Until that is done, treat the
> pin as unverified for production.**

The verification was never done, and nothing enforced it. That is the same
failure shape as RFC 125: a gate that does not exist cannot fail.

## 3. Background — the three defects

**(a) `wasm-bindgen` is not a dependency.** `lib.rs:179` uses
`#[wasm_bindgen::prelude::wasm_bindgen(start)]` and `pages/login.rs:39` uses
`wasm_bindgen::JsValue`, but `crates/frontend/Cargo.toml` lists only
`wasm-bindgen-futures`. The `csr` feature list omits `dep:wasm-bindgen`
entirely. → E0432, E0433 (3 errors).

**(b) Leptos router API drift, never compiled.** 26 `<Route path="…"/>` uses in
`app.rs` pass a bare `&str`. `leptos_router` 0.8.13 requires a
`PossibleRouteMatch`, produced by the `path!()` macro. The `path!` macro is not
imported or used anywhere in the crate. → E0277 ×46, E0599 ×27 (73 errors),
all traceable to this one idiom repeated 26 times.

The pin history in `Cargo.toml` records `=0.8.2 → =0.8.19` (leptos) and
`=0.8.2 → =0.8.13` (leptos_router) during v0.80.2, verified host-side only.

**(c) Trunk does not enable the feature.** `index.html:27` is
`<link data-trunk rel="rust" data-wasm-opt="z"/>` — no `data-cargo-features`,
and no `Trunk.toml` exists. Cargo therefore builds with `default = []`, so
`app`, `pages`, and `leptos_start` — all `#[cfg(feature = "csr")]` — are
compiled out. The bundle has no `wasm_bindgen(start)` export for the generated
bootstrap to call. The comment at `index.html:16` claiming the directive
"Compiles crates/frontend with --features csr" is false.

(a) and (b) break the build with the feature on. (c) means the feature is never
on. The two defects have concealed each other: (c) is why nobody hit (a)/(b).

## 4. Non-goals

- Migrating to Leptos 0.9.x. Out of scope; `DEPENDENCIES.md` tracks it.
- Adopting the mockup's `cesauth-ui` (SSR + hydrate). That is the open UI-strategy
  decision and would supersede this crate's architecture, not repair it.
- Removing the surviving `format!` template layer (RFC 115 Phase C residue).
- Any change to backend routes or `leptos_shell.rs` itself.
- The 19-file documentation sweep (RFC 126).

## 5. Proposed design

**R1 — Add `wasm-bindgen` as a real dependency.** Add
`wasm-bindgen = { workspace = true, optional = true }` and `dep:wasm-bindgen`
to the `csr` feature. The workspace already pins `wasm-bindgen = "0.2"`, so no
new version enters the graph.

**R2 — Convert the 26 routes to `path!()`.** Import `leptos_router::path` and
rewrite `<Route path="/x"/>` as `<Route path=path!("/x")/>`. Mechanical, but
verify each path string is preserved character-for-character — these are the
production URLs, and a typo here is a silently broken screen, not a compile
error.

**R3 — Re-check and resolve the residue.** R1 and R2 should clear the great
majority. Errors noting `gloo-net-0.6.0/src/http/request.rs`,
`js-sys-0.3.98/src/futures/mod.rs`, and `leptos_server-0.8.7/src/resource.rs`
may be cascades from R2 or may be genuine further drift. Re-run before
assuming; do not batch-fix on the current error list.

**R4 — Make Trunk build the feature.** Add `data-cargo-features="csr"` to the
`data-trunk` link (or introduce `Trunk.toml`), and correct the false comment at
`index.html:16`. Without R4, R1–R3 are unobservable.

**R5 — Gate it.** Add `cargo check -p cesauth-frontend --features csr
--target wasm32-unknown-unknown` to CI as a blocking job. This is the item that
prevents recurrence; R1–R4 are one-time repairs. A full `trunk build` gate would
be stronger but needs the Trunk toolchain on the runner — R5 is the cheap check
that would have caught all three defects, and it belongs in the same workflow
family as the existing wasm32 backend gate.

## 6. Data model / API impact

None. No wire format, schema, DO payload, cookie, or public `core` type. Route
*strings* must be preserved exactly (R2); they are a user-visible contract.

## 7. Testing strategy

1. `cargo check -p cesauth-frontend --features csr --target wasm32-unknown-unknown`
   — zero errors. This is the primary exit criterion.
2. Confirm the 26 route strings are byte-identical before and after R2. Diff
   the extracted path literals rather than eyeballing the diff.
3. `trunk build --release` produces `crates/frontend/dist/` containing
   `cesauth_frontend.js` and `cesauth_frontend_bg.wasm` — the exact filenames
   `leptos_shell.rs:43-44` hardcodes. A build that emits different names is a
   failure even if it compiles.
4. Confirm R5 fails on a deliberately reintroduced defect (drop
   `dep:wasm-bindgen`, observe red, restore). Same principle as RFC 126 §8.2: a
   gate that cannot be shown to fire is not a gate.
5. Full RFC 125 gate set — no regression.

## 8. Migration / rollout

Order: R1 → R2 → R3 (iterate to zero) → R4 → R5. R5 last, so it goes green on
first introduction rather than being merged red.

No consumer action. No version-surface change.

## 9. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| A route string is altered during R2 | A screen 404s in production, with no compile error to catch it | §7.2 requires a literal-level diff of all 26 paths |
| R3 uncovers deeper 0.8.x drift than expected | Scope grows beyond one release | Re-scope and report rather than absorbing it; R1/R2/R5 still ship value alone |
| `trunk build` emits different artifact names than `leptos_shell.rs` expects | Bundle builds but the shell still cannot load it | §7.3 checks names explicitly, not just build success |
| Fixing this entrenches the CSR architecture just as the mockup (SSR + hydrate) is under consideration | Wasted effort if the mockup is adopted | Accepted deliberately: the shipped product is broken *now*, and the UI-strategy decision has no date. Repair is cheap and independent of that choice. |

## 10. Acceptance criteria

1. `--features csr` wasm32 check exits 0.
2. All 26 route strings unchanged (§7.2 evidence attached).
3. `trunk build --release` produces `dist/` with the two filenames
   `leptos_shell.rs` references.
4. CI gate present, blocking, and demonstrated to fail on a reintroduced defect.
5. `index.html` comment matches what the directive actually does.
6. Full RFC 125 gate set green.

## 11. Open questions

1. **Does this warrant pulling ahead of RFC 126, or ahead of the assurance
   track itself?** My recommendation is yes to the former (already sequenced),
   and that the owner decide the latter — RFCs 117–124 harden an
   authentication core whose user-facing security screens currently cannot
   render.
2. **Is a `trunk build` CI gate wanted in addition to R5?** It is the only
   check that would catch R4-class defects and artifact-name drift. It costs
   Trunk toolchain setup on the runner.
3. ~~**Does the surviving `format!` template layer still serve these routes as
   a fallback?**~~ **Resolved — no fallback exists.** `routes/me/security.rs`
   returns the Leptos shell unconditionally after session verification; the
   only remaining reference to the template layer in that file is a *type*
   import (`SecurityCenterState`) used by the `.json` handler, not a render
   path. `security_center_page_for` is never called. The same shape holds for
   the sessions and TOTP handlers. The distinction in item 1 is therefore
   "broken", not "degraded".
