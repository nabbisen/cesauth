# RFC 135 — WebAssembly under the Content Security Policy

**Status.** Accepted — approved by the owner 2026-09-12, including the
ADR-007 amendment (W2).
**Author.** Architect · **Date.** 2026-09-12
**Priority.** **P0.** The CSR frontend cannot run. Every `client` surface is a
blank page.
**Target release.** 0.83.0, ahead of RFC 131 R5b–e, which are blocked on it.
**Found by.** RFC 131 R5's M2 gate — the first time anything opened cesauth in
a browser.

---

## 1. Summary

The browser refuses to compile cesauth's WASM bundle:

```
CompileError: WebAssembly.instantiateStreaming(): Compiling or instantiating
WebAssembly module violates the following Content Security Policy directive
because 'unsafe-eval' is not an allowed source of script in the following
Content Security Policy directive: "script-src 'nonce-…'".
```

The shell is served, the bootstrap script runs under its nonce, every asset
resolves, `init()` is called — and dies there. WebAssembly compilation is a
separate CSP capability, `'wasm-unsafe-eval'`, and cesauth's policy has never
granted it. `<div id="root">` stays empty on every client-rendered surface.

## 2. What is established

| Fact | Evidence |
|---|---|
| The directive is absent | `crates/core/src/security_headers.rs:156` `DEFAULT_CSP`; the shell's own CSP at `crates/backend/src/routes/leptos_shell.rs:127-130` — `script-src 'nonce-{n}'` only |
| The shell claims it is not needed | `leptos_shell.rs:50-51`, `:118-119` — *"`'wasm-unsafe-eval'` is NOT required. Leptos compiles to a standard WASM binary loaded via `WebAssembly.instantiateStreaming`"* — **citing, as its reason, the exact call CSP blocks** |
| Removing CSP in-browser makes it render | M2 diagnostic probe: zero page errors, full login UI (`login-csp-stripped.png`) — CSP is the sole blocker, not the first of several |
| The app does not mount into `#root` | `crates/frontend/src/lib.rs:196` `mount_to_body`; the doc at `:186-190` and the served shell both say `#root`. Both false |
| `mount_to(parent)` exists | `leptos-0.8.19/src/mount.rs:175` |
| ADR-007's hard bar is on `'unsafe-eval'` and never mentions WASM | `docs/src/expert/adr/007-…md:123-125` |
| The CSP predates the WASM frontend | ADR-007 `616fc14` 2026-05-06; Leptos foundation `4d62483` 2026-07-07 |
| The shell's CSP survives `apply()` | `lib.rs:580-593` — `already_set` is respected; the served `default-src 'self'` (not `DEFAULT_CSP`'s `'none'`) confirms it |
| A substring test would trip | `security_headers.rs:348` `!DEFAULT_CSP.contains("unsafe-eval")` — `"wasm-unsafe-eval"` contains it. So the directive must not go in `DEFAULT_CSP` |

**Not a regression.** No route resolved before 0.82.0 (RFC 134), so no one could
have observed it. **Not ADR-007's decision being reversed.** ADR-007 chose a
policy for a server-rendered application; RFC 115 built a WASM frontend under it
two months later without amending it — the same shape as External Design v2 §4
(RFC 132 §2).

## 3. Why every gate is green against a dead application

`runtime-smoke-check.sh` passes all ten checks on this build. Each is true. The
sequence is now complete: `cargo check` proved compilation while the router
panicked; `wrangler build` proved the Worker built while `/` was shadowed; a 200
with headers proved the shell was served while its assets 404'd; ten `curl`
assertions prove a page is served while the browser refuses to compile it.
**Only a browser could find this, which is what R5 is.**

## 4. Non-goals

- **Not `'unsafe-eval'`.** ADR-007's hard bar stands, and this RFC adds a test
  that keeps it standing.
- **Not `DEFAULT_CSP`.** Server-rendered surfaces need no WASM and get no
  directive.
- **Not styling.** The CSR app renders unstyled with CSP removed. That is
  because **no stylesheet exists** — not in Trunk's template, not in
  `dist/assets/` — and the design tokens in `design_tokens.rs` are consumed only
  by the three server-rendered frames; the Leptos `App` never injects them.
  Presentation wiring is RFC 131 R3.
- Not R5b–e, R2b, or R3.

## 5. The change

**W1 — `'wasm-unsafe-eval'` in the shell's `script-src`.** `leptos_shell.rs`'s
`format!` string only. Scope follows by construction: only routes calling
`leptos_html_shell` receive it — the `client` surfaces of RFC 132 §5.1.

**Why this scoping is a proof, not a convention.** RFC 132's E3 asserts no
`server`-declared route calls `leptos_html_shell`. So no `server` route can ever
carry the directive, and when R3 converts the three §8 gaps (`/`, `/login`,
`/me/security/totp/verify`) to server rendering, they stop calling the shell and
**fall back to the strict policy automatically.** The sign-in page ends with no
WASM directive at all.

**W2 — Amend ADR-007.** Its bar on `'unsafe-eval'` is unchanged. Add:
`'wasm-unsafe-eval'` is a distinct CSP Level 3 directive permitting WebAssembly
compilation without JavaScript `eval`; it is granted only on client-rendered
surfaces via the Leptos shell; RFC 132's E3 enforces that boundary; RFC 115
introduced the WASM frontend without amending this ADR, and this is that
amendment.

**W3 — Tests.**
- `security_headers.rs:348` → `!DEFAULT_CSP.contains("'unsafe-eval'")`, quoted,
  so it asserts what it means and cannot be tripped by the substring.
- New: the shell's CSP **contains** `'wasm-unsafe-eval'` and **does not
  contain** `'unsafe-eval'` (quoted). ADR-007's bar as a running check.

**W4 — Mount into `#root`.** `mount_to(document.get_element_by_id("root"), App)`
in `lib.rs:196`. Makes the served shell's comment and `lib.rs:186-190` true;
gives R5 a precise, stable assertion; keeps `<noscript>` and any future
server-rendered content outside the app's subtree.

**W5 — Correct the two false comments** (`leptos_shell.rs:50-51,118-119`;
`lib.rs:186-190`). Cite `instantiateStreaming` correctly: it is *why* the
directive is needed. Fifth consecutive cycle of staleness in that file; this is
the one that fixes the cause rather than the sentence.

**W6 — Extend `runtime-smoke-check.sh`:** `/login`'s CSP contains
`'wasm-unsafe-eval'` and does not contain `'unsafe-eval'`. A presence guard
against silent removal — **honest that it proves the directive, not the mount.**
The mount is proven by §9.

Order: **W4 → W5 → W1 → W3 → W2 → W6.** Gate last.

## 6. Data model / API impact

None. One response header on client surfaces gains one directive.

## 7. Testing strategy

1. Full gate set, plus W3's tests, plus W6's extended smoke check.
2. **W6 fires:** remove the directive → red; restore → green.
3. **§9's browser criterion** — the M2 probe, unmodified, against the real CSP.
4. **The negative:** a `server` route's response (`POST /magic-link/request`)
   does **not** carry `'wasm-unsafe-eval'`. Curl it and show the header.

## 8. Risks

| Risk | Mitigation |
|---|---|
| The permission leaks to a `server` surface | Structurally impossible while E3 holds; §7.4 demonstrates it |
| `'wasm-unsafe-eval'` is read as `'unsafe-eval'` by a future reviewer | W2 records the distinction in the ADR; W3 tests both directions |
| It mounts and something else is wrong | Expected. `/` has failed for four distinct reasons in four cycles. §9 asserts *zero page errors*, so the next layer surfaces immediately |
| Styling is mistaken for a CSP problem | §4 records it is not: no stylesheet exists. R3 |

## 9. Acceptance criteria

1. The M2 probe, re-run unmodified against the served CSP: **`MOUNTED`**, zero
   page errors, `#root` non-empty. Captured as redirected output with the
   screenshot.
2. `POST /magic-link/request`'s response CSP does **not** contain
   `'wasm-unsafe-eval'` (§7.4).
3. `DEFAULT_CSP` unchanged; `security_headers.rs:348` green with the quoted
   form.
4. W3's shell-CSP test passes both directions.
5. ADR-007 amended (W2).
6. Both false comments corrected (W5).
7. W6 in the smoke check, blocking, with its pair.
8. Full gate set green.

## 10. Release level

**Patch** — a fix: the application could not run and now can. Ships inside
0.83.0, which is minor because of R5. Stated per `contributing.md`
§"Choosing the version level".

## 11. Open questions

None the RFC can settle. The one decision is the owner's: whether to amend
ADR-007 as W2 describes. If the answer is no, the alternative is abandoning the
WASM frontend — which is the decision RFC 131 already made the other way.
