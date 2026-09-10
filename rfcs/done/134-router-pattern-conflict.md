# RFC 134 — Router pattern conflict: cesauth serves no requests

**Status.** Implemented (v0.82.0)
**Author.** Architect · **Date.** 2026-09-09
**Priority.** **P0.** Nothing else ships first.
**Target release.** The next one, whatever it is numbered.
**Found by.** RFC 131 R5's M1 gate, third attempt (C2-131).

---

## 1. Summary

`crates/backend/src/lib.rs` registers three routes whose `.json` suffix sits on
a **parameter** segment. `matchit`, the matcher inside the `worker` crate,
rejects such a pattern when the bare `:param` sibling is already registered, and
`worker` turns that rejection into a **panic**:

```
Rust panic: panicked at worker-0.8.3/src/router.rs:367:21:
  failed to register Get route for /admin/tenancy/tenants/:tid.json pattern:
  insertion failed due to conflict with previously registered route:
  /admin/tenancy/tenants/:tid
```

The router is constructed **inside** `#[event(fetch)]` (`lib.rs:146-153`), so
the panic fires on **every request, before dispatch**. No route works. The
runtime reports it as *"your Worker's code had hung and would never generate a
response"* — a 500 with no body and no headers.

## 2. What is established

| Property | Evidence |
|---|---|
| The mechanism is a panic, not an error | `worker-0.8.3/src/router.rs:360-370` — `.insert(pattern, …).unwrap_or_else(\|e\| panic!(…))` |
| The matcher is `matchit` | `worker-0.8.3/src/router.rs:4` |
| It fires per request, ahead of every handler | `lib.rs:146` `#[event(fetch)]`, `:151` `Router::new()`, chain built inline |
| Exactly three routes have the shape | `grep -oE '"/[^"]*:[a-z_]+\.[a-z]+"' crates/backend/src/lib.rs \| sort -u` |
| `.json` on a *literal* segment is fine | `/me/security.json` and ~20 siblings register without conflict |
| Versions never moved | `worker 0.8.3` + `matchit 0.7.3` identical in `Cargo.lock` at tags 0.80.2, 0.81.0, 0.81.2 and HEAD |

The three:

```
/admin/tenancy/tenants/:tid.json          conflicts with /admin/tenancy/tenants/:tid
/admin/t/:slug.json                       conflicts with /admin/t/:slug
/admin/t/:slug/organizations/:oid.json    conflicts with /admin/t/:slug/organizations/:oid
```

**Eight shipped releases carry it.** `:slug.json` landed in `30f73d5`
(2026-07-07, RFC 115 Phase C Screen 4); `:tid.json` in `580eeba`, same day.
`git tag --contains` gives **0.79.6, 0.80.0, 0.80.1, 0.80.2, 0.81.0, 0.81.1,
0.81.2, 0.81.3** — every release since 2026-07-07.

**Not host-specific.** The panic is in the `worker` crate's Rust code, compiled
into the Worker. Stated as inference: nobody has deployed this tree, so it has
been observed under `wrangler dev` only. The code path does not vary by host.

## 3. Why it was invisible

Every gate was honest about what it measured, and none of them measured this:

| Gate | What it proves |
|---|---|
| `cargo check --target wasm32` | it compiles |
| `cargo test` (1,233) | host-compilable crates behave |
| `make build-frontend` | a bundle is produced |
| `wrangler build` (added C1-131) | the Worker **builds** |
| `route-contracts-check.sh` | the table is complete and consistent |

**None boots the runtime and issues a request.** The "build-time only" caveat
every review has carried was covering this, not merely "does the bundle mount."

The architect's prioritisation is the direct cause of the delay: browser-level
verification (RFC 131 R5) was ranked behind documentation correctness and
rendering policy across four releases, and RFC 127's criterion 3 — which asked
exactly this question — was accepted as a standing known gap in 0.81.1. One
`curl` at any point in two months would have found it.

## 4. Non-goals

- Not a `worker` or `matchit` upgrade to make the pattern legal. The conflict is
  a genuine ambiguity, not a matcher bug: `/tenants/foo.json` could be `:tid`
  = `"foo.json"` or `:tid` = `"foo"` with a `.json` suffix.
- Not the `.json` convention itself. Twenty-odd literal-segment `.json` routes
  work and stay.
- Not content negotiation via `Accept`. Cleaner in principle, a much larger
  change, and it would touch every `.json` consumer. If it is ever wanted it is
  its own RFC.
- Not RFC 132's closure, R2b, R5b–e, or anything in the assurance track.

## 5. The change

**T1 — reshape the three patterns so `.json` sits on a literal segment.**
Proposed spelling, consistent with the existing convention:

```
/admin/tenancy/tenants/:tid.json         →  /admin/tenancy/tenants/:tid/detail.json
/admin/t/:slug.json                      →  /admin/t/:slug/detail.json
/admin/t/:slug/organizations/:oid.json   →  /admin/t/:slug/organizations/:oid/detail.json
```

**This deliberately breaks the standing "never change a route string" rule, and
the justification is narrow: these three strings have never successfully served
a request in any release.** There is nothing to be compatible with. The rule
exists to protect working contracts; these are not contracts, they are
registrations that have only ever panicked.

`docs/src/expert/route-contracts.md` updates in the same change — the three rows
keep their `n/a` Rendering value and their audit/CSRF columns.

**T2 — pin `worker`.** `Cargo.toml:42` declares `worker = { version = "0.8", … }`
— unpinned, floating within 0.8.x. That is the same root cause as `worker-build`
last cycle, which C1-131 pinned while leaving the crate itself free. Pin to the
version verified by T4, with a comment recording why.

**T3 — a runtime smoke gate.** The item that matters more than the fix. Boot
`wrangler dev`, issue requests, assert a real response:

- `GET /` → 200, `text/html`, non-empty body, **and a `content-security-policy`
  header** (the C1-131 finding: a missing header is invisible to a status check).
- `GET /login` → same.
- One `.json` route → 200 and `application/json`.
- A route that should 404 → 404, proving the matcher discriminates rather than
  answering everything.

This is a minimal stand-in for RFC 131 R5, not a replacement. R5 still owns
browser-level verification. T3 exists so this class of failure cannot recur in
the interval before R5 lands.

**T4 — verify, then pin.** Report which `worker` version the smoke gate passes
on before T2 records it. Do not pin a version nobody has exercised: RFC 029 was
marked Implemented on a measurement that had stopped being true.

Order: **T1 → T4 → T2 → T3.** T3 last, so it lands green.

## 6. Data model / API impact

Three route strings change. No schema, no `core::ports` trait, no config knob,
no permission slug. The three routes' handlers are untouched.

## 7. Testing strategy

1. The full nine-gate set, plus `wrangler build`, plus the new T3 smoke gate.
2. **T3 demonstrated to fire:** restore one conflicting pattern, show the smoke
   gate red with the panic; revert, show green. A gate that cannot be shown to
   fail is not a gate — eighth time this project has required the pair, and the
   seventh caught a hole in the gate itself rather than in the code.
3. `route-contracts-check.sh` at 188/188 with the three paths updated.

## 8. Risks

| Risk | Mitigation |
|---|---|
| Fixing the first conflict reveals a second | The panic reports one pattern at a time. §2's grep enumerates all three up front; T3 proves the router constructs, not just that one pattern was fixed |
| The reshaped paths collide with an existing route | Assert mechanically against the 188-row table; `detail.json` appears nowhere today |
| A further failure hides behind this one | Likely, and expected. `/` has already failed for three distinct reasons in three cycles. T3's assertions are deliberately about *content and headers*, not status codes, so the next layer surfaces immediately |
| Pinning `worker` freezes a defect in place | T4 measures before T2 pins; the pin is a comment away from being revisited |

## 9. Acceptance criteria

1. `wrangler dev` starts and `GET /` returns 200 with an HTML body — no panic in
   the console output, captured as redirected output.
2. `GET /login` likewise, **with a `content-security-policy` header present.**
3. All three reshaped routes resolve; the pre-existing literal-segment `.json`
   routes still resolve.
4. A route expected to 404 returns 404.
5. `worker` pinned to a version the smoke gate passed on, with that version
   stated.
6. T3 in CI, blocking, with a captured fires/does-not-fire pair.
7. `route-contracts-check.sh` 188/188; full gate set green.
8. No change to any handler, schema, or `core::ports` trait.

## 10. Release level

**Patch.** It is a fix, and the route strings it changes have never served a
request, so nothing depended on them. Stated explicitly because the version
rule (`docs/src/expert/contributing.md` §Choosing the version level) requires
the reasoning rather than the number — and because "route strings changed"
would normally read as minor. It does not here, for the reason above.

T3 is a new gate, which is added capability in the sense that release rule
cares about. If the owner prefers the conservative reading, this is a minor.
**Architect's recommendation: patch**, on the grounds that a gate protecting a
fix is part of the fix.

## 10a. Found in review: the shell's assets 404 (C1-134)

**Added 2026-09-09**, reviewing the implementation. The router fix is correct
and complete; this is a separate defect one layer below it, and the acceptance
criteria above did not reach far enough to catch it.

`crates/backend/src/routes/leptos_shell.rs` references every asset under an
`/assets/` prefix (lines 91, 109, 110) and its module doc at `:19` asserts they
are "served at `/assets/`". They are not: `wrangler.toml:161-162` sets
`[assets] directory = "crates/frontend/dist"`, which Workers Static Assets
serves from the **root**. Probed against the running Worker:

```
/assets/cesauth-frontend_bg.wasm   404      /cesauth-frontend_bg.wasm   200
/assets/cesauth-frontend.js        404      /cesauth-frontend.js        200
```

The module script's first `import` therefore 404s, `init()` never runs, and
`<div id="root">` stays empty on every client-rendered surface. This is the
empty root div RFC 127 criterion 3 and RFC 130 §10 both anticipated.

**Ruled fix:** `make build-frontend` outputs under `dist/assets/`, making the
shell's paths true — *not* stripping the prefix. Serving assets at the root
means any filename in `dist` can shadow the Worker route at that path, which is
how `dist/index.html` swallowed `/` (RFC 131 C1-131). Moving them under a
prefix bounds that class to `/assets/*` permanently.

**And the gate lesson, which matters more than the bug.**
`runtime-smoke-check.sh` asserted the shell is *served* — 200, `text/html`,
non-empty body, CSP present, no panic — every one of which was true while the
application could not load a byte of itself. Same shape as every gap in this
sequence: `cargo check` proved compilation while the router panicked;
`wrangler build` proved the Worker built while `/` was shadowed. C1-134
extends the gate to derive every asset URL **from the served HTML** and assert
each resolves. A criterion written one layer lower would have caught this on
the first attempt; that is a defect in §9 as authored, not in the work.

## 11. Open questions

1. **The `detail.json` spelling** (§5 T1) is the architect's proposal, not a
   requirement. Any spelling that keeps `.json` off a parameter segment works.
   Owner or dev-team preference welcome before implementation.
2. **Should the eight broken releases be recorded anywhere beyond this RFC?**
   The project keeps a ten-item tag/CHANGELOG discrepancy ledger; this is a
   different and larger class — releases that shipped and could not run. My
   recommendation is a short, dated note in `CHANGELOG.md` above the 0.79.6
   entry rather than editing eight historical entries. Owner's call.
