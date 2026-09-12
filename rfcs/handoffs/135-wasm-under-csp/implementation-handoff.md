# Developer Handoff — RFC 135, WebAssembly under the CSP (P0)

**Governing RFC.** [`rfcs/done/135-wasm-under-csp.md`](../../done/135-wasm-under-csp.md)
**Target release.** 0.83.0 — **and why that level:** RFC 135 is a **patch** (the
application could not run; now it can). 0.83.0 is **minor** because RFC 131 R5
adds the browser harness. This RFC is not the reason for the level.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. R5b–e are blocked on *this*.

---

## 1. Purpose

The browser refuses to compile cesauth's WASM bundle. After this, it compiles,
Leptos mounts into `#root`, the shell's claims about itself are true, and a
gate guards the directive against silent removal.

## 2. Why this matters

Every `client` surface is a blank page, and every existing gate says it is
healthy. Your own M2 report §5 states the reason better than the RFC: ten
`curl` assertions cannot see what a browser decides. This is the last known
layer between "served" and "renders."

## 3. Resolved decisions — do not re-open

**The directive goes in the shell, not `DEFAULT_CSP`.** `leptos_shell.rs`'s
`format!` string, `script-src 'nonce-{n}'` → `script-src 'nonce-{n}'
'wasm-unsafe-eval'`. Scope follows by construction (RFC 135 §5 W1), and
`security_headers.rs:348`'s substring test stays green because `DEFAULT_CSP`
does not change.

**`'unsafe-eval'` stays barred**, and W3 makes that a running test in both
directions.

**Mount into `#root`, not "fix the comments to say body."** RFC 135 §5 W4: it
makes the shell's promise true and gives R5 a stable assertion.

**ADR-007 is amended, not superseded.** The owner authorized W2 on 2026-09-12.
Its bar on `'unsafe-eval'` is unchanged; the amendment records the distinct
directive, its scope, the enforcing gate, and that RFC 115 built the WASM
frontend without amending the ADR.

**Styling is not in scope.** RFC 135 §4. No stylesheet exists anywhere; that is
R3.

## 4. Facts already measured — do not re-derive

RFC 135 §2 is measured ground. Two implementation facts on top of it:

- **`web-sys` lacks the features W4 needs.** `crates/frontend/Cargo.toml:70-77`
  enables `Window, Navigator, Location, Request, RequestInit, RequestMode,
  Response, Headers` — **no `Document`, `Element`, or `HtmlElement`.** Getting
  `#root` needs all three. Add them; say so in the review.
- **`mount_to` returns an `UnmountHandle`** (`leptos-0.8.19/src/mount.rs:175`).
  See §7 — this is the trap.

*If any of this fails to reproduce, that is a finding — report it.*

## 5. Change scope

| # | Task | Files |
|---|---|---|
| W4 | `mount_to(#root, App)` with the handle **forgotten** (§7); add `Document`, `Element`, `HtmlElement` to `web-sys` features | `crates/frontend/src/lib.rs:196`, `crates/frontend/Cargo.toml` |
| W5 | Correct the two false comments — `leptos_shell.rs:50-51` and `:118-119` (cite `instantiateStreaming` as *why the directive is needed*), `lib.rs:186-190` (now true after W4; make the wording match `mount_to`) | as named |
| W1 | `'wasm-unsafe-eval'` in the shell's `script-src` | `crates/backend/src/routes/leptos_shell.rs:~128` |
| W3 | `security_headers.rs:348` → `!DEFAULT_CSP.contains("'unsafe-eval'")` (quoted); new backend test: the shell's CSP **contains** `'wasm-unsafe-eval'` and **does not contain** `'unsafe-eval'` (quoted) | `crates/core/src/security_headers.rs`, `crates/backend/src/routes/leptos_shell.rs` (tests) |
| W2 | Amend ADR-007 per RFC 135 §5 W2 — an appended dated section, the same form ADR-013 and RFC 006 already use; do not rewrite the original text | `docs/src/expert/adr/007-security-response-headers.md` |
| W6 | `runtime-smoke-check.sh`: `/login`'s CSP contains `'wasm-unsafe-eval'` **and** does not contain `'unsafe-eval'`; plus the negative — `POST /magic-link/request`'s CSP does **not** contain `'wasm-unsafe-eval'` | `scripts/runtime-smoke-check.sh` |

Order: **W4 → W5 → W1 → W3 → W2 → W6.** Gate last, so it lands green.

## 6. Explicit non-change scope

- **`DEFAULT_CSP` does not change.** If your diff touches the constant, stop.
- No `'unsafe-eval'` anywhere, ever.
- No styling work, no stylesheet, no design-token injection — R3.
- No R5b–e. No `e2e/` directory yet.
- No route strings, no handlers, nothing under `crates/core` beyond the one test
  line.
- Do not touch the three RFC 132 §8 conformance gaps; they are R3's and they
  will drop to the strict policy automatically when converted.
- No `cargo fmt`.

## 7. The trap in W4 — a one-liner that compiles and renders nothing

`mount_to` returns an `UnmountHandle`. If it unmounts on drop — which is the
Leptos design, and is why `mount_to_body` calls `.forget()` internally — then

```rust
leptos::mount::mount_to(root, app::App);          // handle dropped here
```

mounts the app and **immediately unmounts it**, at the end of the statement.
The page compiles, the bundle loads, no error is thrown, and `#root` is empty —
indistinguishable from today's outage. Write:

```rust
leptos::mount::mount_to(root, app::App).forget();
```

**Confirmed, not hypothesised:** `impl<M> Drop for UnmountHandle<M>` is at
`leptos-0.8.19/src/mount.rs:295`, and `mount_to_body` itself is exactly
`let owner = mount_to(body(), f); owner.forget();` (`mount.rs:170-171`). You are
replicating what `mount_to_body` already does, minus the target. Leave the
`.forget()` off and the outage survives the fix with every gate green.

Getting `root`: `web_sys::window()` → `.document()` →
`.get_element_by_id("root")` → `.dyn_into::<web_sys::HtmlElement>()`. If it is
`None`, **panic with a clear message** — `console_error_panic_hook` is already
set two lines above, so the panic is readable in the console. Do not fall back
to `mount_to_body` silently; a missing `#root` is a shell defect and should be
loud.

## 8. Assert the machine-checkable parts mechanically

```sh
# 1. DEFAULT_CSP unchanged
git diff -- crates/core/src/security_headers.rs | grep -E '^[-+].*DEFAULT_CSP.*=' && echo "CONSTANT CHANGED — stop" || echo "clean"

# 2. the directive is in the shell and nowhere else
grep -rn "wasm-unsafe-eval" crates/ --include='*.rs' | grep -v '//' | grep -v 'test'   # expect exactly one hit, in leptos_shell.rs

# 3. 'unsafe-eval' (quoted) appears in no CSP string
grep -rn "'unsafe-eval'" crates/ --include='*.rs' | grep -vE 'assert|//|test' && echo "FOUND — stop" || echo "clean"

# 4. the negative, live
curl -s -D - -o /dev/null -X POST http://localhost:8787/magic-link/request | grep -i content-security-policy
#    must NOT contain wasm-unsafe-eval
```

Attach all four.

## 9. Required tests and evidence

Full gate set (the RFC 129 handoff §9 list), plus:

```sh
bash scripts/runtime-smoke-check.sh > evidence/runtime-smoke.log 2>&1     # now 12+ checks
make build-frontend                 > evidence/make-build-frontend.log 2>&1  # W4 changes the bundle; record with its command
```

**And the acceptance criterion — RFC 135 §9.1:** re-run your M2 probe
(`evidence-131-m2-first-render/probe.mjs`), **unmodified**, against the served
CSP:

- `=== VERDICT: MOUNTED ===`
- zero page errors
- `#root innerHTML len` > 0
- screenshot, with the real policy in place this time

Capture the console output in full. Then **W6 fires:** remove the directive →
the smoke check goes red **and** the probe reports `DID NOT MOUNT`; restore →
both green. Both halves, both instruments.

**Counts in prose are measurements** — attach the command for every number.

## 10. What must NOT be claimed

- **Not that the frontend works.** `/login` mounts and renders unstyled. One
  page, one engine, no interaction, no authenticated screen.
- **Not that it is styled.** It is not, and that is R3.
- **Not that it works on Cloudflare.** Miniflare only.
- **Not that R5 exists.** It is unblocked by this, not delivered by it.

## 11. Prohibited shortcuts

- No `'unsafe-eval'`. No `DEFAULT_CSP` edit. No `SECURITY_HEADERS_CSP` env
  override to sidestep the shell.
- No silent `mount_to_body` fallback (§7).
- No weakening the M2 probe to make it report `MOUNTED`.
- No `#[allow(...)]`, no `continue-on-error: true`, no `cargo fmt`.

## 12. Acceptance criteria

RFC 135 §9, items 1–8. Checked hardest: **item 1** (the probe reports
`MOUNTED` against the real CSP — the first time cesauth will have rendered under
its own policy) and **item 2** (a `server` route's CSP carries no WASM
directive — the scoping is the design, and §8.4 is its proof).

## 13. Known risks

RFC 135 §8, plus §7's drop trap. **If the work turns out materially larger than
scoped, stop and report.** In particular: if adding the three `web-sys`
features cascades into anything beyond `Cargo.toml`, report before proceeding.

## 14. Review request

Write the package to `.git-exclude/review-request/`. It must include:

The probe's verdict and console output **first** · implementation summary ·
changed files · deviations from §5 · every log from §9 · the four §8 assertions
· W6's pair on both instruments · the ADR-007 amendment text verbatim · the
bundle figure with its command · what remains unverified (§10) · requested
review focus.

**Do not cut a release, bump a version, or create a tag.** Implementation only;
the tag is the owner's alone.

Report the path only.
