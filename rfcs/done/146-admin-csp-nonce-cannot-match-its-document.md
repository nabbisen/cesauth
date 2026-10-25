# RFC 146 — The admin surface's CSP nonce cannot match its own document

**Status.** **Done** — landed at `3013ff3`, accepted 2026-10-25. Awaiting the
0.85.1 cut for a released version.
**Tier.** P1 — it is structural: on this path a matching nonce is not possible,
not merely absent.
**Size.** Small in design, mechanical in breadth: one signature, 78 call sites.
**Touches.** `crates/backend/src/routes/admin/console/render.rs`, its 78 callers
across 26 modules.
**Depends on.** Nothing. **Blocks RFC 145** — see §7.
**Found by.** The architect, 2026-10-25, while writing RFC 145's cycle-1 handoff.

## 1. Summary

`render::html_response(body: String)` generates a CSP nonce, stores it in the
render-context global, and puts it in the `Content-Security-Policy` header —
**after its caller has already rendered `body`**. In Rust the argument is
evaluated before the call, so the document was built from whatever nonce was in
the global beforehand.

**The body's nonce and the header's nonce are therefore different by
construction**, and the inline `<style nonce="…">` every admin page carries is
blocked by its own policy.

## 2. What is established

**The ordering.** `routes/admin/console/render.rs:49-72`:

```
pub fn html_response(body: String) -> Result<Response> {
    let csp_nonce = … CspNonce::generate() …;          // generated here
    cesauth_frontend::set_render_nonce(csp_nonce.as_str());
    let mut resp = Response::from_html(body)?;          // body built BEFORE the call
    … h.set("content-security-policy", &csp_header)     // carries csp_nonce
```

**The call shape.** Every caller looks like
`render::html_response(ui::admin::token_new_form(&principal, Some(err)))`
(`console/tokens.rs:120`). The template is evaluated first.

**The body's nonce comes from the global at render time.**
`crates/frontend/src/tenancy_console/frame.rs:76` — `let nonce =
crate::render_nonce();` — and `:107` — `<style nonce="{nonce}">`.

**The policy blocks a mismatch.** The header is
`style-src 'self' 'nonce-{n}'`. `'self'` does not authorise an inline
`<style>`; only a matching nonce does.

**The breadth.**

```
$ grep -rn 'html_response(' crates/backend/src --include='*.rs' | grep -v 'pub fn html_response' | wc -l
78
$ grep -rln 'html_response(' crates/backend/src --include='*.rs' | wc -l
26
```

**No caller sets the nonce first.** `grep -rn 'set_render_nonce'
crates/backend/src` returns four call sites: `leptos_shell.rs:110`,
`console/render.rs:59` (the one inside `html_response`), `me/totp/verify.rs:115`
and `magic_link/request.rs:238`. None of the 78 admin callers is among them.

**Consequence, by case.** In a fresh isolate the first such response renders
`nonce=""` under a header naming a real nonce. In every later response the body
carries the *previous* response's nonce. Both mismatch.

## 3. What I have NOT done, and it matters

**I have not observed this in a browser.** The reasoning above is from the code
and Rust's evaluation order, which is unambiguous, but this project's standard
is measurement and a confident chain of reasoning is exactly what produced the
false premise in RFC 142 §9.

**So the first deliverable is the measurement, not the fix** (§5.1). If the
measurement contradicts §2, that result supersedes this RFC and the fix is not
applied.

## 4. Why nothing caught it

- **Nothing asserts a document's nonce against its own response header.** Every
  nonce test in the tree sets the global and checks the template emits it
  (`templates/tests/rfc_006_and_later.rs`), which passes under this defect: the
  template is correct, and it is the pairing that is wrong.
- **A blocked inline stylesheet is silent.** The page returns 200 with complete
  markup; only the styling is missing, and the project has an accepted reason
  for admin pages to look plain (RFC 131 R3 owns styling, and RFC 145 §14 R2
  says a plainer screen is not a defect). **The excuse was already in place
  before the defect was found.**
- **The browser suite does not reach an authenticated admin screen.**

That second point is the one worth keeping: a defect whose symptom matches an
accepted explanation will not be reported by anyone.

## 5. Proposed design

1. **Measure first.** A host test that renders an admin page the way a handler
   does and asserts the body's `nonce="…"` equals the nonce in the response's
   `content-security-policy`. **It must fail before the fix.** That failure is
   the evidence this RFC is real; the same test is then the regression guard.
2. **Make the ordering structural, not remembered.** `html_response` takes a
   closure instead of a `String`:

   ```
   pub fn html_response(render: impl FnOnce() -> String) -> Result<Response>
   ```

   It generates the nonce, sets the global, *then* calls `render()`. The body
   cannot be built before the nonce exists, because the function owns both
   steps. Call sites become `html_response(|| ui::admin::token_new_form(…))`.
3. **Convert all 78 call sites.** Mechanical. The compiler finds every one.
4. **Do not** fix this by having callers set the nonce themselves. That is the
   same contract this defect proves nobody can be relied on to honour, and 78
   places would each have to remember it.

## 6. Non-goals

- **Not styling.** RFC 131 R3 owns how admin pages look. This RFC makes the
  styles they already carry take effect.
- **Not the other nonce finding.** RFC 143 §10.1 records that the TOTP POST
  error path inherits its nonce from the isolate. Same family, different path,
  separately scheduled. Do not merge them.
- **Not `leptos_html_shell`.** It sets the nonce before rendering and is
  correct.

## 7. Why this blocks RFC 145

RFC 145 converts 34 admin `GET` routes from a dead shell to server-rendered
pages **through `render::html_response`**. Landing it first would give every
converted page a blocked stylesheet, and RFC 145 §14 R2 would explain the
result away as "the server templates look plainer".

**RFC 145 cycle 1 is written and held** at
`rfcs/handoffs/145-.../cycle-1-handoff.md`. It is dispatched once this lands.
Fixing the mechanism before using it is cheaper than converting 34 routes onto a
broken one and discovering it later.

## 8. Acceptance criteria

1. The §5.1 test exists, **failed before the fix**, and passes after — both
   recorded.
2. `html_response` cannot be called with a pre-rendered body; the type forbids
   it.
3. All 78 call sites converted; `grep` for the old shape returns 0.
4. Every admin HTML response's body nonce equals its own CSP header's nonce.
5. No existing test weakened; the route count does not change.

## 9. Level

**Patch.** A control that was intended, documented and already paid for begins
working. No surface changes.

## 10. Measured, accepted, closed (2026-10-25)

**§3's caveat is discharged: the defect was observed, not inferred.** Driving a
running Worker through both named frames' error-redisplay paths, pre-fix:

| Frame | Body `nonce` | CSP header `'nonce-…'` |
|---|---|---|
| `admin::frame::admin_frame` | `TfI21VUa71JVvFS2ADMzNg` | `3rCw7Me3vW6Ky_ts81GFzA` |
| `tenancy_console::frame::…_for` | `3rCw7Me3vW6Ky_ts81GFzA` | `nuOjtdAxX7w46T4fYu-YOA` |

**The tenancy request's body nonce is exactly the admin request's header
nonce** — the stale-isolate-global mechanism caught in the act, which is
stronger evidence than §2 asked for. Post-fix both frames match, and three
consecutive requests produced three distinct matching pairs.

**§2's test as written could not run.** `worker::Response`/`Headers` wrap
`web_sys` types with no host constructor — `cannot call wasm-bindgen imported
functions on non-wasm targets` — so no `cargo test` can read a real response's
headers on this target, fixed or broken. The handoff required an impossible
test; the implementer proved the impossibility with a probe instead of quietly
substituting. The gate was satisfied by the live run and the regression guard by
a pure core, `render_with_nonce(impl FnOnce() -> String) -> (String, String)`,
which is host-testable precisely because it returns no `Response`.

**The count was 77, not the 78 the handoff stated.** The architect's grep
included a string literal in `audit/tests.rs:289` quoting
`render::html_response(…)` as audit-scanner test data. The authoritative method
is the compiler's error count against the new signature before any site is
converted.

Gates at `3013ff3`, re-run independently: **1,552 host tests** (1,549 + 3),
`migration_chain` **31**, routes **193**, clippy / backend-wasm32 / `deny` /
`audit` / drift / mdbook all **exit 0**. Nonce-masked diffs of both frames'
bodies: **0 lines** — nothing changed but the nonce. Review:
`.git-exclude/reviewed/146-review.md`.

### 10.1 One residue, dormant and recorded

`invitations.rs:199` remains `html_response(|| body)` with the body pre-built,
because the `Valid` arm's `csrf::mint()?` cannot propagate through a
`FnOnce() -> String` and hoisting it would make all five outcomes fallible — a
behaviour change the handoff's §5 told the implementer to report rather than
make. **Dormant:** that page is raw `<html><body>` string literals with no
template, no `render_nonce()` call and no `<style>`, so it has no nonce to
mismatch.

The type cannot forbid `html_response(|| precomputed)`, so if that page ever
gains a nonced frame the defect returns silently. A check for
`html_response(|| <bare identifier>)` closes it and belongs with **RFC 145
cycle 3**, which is already extending the same script.
