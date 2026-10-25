# Developer Handoff — RFC 146, the admin CSP nonce

**Governing RFC.** `rfcs/accepted/146-admin-csp-nonce-cannot-match-its-document.md`
**Target release.** 0.85.1 — **and why that level:** **patch.** A control that was
intended, documented and already paid for begins working. No surface changes.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **This unblocks RFC 145 cycle 1.**

---

## 1. Purpose

`render::html_response(body: String)` generates a CSP nonce, stores it in the
render-context global, and puts it in the `Content-Security-Policy` header —
**after** its caller has rendered `body`. The body is an argument, and Rust
evaluates arguments before the call, so the document was built from whatever
nonce the global held beforehand.

Body nonce and header nonce therefore differ **by construction**, and the inline
`<style nonce="…">` every admin page emits is blocked by its own `style-src`.

## 2. Step 1 is to prove me wrong or right. Do not fix anything first.

**I have not observed this in a browser.** The reasoning is from the code and
Rust's evaluation order, but this project's standard is measurement, and a
confident chain of reasoning is exactly what produced the false premise in
RFC 142 §9.

**Deliverable 1 is a host test that fails.** Render an admin page the way a
handler does — call a template, pass the result to `html_response` — then
extract the `nonce="…"` from the returned body and the `'nonce-…'` from the
returned response's `content-security-policy`, and assert they are **equal**.

- **If it fails:** the defect is real, you have the regression guard, continue
  to §4.
- **If it passes:** **stop and report.** RFC 146 is wrong, I withdraw it, and
  RFC 145 cycle 1 is unblocked as written. That is a good outcome, not a wasted
  cycle, and it is why this is deliverable 1 rather than a test added after the
  fix.

Record the failure output verbatim in evidence. It is the whole basis of the
RFC.

## 3. Facts already measured — do not re-derive

| Fact | Command | Result |
|---|---|---|
| The ordering | read `routes/admin/console/render.rs:49-72` | `CspNonce::generate()` → `set_render_nonce` → `Response::from_html(body)` → header set |
| The call shape | `console/tokens.rs:120` | `render::html_response(ui::admin::token_new_form(&principal, Some(err)))` |
| The body reads the global at render time | `tenancy_console/frame.rs:76,107` | `let nonce = crate::render_nonce();` … `<style nonce="{nonce}">` |
| Call sites | `grep -rn 'html_response(' crates/backend/src --include='*.rs' \| grep -v 'pub fn html_response' \| wc -l` | **78** |
| Modules | `grep -rln 'html_response(' …` | **26** |
| No caller sets the nonce first | `grep -rn 'set_render_nonce' crates/backend/src` | 4 sites: `leptos_shell.rs:110`, `console/render.rs:59` (inside the helper), `me/totp/verify.rs:115`, `magic_link/request.rs:238` |

## 4. Resolved decisions — do not re-open

**D1. The fix is a closure, not a convention.**

```
pub fn html_response(render: impl FnOnce() -> String) -> Result<Response>
```

Generate the nonce, `set_render_nonce`, **then** call `render()`. The body cannot
exist before the nonce, because the function owns both steps.

**D2. Do not fix this by having callers set the nonce.** 78 places would each
have to remember a rule this defect proves nobody remembers. RFC 146 §5.4
rejects it.

**D3. All 78 call sites convert** to `html_response(|| …)`. The compiler finds
every one; that is the point of changing the signature rather than adding a
second function.

**D4. Do not add an overload or keep the old signature.** If
`html_response(String)` still exists, the defect still exists.

**D5. Out of scope: the other nonce finding.** RFC 143 §10.1 — the TOTP POST
error path inherits its nonce from the isolate because `decide_verify_post`
never sets one. Same family, different path, and it is scheduled separately. Do
not fix it here, and do not reproduce its shape.

**D6. `leptos_html_shell` is correct** — it sets the nonce before rendering.
Leave it alone.

## 5. Report-and-stop gates

1. **The §2 test passes before any fix.** Stop; the RFC is wrong.
2. **A call site cannot be expressed as a closure** — e.g. the body is built
   from something borrowed in a way the closure cannot capture. Report the site;
   do not restructure the caller's logic to force it.
3. **Converting reveals a caller that renders two bodies**, or renders then
   discards. Report it rather than guessing the intent.
4. **The CSP header's own content needs changing** to make a page work. That is
   not this RFC; report it.

## 6. Change scope

- `crates/backend/src/routes/admin/console/render.rs` — `html_response`'s
  signature and body order.
- The **78** call sites across **26** modules — mechanical.
- Tests, per §8.
- **No change to** any template, any CSP policy string, `leptos_html_shell`,
  `json_response`, or the TOTP paths.

## 7. Task detail worth stating explicitly

- `json_response` (`render.rs:82`) does not render HTML and does not take part.
- Several call sites are inside `match` arms returning early
  (`config.rs:255,263`). `html_response(|| …)` works unchanged there; the
  closure is evaluated inside the helper, not at the match.
- Where a caller already computed an expensive value before calling, it may be
  captured by the closure rather than recomputed inside it. Capturing is fine;
  **rendering** is what must happen inside.
- Keep each closure to the template call. A closure that also does I/O or
  fallible work changes when errors surface.

## 8. Required tests and evidence

1. **The §2 test**, with its **failing** run recorded, then passing.
2. **The type forbids the old shape**: `html_response(some_string)` does not
   compile. A short note stating you confirmed this is enough; a test that fails
   to compile is not a test this project can run.
3. **One assertion per distinct admin frame** that emits a nonce — at minimum
   the `tenancy_console` frame and whichever frame the operator console uses —
   so a second frame with the same bug cannot hide behind the first one's test.
4. **No behaviour change beyond the nonce.** The body bytes other than the nonce
   value, the status, and every other header are unchanged. Show this by diffing
   a rendered page before and after with the nonce masked.
5. Full gate set. Route count unchanged at **193**.

**A count in prose carries its command**, including the 78 once you have
converted them.

## 9. What must NOT be claimed

- **Not** that the admin console is now styled. This makes the stylesheet the
  pages already carry take effect; whether they look finished is RFC 131 R3's
  question.
- **Not** that CSP is now correct everywhere. RFC 143 §10.1 is open, and this
  RFC does not touch it.
- **Not** that the browser suite verifies it. It does not reach an
  authenticated admin screen. If you can drive one page with `curl` against
  `wrangler dev` and compare the body's nonce to the response header, that is
  worth more than any assertion here — but say which page.

## 10. Acceptance criteria

1. The §2 test exists, failed before the fix, and passes after — both recorded.
2. `html_response` cannot be called with a pre-rendered body.
3. All **78** call sites converted; a grep for the old shape returns 0.
4. Every admin HTML response's body nonce equals its own CSP header's nonce.
5. No existing test weakened; route count **193**.

## 11. Known risks

**R1 — the measurement contradicts the RFC.** Genuinely possible. §2 and §5.1
exist so that this costs one test, not one cycle.

**R2 — 78 mechanical edits.** The risk is not difficulty, it is attention
fatigue near the end. The compiler catches a missed conversion, so trust it
rather than re-reading all 26 modules.

## 12. Review request

`.git-exclude/review-request/146-report.md`, evidence under
`.git-exclude/review-request/evidence-146/`.

Lead with the §2 result — the failing run, verbatim — because everything else
depends on it. Then the 78 with its command, the before/after nonce-masked
diff, and anything you could not verify.
