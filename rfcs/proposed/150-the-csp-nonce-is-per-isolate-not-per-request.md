# RFC 150 — Outside the admin console, the CSP nonce is per-isolate, not per-request

**Status.** **Proposed** — awaiting owner authorization.
**Tier.** P1 — RFC 006's stated invariant is a *per-request* nonce. On seven
HTML responders it is per-isolate, which is a different and weaker thing.
**Size.** Small per site; the gate is the lasting part.
**Touches.** `crates/backend/src/routes/{me/totp/verify.rs, me/totp/enroll.rs,
magic_link/request.rs, magic_link/verify.rs, admin/admin_login.rs}`,
`scripts/route-contracts-check.sh` (or a new check),
`crates/backend/src/routes/admin/console/render.rs` (the helper to reuse).
**Depends on.** RFC 006 (the invariant), RFC 146 (**the fix already exists** —
`render_with_nonce`, built for the console's 77 call sites).
**Found by.** The architect, 2026-10-25, recorded in RFC 143 §10.1 as
"needs measuring, not asserting"; breadth established 2026-10-27.

## 1. Summary

The security-headers middleware builds the `Content-Security-Policy` header by
**reading back** a nonce the handler was supposed to store in a thread-local
before rendering (`lib.rs:566-600`). A handler that never stores one does not
produce an error: the middleware uses whatever is in that thread-local, which in
a warm isolate is **the nonce from a previous request** — possibly a previous
request from a different user.

Because the template reads the same thread-local, **header and document always
agree**, so nothing looks broken. That is precisely why this survived: the
symptom of a per-request nonce degenerating into a per-isolate nonce is no
symptom at all.

RFC 143 §10.1 recorded one instance and said it needed measuring. It is seven.

## 2. What is established

**Only four call sites set the nonce**, one of which is RFC 146's own helper:

```
$ grep -rn "set_render_nonce" crates/backend/src --include="*.rs" | grep -v "^.*://"
routes/magic_link/request.rs:238
routes/admin/console/render.rs:73      # inside RFC 146's render_with_nonce
routes/leptos_shell.rs:110
routes/me/totp/verify.rs:115           # inside decide_verify_get, not the POST path
```

**Eleven HTML responders exist outside the console helper:**

```
$ grep -rn "from_html" crates/backend/src --include="*.rs" | grep -vc "tests\?\.rs\|tests/"
11
```

Resolved by hand, per function — **a script that follows only one level of
indirection gets two of these wrong in both directions, so the table below was
checked by reading each function**:

| Site | Enclosing fn | Nonce set before render? |
|---|---|---|
| `leptos_shell.rs:159` | `leptos_html_shell` | **yes** — `:110`, same fn, earlier |
| `console/render.rs:110` | `html_response` | **yes** — via `render_with_nonce` (`:73`), RFC 146 |
| `me/totp/verify.rs:170` | `get_handler` | **yes** — via `decide_verify_get` (`:115`) |
| `magic_link/request.rs:240` | `request` | **yes** — `:238`, immediately before |
| `magic_link/request.rs:147` | `request` | **no — same fn, but an early return at `:147`, 91 lines *before* the `set` at `:238`** |
| `me/totp/verify.rs:477` | `post_handler` | **no** — `decide_verify_post` (`:274`) sets none |
| `me/totp/enroll.rs:474` | `post_confirm_handler` | **no** |
| `me/totp/enroll.rs:508` | `post_confirm_handler` | **no** |
| `magic_link/verify.rs:38` | `form_retry` | **no** |
| `magic_link/verify.rs:48` | `html_terminal_error` | **no** |
| `admin/admin_login.rs:113` | `login_form_response` | **no — and see §3** |

**The documents in question do carry nonce-ed inline content.** Five templates
read `render_nonce()` and emit it: `admin/frame.rs:106,138`,
`templates/chrome.rs:313,323`, `tenancy_console/frame.rs:76,107`,
`tenant_admin/frame.rs:121,158`, and `templates/totp.rs:139,178` — the last an
inline **`<script defer nonce="{nonce}">`**, not a style. The TOTP enrol and
verify POST paths render through it.

**An absent nonce does not fail loudly.** `lib.rs:594-600`:

```rust
let nonce_str = cesauth_frontend::render_nonce();
let nonce = if !nonce_str.is_empty() { Some(CspNonce::from_str(&nonce_str)) } else { None };
```

`None` means the configured CSP is used unchanged. The configured default is
**strict** — `DEFAULT_CSP` contains `default-src 'none'` and no
`'unsafe-inline'`, both asserted (`crates/core/src/security_headers.rs:347,362`).
**So my first hypothesis was wrong:** a missing nonce does not silently relax
the policy. It blocks the inline content instead.

## 3. The two consequences, stated separately

**(a) Cold isolate — a degraded page.** On an isolate whose first request hits
one of the seven, the thread-local is empty, the CSP carries no nonce, and the
document's `nonce=""` matches nothing. The inline `<style>` or `<script>` is
blocked. For `templates/totp.rs:178` that is a **script**, so the question is
whether anything on the TOTP pages depends on it — RFC 143 made that surface
work without JavaScript, which may mean the answer is "nothing", and that is
worth knowing rather than assuming.

**(b) Warm isolate — a nonce that is not per-request.** The header and document
both carry the previous request's value. Header and document agree, the page
renders, and the nonce is no longer unpredictable per response. A nonce's whole
contribution is that an injected inline fragment cannot know it; one that
persists across requests in an isolate may be learned from one response and
still be accepted by a later one, including a later one served to a different
user. **Stated at its honest level: this weakens a defence-in-depth control. It
is not a direct vulnerability** — using it needs an inline-injection foothold,
isolate co-residency and timing — but it means RFC 006's invariant is not met
where the code claims it is.

**`admin_login.rs` is a third, simpler case.** Its HTML is a hard-coded string
whose `<style>` tag (`:98`) **carries no `nonce` attribute at all**. Under either
CSP it is blocked, so the operator login page should be rendering unstyled
today. That is a falsifiable prediction and §4's first task.

## 4. Direction

**Measure before changing anything.** Three measurements, in this order:

1. Fetch `/admin/login` against `wrangler dev`, read the `Content-Security-Policy`
   header and confirm from the browser console whether the inline style is
   blocked. This settles §3's prediction and costs one request.
2. For the TOTP POST paths, reach them on a **cold** isolate and record whether
   the response's CSP has a nonce and whether the document's matches. RFC 146's
   lesson applies: `worker::Response` cannot be built on the host
   (`cannot call wasm-bindgen imported functions on non-wasm targets`), so the
   measurement is a live run, and only the pure decision is host-testable.
3. Confirm reuse directly: two requests to a nonce-less responder on the same
   warm isolate, asserting the two CSP nonce values are **equal**. Equality is
   the defect; a test asserting inequality is the guard.

**Then apply RFC 146's fix.** `render_with_nonce(render) -> (String, String)` is
already pure, already host-tested (`console/render.rs:164-206`), and already
proven across 77 call sites. The seven sites should reach their HTML through it
rather than each growing its own `set_render_nonce` call — a per-site fix is
what produced this spread.

**Then the gate**, which is the part that lasts. A check that **`Response::from_html`
is not reached except through the nonce-setting helper**, in the shape of RFC 132's
E3: a named exemption list that must shrink, and a hard failure when the
resolver cannot decide. E3's own history is the warning here — RFC 145 §11.2
showed E3 silently passing on a wrapper-shaped call for all 35 routes it was
believed to cover, so **this check must re-verify its own premise each run** and
exit non-zero when it cannot, exactly as `resolve_body_shell_status` now does.

## 5. Also recorded in RFC 143 §10.1, carried here

**`decide_verify_get` is a decision function with a side effect** — it sets the
render nonce (`:115`) — and returns `StaleGate`, signing the user out, if the
nonce RNG fails (`:109`). Both belong to this RFC: the side effect is why the
GET path happens to be correct and the POST path is not, and a failed RNG
should not be an authentication outcome. The third §10.1 item (six of nine
mockup view models unused) stays in RFC 131 R3's scope.
