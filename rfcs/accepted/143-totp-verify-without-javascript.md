# RFC 143 — A no-JavaScript user is stranded at the second factor

**Status.** Accepted — approved by the owner 2026-09-24.
**Tier.** P1 · Category A — it locks a user out of their own account.
**Size.** Small.
**Touches.** `crates/backend/src/routes/me/totp/verify.rs`, a template,
`scripts/route-contracts-check.sh`.
**Depends on.** Nothing. Independent of RFC 131 R3.
**Found by.** The 2026-09-24 state review.

## 1. Summary

`GET /me/security/totp/verify` is one of three routes exempt from RFC 132's
render-server-side rule. A user who signs in **without JavaScript** and has TOTP
enrolled reaches a second-factor page that requires JavaScript, and **cannot
complete sign-in at all**.

## 2. What is established

- The exemption list is `scripts/route-contracts-check.sh:153-155`: `GET /`,
  `GET /login`, `GET /me/security/totp/verify`.
- RFC 132 §13 q1 was decided on 2026-09-24, and RFC 131 R3 now converts the
  first two.
- The third is different in kind. `/` and `/login` degrade a user to a slower
  path; this one **strands** them: the first factor has already succeeded, the
  gate cookie is set, and the only way forward needs a script.
- The page is already a decision function plus a shell:
  `decide_verify_get` returns `RenderPage` or `StaleGate`
  (`routes/me/totp/verify.rs:77-120`), and only the rendering is client-side.
- **Superseded by §9 (measured 2026-10-25): the page itself already exists.**
  Not a pattern to follow — `templates/totp.rs::totp_verify_page_for` is the
  whole screen, locale-aware, with the recovery form inline, and it is already
  served in production by the POST wrong-code path (`verify.rs:471`).

## 3. Why it is worth its own RFC rather than R3's backlog

R3 is a large programme — styling, component adoption, the first wired dialog.
This is a lockout, it is independent of every part of that, and binding it to R3
would delay a correctness fix behind a design programme. A TOTP code is six
digits in a form.

## 4. Proposed design

1. **Server-render the verify page**: the six-digit form, its CSRF token, and the
   error state, following `magic_link_sent_page`'s shape. The existing
   `decide_verify_get` / `decide_verify_post` split already separates the
   decision from the rendering, so this is a template and a wiring change.
2. **The recovery-code path on the same screen** must work without JavaScript
   too, or the fallback has a fallback that does not work. (§9.2: in the
   template it already does; it is the CSR page that broke it.)
3. **Remove the route from `E3_EXEMPT`**, so the existing gate enforces it. This
   is the acceptance test: the check fails if the page regresses.
4. **Keep the client enhancement** where it adds something (autofocus,
   auto-submit at six digits) — as enhancement, never as the mechanism.

## 5. Non-goals

- Not TOTP enrolment (`/me/security/totp/enroll`), which is a different screen
  and not on the sign-in path.
- Not styling. R3 owns that, and this must not wait for it.
- Not the other two exemptions. R3 owns them.

## 6. Testing strategy

- The existing decision tests are unchanged.
- A server-rendered response for a live gate contains the form and a CSRF token;
  a stale gate still redirects.
- **The exemption removal is the gate**: `route-contracts-check.sh` passes with
  the route no longer exempt, and fails if the handler reverts to the shell.
- If the browser suite can reach an authenticated screen by then, a no-JS
  assertion belongs there; if it cannot, say so rather than claiming coverage.

## 7. Acceptance criteria

1. The full sign-in path — magic link, then TOTP — completes with JavaScript
   disabled.
2. `/me/security/totp/verify` is no longer in `E3_EXEMPT`, and the check passes.
3. No existing test is weakened.

## 8. Level

**Patch.** A user who could not complete sign-in now can.

---

## 9. Measured before dispatch (architect, 2026-10-25)

I went to write the handoff, found §2's last bullet contradicted
`route-contracts.md:66`, and stopped to measure. The lockout in §1 is real and
unchanged. Almost everything else about the shape of the work was wrong, and in
the project's favour: **the page does not need to be written.**

### 9.1 The screen already has two renderers, and which one you see depends on whether you have made a typo

| Path | Code | Renders |
|---|---|---|
| `GET /me/security/totp/verify` | `get_handler` → `leptos_html_shell` (`verify.rs:129-152`) | the **CSR shell** — needs JavaScript |
| `POST`, wrong code | `templates::totp_verify_page_for` (`verify.rs:471`) | the **server-rendered page**, locale-aware, status 200 |

So the server-rendered second-factor page is **already in production**. A no-JS
user is stranded not because the page does not exist, but because the only way
to reach it is to submit a form they cannot see.

That also means a user with JavaScript sees the Leptos page first and, after one
wrong digit, a differently-built page for the same step. Two implementations of
one screen is the condition that produced §9.2.

### 9.2 The CSR page is a regression against the template it shadows

**The recovery path is dead.** The template puts the recovery form *inline* —
a `<form method="POST" action="/me/security/totp/recover">` inside the
`<details>`, which matches the POST-only route (`lib.rs:234`). The CSR page
replaced that form with a link: `<a href="/me/security/totp/recover">` at
`pages/totp.rs:193-194`. Clicking it issues a **GET** to a path with no GET
handler, so it falls through to `.or_else_any_method_async("/*catchall")` and
returns **`Response::error("not found", 404)`** (`lib.rs:492-494`). Nothing
rescues it: `wrangler.toml`'s `[assets]` sets `directory` only — there is no
`not_found_handling`, so no SPA rewrite — and `app.rs:63-65` registers routes
for `enroll`, `verify` and `disable` but **not** `recover`. Dead on the server
and dead in the client router.

A user who has lost their authenticator is the exact user this link is for, and
for them the only remaining door returns a bare 404.

**Japanese was dropped on this screen.** `grep -c 'MessageKey::'`:
`templates/totp.rs` **29**, `pages/totp.rs` **0**. The template is locale-aware
and has en/ja tests (`templates/tests/i18n.rs:60,70`); the CSR page hardcodes
seven English strings ("Authentication code", "Verify", "Lost access to your
authenticator?", …). A `ja` user reaching the second factor gets English — and
then Japanese again if they mistype, because that is the template.

### 9.3 `route-contracts.md:66` must **not** be changed

It declares the route `server` with view `totp_verify_page_for`. That is why the
route needs an E3 exemption at all: E3 applies only to `server`-declared routes,
which is why `:63` enroll and `:70` disable — both declared `client` — need no
exemption. The row is the **intent**; the exemption is the acknowledged debt; the
handler is the outlier.

A reader who finds the mismatch may be tempted to "fix the documentation" to say
`client`. That would make the gate green, delete the record of the lockout, and
leave the user stranded. **Landing this RFC makes the row true.** The row is
correct as written and stays as written.

### 9.4 The design, narrowed — this supersedes §4.1, §4.2 and §4.4

1. **`get_handler` renders the template the POST path already renders.** Its
   `RenderPage` arm becomes `get_json_handler`'s `RenderPage` arm
   (`verify.rs:172-184`) with HTML instead of JSON: `csrf::mint()`, then
   `totp_verify_page_for(&token, None, crate::i18n::resolve_locale(&req))`, then
   `set-cookie: csrf::set_cookie_header(&token)` and `cache-control: no-store`.
   The minted token must reach the cookie, or the form it renders cannot pass
   its own CSRF check. `StaleGate` keeps `clear_gate_and_redirect("/login")`.
2. **Delete the CSR page**: `TotpVerify` in `pages/totp.rs` and its
   `<Route>` at `app.rs:64`. One renderer owns the screen. Keeping both is what
   produced a 404 link and a lost locale, and no amount of care keeps two
   hand-written copies of one screen in step.
3. **Delete `GET /me/security/totp/verify.json`** — handler, registration
   (`lib.rs:228`), and its row at `route-contracts.md:67`. Its **only** consumer
   is `pages/totp.rs:128`, which step 2 deletes, and the server-rendered page
   embeds the token the endpoint existed to fetch. Leaving it would create a new
   instance of the class RFC 141 §13 is cleaning up this cycle.
4. **Remove the route from `E3_EXEMPT`**, leaving two entries, and delete its
   comment block (`route-contracts-check.sh:147-152`). Do not widen the facility.
5. **§4.4 is narrowed.** Progressive enhancement by script — autofocus,
   auto-submit at six digits — is allowed, as a script layered on the rendered
   form. A **second full implementation** of the screen is not, under any
   justification. That is the defect, not a detail of it.

`enroll` and `disable` keep their CSR pages and their `.json` endpoints: both
are declared `client`, neither is on the sign-in path, and both are out of scope
(§5).

### 9.5 What this changes in the gates

- **Route count falls 194 → 193**, from step 3's one documented route. The
  handoff states the expected figure so a changed count is a result, not a
  surprise.
- `E3_EXEMPT` goes from **3** entries to **2**.
- Host tests: the template's existing tests are unchanged and already cover the
  en/ja rendering. New coverage is the handler's, not the template's.

### 9.6 Level — unchanged

**Patch**, and now for three reasons rather than one: a no-JS user completes
sign-in; a user who lost their authenticator reaches a recovery form instead of
a 404; and a `ja` user reads Japanese at the second factor. All three are
restorations of behaviour the server template already implements. No capability
is added.
