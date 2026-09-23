# RFC 143 — A no-JavaScript user is stranded at the second factor

**Status.** Proposed
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
- A server-rendered OTP form already exists as a pattern —
  `templates/login.rs::magic_link_sent_page` renders a code input with its CSRF
  token.

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
   too, or the fallback has a fallback that does not work.
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
