# Developer Handoff — RFC 143, the second factor without JavaScript

**Governing RFC.** `rfcs/done/143-totp-verify-without-javascript.md` (moved
to `done/` 2026-10-25 when C1-143 was accepted) —
**read §9 first.** §9 was measured on 2026-10-25 and supersedes §4.1, §4.2 and
§4.4. The original §4 would have you write a template that already exists.

**Target release.** 0.85.0 — **and why that level:** 0.85.0 is a **minor**
because RFC 141 adds a capability (the client-registration API). **RFC 143's own
level is patch:** every change here restores behaviour the server-rendered
template already implements. No capability is added, no surface is created; one
documented route is *removed* (§3 D3).

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing.

---

## 1. Purpose

A user who signs in with JavaScript disabled and has TOTP enrolled reaches a
second-factor page that requires JavaScript. The first factor has already
succeeded and the gate cookie is set, so they are **stranded mid-sign-in** with
no way forward and no way back.

Make `GET /me/security/totp/verify` serve the server-rendered page that the POST
wrong-code path already serves, and delete the client-rendered duplicate.

## 2. Why this matters

This is the only route on the sign-in path still exempt from RFC 132's
render-server-side rule, and the exemption was granted (C1-132 ruling 1,
2026-09-09) with that debt written down. Paying it also closes two defects the
duplicate introduced — a recovery link that returns 404 and a locale that was
silently dropped (§4).

The deeper reason: one screen currently has **two hand-written
implementations**, and which one a user sees depends on whether they have
mistyped a digit. That is the condition that produced both defects, and it will
produce the next one. This change leaves one renderer in charge.

## 3. Resolved decisions — do not re-open

**D1. The template is not written; it exists.**
`crates/frontend/src/templates/totp.rs:223` —
`totp_verify_page_for(csrf_token, error, locale)` renders the heading, the intro,
the error block, the six-digit form with its CSRF token, **and the recovery form
inline**. It is locale-aware (29 `MessageKey` uses) and already has en/ja tests.
Use it as-is. Do not write a new template, do not copy it, do not "improve" it
in this cycle.

**D2. The CSR page is deleted, not fixed.** `TotpVerify` in
`crates/frontend/src/pages/totp.rs` and its `<Route>` at
`crates/frontend/src/app.rs:64`. Not kept as a fallback, not feature-flagged.

**D3. `GET /me/security/totp/verify.json` is deleted** — `get_json_handler`
(`verify.rs:155-185`), its registration (`lib.rs:228`), and its row at
`docs/src/expert/route-contracts.md:67`. Its only consumer is the page D2
deletes, and the server-rendered page embeds the token the endpoint existed to
hand out.

**D4. `docs/src/expert/route-contracts.md:66` does not change.** It declares the
route `server` with view `totp_verify_page_for`. That declaration is the
*intent*; today the handler is the outlier. This work makes the row true. See
§11.

**D5. Client-side enhancement is allowed; a second implementation is not.** A
small script that adds autofocus or auto-submit at six digits, layered on the
rendered form, is in scope if you want it. Rebuilding the screen in Leptos is
not, under any justification.

**An implementer must inherit no unresolved decisions.** If something here is
genuinely undecided, stop and report it (§5) rather than choosing.

## 4. Facts already measured — do not re-derive

| Fact | Command I ran | Result |
|---|---|---|
| The GET serves the shell | `sed -n '129,152p' crates/backend/src/routes/me/totp/verify.rs` | `RenderPage` → `leptos_html_shell(...)` |
| The server page is already live | `grep -rn 'totp_verify_page_for' crates --include='*.rs'` | called at `verify.rs:471` — the POST **wrong-code** path, status 200 |
| The recovery link is dead | route table + catchall | `<a href>` at `pages/totp.rs:193-194` issues a GET; `lib.rs:234` registers **POST only**; unmatched → `.or_else_any_method_async("/*catchall")` → `Response::error("not found", 404)` (`lib.rs:492-494`) |
| Nothing rescues that GET | `grep -n 'not_found_handling' wrangler.toml` | **no match** — `[assets]` sets `directory` only, so there is no SPA rewrite; and `app.rs:63-65` has no `recover` route |
| The template does recovery correctly | `sed -n '254,268p' crates/frontend/src/templates/totp.rs` | an inline `<form method="POST" action="{recover_url}">` inside the `<details>` |
| The locale regression | `grep -c 'MessageKey::'` on each file | `templates/totp.rs` **29**, `pages/totp.rs` **0** (seven hardcoded English strings) |
| Why this route needs an E3 exemption and its siblings do not | `grep -n 'totp' docs/src/expert/route-contracts.md` | `:66` verify is declared **`server`**; `:63` enroll and `:70` disable are declared **`client`**, and E3 only applies to `server` rows |
| `verify.json` has exactly one consumer | `grep -rn 'verify\.json' crates --include='*.rs'` | `pages/totp.rs:128`, plus its own handler and registration |
| The decision function is unaffected | `crates/backend/src/routes/me/totp/verify/tests.rs` | the `decide_verify_get` tests test the decision, not the rendering |

**Baseline at `b16c2b1`:** host tests **1,542**, route contracts **All 194
routes**, `E3_EXEMPT` **3** entries, clippy/deny/audit/drift/mdbook green.

## 5. Report-and-stop gates

Stop, write what you found, and report — do not work around any of these:

1. **The minted CSRF token does not reach the cookie**, or the rendered form
   fails its own CSRF check on submit. That is the one way this change can break
   a working flow (§14 R1).
2. **The route count does not land on 193** (§9.5). Report the figure with the
   command.
3. **Removing the `E3_EXEMPT` entry does not make the check pass** — that means
   the handler still reaches the shell somewhere, and the fix is incomplete.
4. **Anything suggests `route-contracts.md:66` should change.** It should not
   (D4). Report instead.
5. **Deleting the CSR page breaks a consumer you did not expect.** Name it.

## 6. Change scope

- `crates/backend/src/routes/me/totp/verify.rs` — `get_handler`'s `RenderPage`
  arm renders the template; `get_json_handler` deleted.
- `crates/backend/src/lib.rs` — the `verify.json` registration (`:228`) deleted.
- `crates/frontend/src/pages/totp.rs` — `TotpVerify` and its data fetch deleted.
- `crates/frontend/src/app.rs` — the `:64` `<Route>` and the `TotpVerify` import
  deleted.
- `scripts/route-contracts-check.sh` — the verify entry removed from
  `E3_EXEMPT`, and its comment block (`:147-152`) deleted with it.
- `docs/src/expert/route-contracts.md` — the `verify.json` row (`:67`) deleted.
  **Line 66 untouched.**
- Tests, per §10.

Land the `E3_EXEMPT` removal **last**, so the tree is green when it goes in
rather than merged red.

## 7. Explicit non-change scope

- **`route-contracts.md:66`** (D4).
- **`templates/totp.rs`** — no edits. Not styling, not wording, not the markup.
- **`enroll` and `disable`** — both declared `client`, neither on the sign-in
  path, both keep their CSR pages and their `.json` endpoints (RFC 143 §5).
- **`GET /` and `GET /login`** — the other two `E3_EXEMPT` entries. RFC 131 R3
  owns them. Leave both entries in place.
- **The `decide_verify_get` / `decide_verify_post` split** — the decision
  functions do not change. Only the rendering does.
- **Styling.** RFC 131 R3 owns it. The server page may look plainer than the
  Leptos page did; that is accepted and is not a regression to fix here.

## 8. Task detail worth stating explicitly

`get_handler`'s `RenderPage` arm becomes the HTML form of
`get_json_handler`'s `RenderPage` arm (`verify.rs:172-184`). That arm already
does the three things the page needs:

```
let csrf_token = csrf::mint()...;                                  // 1
let locale = crate::i18n::resolve_locale(&req);                    // 2 (as verify.rs:466 does)
let html = templates::totp_verify_page_for(&csrf_token, None, locale);
let mut resp = Response::from_html(html)?;
resp.headers_mut().append("set-cookie", &csrf::set_cookie_header(&csrf_token)).ok();  // 3
resp.headers_mut().set("cache-control", "no-store").ok();
```

- `error` is `None` on a fresh GET. The POST path supplies `Some(..)`.
- **`set-cookie` is not optional.** The template embeds the minted token in the
  form; `csrf.rs` compares the submitted token against the cookie. Mint without
  setting the cookie and every submission fails — a worse outcome than today's.
- `cache-control: no-store` keeps a CSRF token out of a shared cache.
- `StaleGate` keeps `clear_gate_and_redirect("/login")` exactly as now.
- The `error` parameter means the POST failure path needs no change at all. Do
  not touch it.

## 9. Assert machine-checkable things mechanically

Where this handoff names a constant, assert it rather than eyeballing it:

```
# the exemption really is gone, and the other two really remain
grep -c 'GET /me/security/totp/verify' scripts/route-contracts-check.sh   # expect 0
grep -c 'GET /login'                   scripts/route-contracts-check.sh   # expect 1

# no shell call survives in the verify handler
grep -c 'leptos_html_shell' crates/backend/src/routes/me/totp/verify.rs   # expect 0

# verify.json is gone from code, router and contract
grep -rc 'verify\.json' crates/backend/src/lib.rs docs/src/expert/route-contracts.md

# line 66 is byte-identical to the baseline
git diff b16c2b1 -- docs/src/expert/route-contracts.md | grep -c '^[-+].*totp/verify |'   # expect 0
```

## 10. Required tests and evidence

1. **A live gate GET returns the form server-side.** The response body contains
   the six-digit input and a CSRF token, and **does not** contain the shell's
   script tag.
2. **The minted token round-trips.** The token embedded in the rendered form
   equals the one in the `set-cookie` header. This is the §5.1 risk, so it gets
   its own assertion rather than being implied by a passing flow.
3. **A stale gate still redirects.** Unchanged behaviour, asserted so the change
   cannot quietly alter it.
4. **The recovery form is present and is a POST form** in the GET response —
   i.e. the 404 link cannot come back. Assert the `method="POST"` form, not just
   the word "recover".
5. **The locale is honoured on the GET.** An `Accept-Language: ja` GET renders
   the Japanese chrome; `en` renders English. This is the regression §4 found,
   so it needs a positive assertion at the handler, not only at the template.
6. **`route-contracts-check.sh` passes with the route no longer exempt** — this
   is RFC 143's stated acceptance test — and `E3_EXEMPT` holds **2** entries.

**New or changed gate → a fires/does-not-fire pair.** For the E3 removal:
show the check **failing** on a tree where `get_handler` still calls the shell,
and **passing** after. Without the failing half, a green check proves nothing
about whether it can see this route.

**Evidence policy.** Every file under `evidence/` is redirected command output,
not transcribed. **A count or a list in prose is a measurement** and carries the
command that produced it — including the new host-test total and the 193.

Run the full gate set. I will re-run the release-critical and claim-bearing ones
myself.

## 11. What must NOT be claimed

- Do **not** claim the no-JS sign-in path is verified end-to-end unless you
  actually drove it with JavaScript disabled. If the browser suite cannot reach
  an authenticated screen, **say so** and scope the claim to the handler-level
  assertions. RFC 143 §6 anticipates exactly this; an honest "not covered" is
  the required answer, not a weaker test described in stronger words.
- Do **not** claim the recovery flow works because the form renders. Rendering
  the form is what §10.4 asserts. Whether a recovery code is accepted is
  `recover::post_handler`'s behaviour and is unchanged by this work — say that
  rather than implying coverage.
- Do **not** describe the deleted CSR page as "migrated" or "replaced". The
  server page predates it and outlived it.

## 12. Prohibited shortcuts

- Adding `GET /me/security/totp/recover` to make the old `<a href>` work. The
  link is deleted with the page; the template's inline POST form is the design.
- Adding `not_found_handling` to `wrangler.toml`. Out of scope, and it would
  paper over exactly the class of defect this RFC exists to remove.
- Widening `E3_EXEMPT`, or adding an exemption facility. RFC 132 §8 reserves
  that decision and the comment in the script says so.
- Keeping `get_json_handler` "in case something needs it". If something needs
  it, that is a §5.5 report.

## 13. Acceptance criteria

1. `GET /me/security/totp/verify` renders the second-factor form server-side,
   with a CSRF token that round-trips, in the request's locale.
2. The recovery path on that page is the template's inline POST form; no GET
   link to `/me/security/totp/recover` remains in the tree.
3. `/me/security/totp/verify` is **not** in `E3_EXEMPT`, the check passes, and
   the fires/does-not-fire pair is in evidence.
4. The CSR `TotpVerify` page, its route, and `verify.json` are gone; route
   contracts report **193**.
5. `docs/src/expert/route-contracts.md:66` is unchanged.
6. No existing test is weakened, and the `decide_verify_get` tests still pass
   untouched.

## 14. Known risks

**R1 — the CSRF cookie.** The one way this breaks a flow that works today. §8
and §10.2 exist for it.

**R2 — a plainer screen.** The server page is unstyled relative to the Leptos
one. Accepted (§7); RFC 131 R3 owns styling. Do not fix it here, and do not
report it as a defect.

**R3 — the route count.** 193 is a *deletion*, so a count of 194 means the
`verify.json` row or registration survived, and 192 means something else went
with it. Either way, §5.2.

## 15. Review request

Write the package to `.git-exclude/review-request/143-cycle1-totp-no-js.md`,
with evidence under `.git-exclude/review-request/evidence-143-cycle1/`.

State plainly: the new host-test total with its command, the 193 with its
command, the fires/does-not-fire pair for the E3 removal, and **what you could
not verify** — particularly §11's end-to-end no-JS question. A named gap is a
result. A gap described as coverage is the only thing in this handoff that would
require a correction cycle.
