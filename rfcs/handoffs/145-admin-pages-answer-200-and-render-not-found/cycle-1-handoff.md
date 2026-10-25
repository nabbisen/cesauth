# Developer Handoff — RFC 145 cycle 1, the operator console's dead pages

**Governing RFC.** `rfcs/accepted/145-admin-pages-answer-200-and-render-not-found.md`
— **read §11 first.** §11 is the triage, measured on 2026-10-25, and it changes
§4's and §9's expectations: nothing is deleted, the level is a patch, and the fix
is RFC 143's, not a screen build.

**Target release.** 0.85.1 — **and why that level:** **patch.** Every change
points a GET handler at a template that already exists in its own module and is
already rendered by that module's POST path. No surface is added or removed.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing — **RFC 146 landed at `3013ff3` and is accepted**, so
`html_response` now pairs a document with its own nonce. **Dispatched
2026-10-25.** §8's instruction stands: your handler must **not** call
`set_render_nonce`; the helper owns it.

---

## 1. Purpose

Thirty-five admin `GET` routes documented as client-rendered serve the Leptos
shell, and `app.rs` has no route for any of them, so the router's `<NotFound/>`
fallback renders — **HTTP 200 with a Not Found page**, after an admin auth check.

**One of them is reachable by navigation**, and this cycle ends that:
`crates/frontend/src/pages/operator/console.rs:106` renders
`<a href="/admin/console/tokens/new">` on the tokens console screen, which
works. An operator who follows the UI to issue a token lands on Not Found.

## 2. Why this matters

The capability, its template, that template's tests and its localization all
already exist. What is missing is one line in each GET handler. An operator
cannot issue a token through the console, and the route contract says they can.

The second reason is structural. These rows are declared `render=client`, and
**E3 only checks `server`-declared routes**, so nothing guards them. Converting
them to `server` moves them into a class **E3 already polices**. This cycle is
also how the class stops growing.

## 3. Resolved decisions — do not re-open

**D1. Implement, do not delete.** All three routes keep their paths. §11.2
records why deleting was rejected: the templates exist and are tested.

**D2. The fix is RFC 143's.** Point the GET at the template its own module
already renders, with `None` for the error argument so the fresh form renders.
Measured call sites:

| Route | Template its own POST already renders |
|---|---|
| `/admin/console/tokens/new` | `ui::admin::token_new_form(&principal, Some(err))` — `routes/admin/console/tokens.rs:120,126` |
| `/admin/console/config/:bucket/edit` | `ui::admin::config_edit_form(…)` — `routes/admin/console/config.rs:263` |

Both modules already do `use cesauth_frontend as ui;` and already call
`render::html_response(...)`, so the import and the response helper are in place.

**D3. The contract rows change `client` → `server`.** That is not cosmetic — it
is what brings each route under E3. Change the render column; leave every other
column alone.

**D4. `/admin/t/:slug/deletion-requests` is the one route with no template.**
`grep -c cesauth_frontend crates/backend/src/routes/deletions.rs` is **0**.
**Do not invent one to match the contract row.** Report what the route is, what
the row claims, and which of the two is wrong. If a template is the answer, say
what it would take; it may belong in cycle 2 instead. **This is a
report-and-stop (§5.4), not a build.**

**D5. The `*_json` companions stay for now.** `tokens::new_form_json` and
`config::edit_form_json` are **unregistered** (`grep -c` in `lib.rs`: **0**
each). They are the same class as RFC 141 §13's six handlers. Once the GET
server-renders, nothing will consume them — but **do not delete them in this
cycle**; record them, and RFC 145 cycle 3 resolves the whole family at once with
the gate. Deleting them here would split one decision across three cycles.

**D6. Nothing is deleted and nothing is added**, so the **route count stays
193**. A change in that number is a report-and-stop (§5.2).

## 4. Facts already measured — do not re-derive

| Fact | Command | Result |
|---|---|---|
| The dead-route count | `render=client` GET rows in `route-contracts.md` vs `path!()` in `app.rs` | **60 vs 25 → 35 unmatched** |
| They all reach the shell | each handler resolved to its body | 24 via `operator_json_api::shell`, 11 via `tenant_admin::json_api::shell`; both wrap `leptos_html_shell` (`operator_json_api.rs:38`, `tenant_admin/json_api.rs:48`); **0 unresolved** |
| The fallback they hit | `app.rs:57` | `<Routes fallback=\|\| view! { <NotFound/> }>`; all 27 `path!(` are in `app.rs`, **0** `<Route` elsewhere, no nesting |
| The reachable one | `grep -rn 'href="/admin/console/tokens/new"'` | **1**, at `pages/operator/console.rs:106` |
| `/admin/console/clients` reachability | `grep -rn 'href="/admin/console/clients'` | **0** — excluded from RFC 145; RFC 141 cycle 2 owns it |
| 34 of 35 have a template | §11.1's table | 27 + 5 + 2 have one; **1** does not |
| It predates 0.85.0 | the same comparison on `git show 0.84.3:…` | **34** then, **35** now; the one addition is `/admin/console/clients` |

## 5. Report-and-stop gates

1. **Either converted route still reaches `leptos_html_shell`.** After D3, E3
   will fail — and that failure is correct. Fix the handler, not the exemption
   list, and **never** add an `E3_EXEMPT` entry (§12).
2. **The route count is not 193.**
3. **The template's arguments cannot be satisfied in the GET.** The POST has a
   parsed form and a resolved principal; the GET has the principal and empty
   values. If a template demands something the GET genuinely cannot supply,
   stop and say which argument — do not pass a placeholder.
4. **`/admin/t/:slug/deletion-requests`** — per D4, report rather than build.
5. **Converting reveals that a row's other columns are also wrong.** Report it;
   do not quietly correct a second column.

## 6. Change scope

- `crates/backend/src/routes/admin/console/tokens.rs` — `new_form` renders
  `ui::admin::token_new_form(&principal, None)`.
- `crates/backend/src/routes/admin/console/config.rs` — `edit_form` renders
  `ui::admin::config_edit_form(…, None)`.
- `docs/src/expert/route-contracts.md` — the render column of those two rows,
  `client` → `server`. Nothing else on those rows.
- Tests, per §10.
- **No change to** `app.rs`, the `*_json` handlers, `E3_EXEMPT`, any POST
  handler, or `deletions.rs`.

## 7. Explicit non-change scope

- **The 32 routes of cycles 2 and 3.** Leave them dead; they are dispatched
  separately and converting them here would make this cycle unreviewable.
- **`/admin/console/clients`** — RFC 141 cycle 2.
- **The templates themselves.** No edits: not wording, not markup, not styling.
  RFC 131 R3 owns how admin screens look.
- **The §4.2 gate.** Cycle 3 adds it, when the last row is resolved. Adding it
  now would fail the tree on 32 known rows.
- **The CSRF flow of the POSTs.** Unchanged.

## 8. Task detail worth stating explicitly

The GET handler keeps its auth check and gains the render. Shape, using
`tokens.rs` as the example:

```
pub async fn new_form<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match /* the same resolve the POST uses */ { … };
    render::html_response(ui::admin::token_new_form(&principal, None))
}
```

- **`None` is the error argument.** `Some(msg)` is the POST's failure path and
  must keep working untouched.
- **Resolve the principal the way the POST does**, not the way `shell` did.
  `operator_json_api::shell` called `resolve_admin` and discarded the result
  (`let _admin = …`); these templates need the principal, so it is now used.
- **Keep the authorization check.** If `shell` enforced a role, the
  server-rendered path must enforce the same one. A page that renders for a
  caller who could not previously load the shell is a privilege regression and
  is worse than the Not Found it replaces.
- **The CSP nonce — and do not follow `console/render.rs:59`.** I gave the
  wrong instruction here in the first draft of this handoff, and the correction
  is the reason this cycle is blocked. `render::html_response` already calls
  `set_render_nonce` — but it does so **after** its caller has rendered the
  body, because the body is an argument and Rust evaluates arguments first. The
  document therefore carries one nonce and the header another, on all 78 of its
  call sites. **RFC 146 fixes that by giving `html_response` a closure**, so
  once it lands your handler simply writes
  `render::html_response(|| ui::admin::token_new_form(&principal, None))` and
  the nonce is correct because the helper owns both steps. **Your handler must
  not call `set_render_nonce` itself** — RFC 146 §5.4 rejects that approach
  explicitly.

## 9. Assert machine-checkable things mechanically

```
# no shell call survives in either converted handler
grep -c 'operator_json_api::shell' crates/backend/src/routes/admin/console/tokens.rs   # expect 0
grep -c 'operator_json_api::shell' crates/backend/src/routes/admin/console/config.rs   # expect 0

# both rows now say server, and no E3 exemption was added
grep -c 'GET /admin/console' scripts/route-contracts-check.sh                          # expect 0

# the route count did not move
bash scripts/route-contracts-check.sh | tail -1                                        # expect 193

# the handler does NOT set the nonce itself -- that is html_response's job (RFC 146)
grep -c 'set_render_nonce' crates/backend/src/routes/admin/console/tokens.rs           # expect 0
```

## 10. Required tests and evidence

1. **Each converted GET renders the form server-side**: the response body
   contains the form and **no** shell script tag.
2. **The CSP nonce is per-request and matches**: the `nonce` in the rendered
   `<style>`/`<script>` equals the nonce in the response's CSP header, in the
   same response. This is §14 R1, so it gets its own assertion.
3. **Authorization is unchanged**: a caller who could not load the shell still
   cannot render the page, with the same status.
4. **The POST failure path still renders with `Some(err)`** — unchanged
   behaviour, asserted so this change cannot quietly alter it.
5. **E3 now covers both routes**: the check passes with the rows declared
   `server`, and **fails** if a handler is reverted to the shell. That
   fires/does-not-fire pair is the acceptance test for D3.
6. **The operator flow**: `/admin/console/tokens/new` returns a token-issuance
   form, reached from the link at `pages/operator/console.rs:106`. If you can
   drive it with `curl` against `wrangler dev` as RFC 143 cycle 1 did, do —
   that was the best evidence this project has been sent. If you cannot,
   **say so** and scope the claim.

**A count or a list in prose carries its command.** Evidence under
`evidence-145-cycle1/` is redirected output, not transcribed.

## 11. What must NOT be claimed

- **Not** that the admin console now works without JavaScript. Two of
  thirty-four routes are converted. Say which.
- **Not** that the Not Found class is fixed. It is fixed for the reachable
  instance; 32 routes still have it, by design, until cycles 2 and 3.
- **Not** that E3 now guards the admin console. It guards the two rows you
  converted.
- **Not** that the templates are "new" or "migrated". They predate this work and
  their own POST paths have been rendering them all along.

## 12. Prohibited shortcuts

- **Adding anything to `E3_EXEMPT`.** RFC 132 §8 reserves that decision and the
  script's own comment says so. If E3 fails, the handler is wrong.
- **Changing a contract row to `client` to make a check pass.** That is how
  thirty-five of these came to exist.
- **Adding routes to `app.rs`** to make the shell work. The decision is
  server-rendering (D2).
- **Deleting the `*_json` handlers** (D5), or touching cycle 2/3 routes.
- **Passing a placeholder** for a template argument you cannot satisfy (§5.3).

## 13. Acceptance criteria

1. `/admin/console/tokens/new` and `/admin/console/config/:bucket/edit` render
   server-side, with the same authorization as before and a per-request CSP
   nonce that matches the response's CSP header.
2. Both contract rows read `server`; no other column changed; no `E3_EXEMPT`
   entry added; E3 passes and the fires/does-not-fire pair is in evidence.
3. Route contracts still report **193**.
4. The POST failure paths are untouched and still render with `Some(err)`.
5. `/admin/t/:slug/deletion-requests` is **reported on**, not built.
6. No existing test is weakened.

## 14. Known risks

**R1 — the CSP nonce, now RFC 146's (§8).** This was the risk that turned out
to be a live defect on all 78 `html_response` call sites, which is why this
cycle waits. After RFC 146 lands, the nonce is the helper's responsibility and
this risk is retired; §10.2 still asserts it, because a conversion is exactly
when it would regress. Related but **separate**: RFC 143 §10.1's finding that
the TOTP POST error path inherits its nonce from the isolate. Do not fix that
here.

**R2 — a plainer screen.** These pages will look like the server templates, not
like the console's client-rendered screens. Accepted; RFC 131 R3 owns styling.
Not a defect, and not to be reported as one.

**R3 — authorization drift.** `shell` discarded its `resolve_admin` result; the
template needs the principal. Re-resolving is where a role check can be
accidentally dropped. §10.3 exists for this.

## 15. Review request

Write the package to `.git-exclude/review-request/145-cycle1-console-dead-pages.md`,
evidence under `.git-exclude/review-request/evidence-145-cycle1/`.

State plainly: the 193 with its command, the E3 fires/does-not-fire pair, the
nonce assertion, your finding on `/admin/t/:slug/deletion-requests`, and
**anything you could not verify**. A named gap is a result.
