# Developer Handoff — RFC 141 cycle 2: the OIDC clients screen

**Governing RFC.** `rfcs/done/141-oidc-client-registration.md` §4.1, and its
cycle-2 re-scope note (2026-10-30).
**Builds on.** `481dcab` on `main` — tag `0.91.2`, 13/13 CI green.

**Target release.** **0.92.0 — minor.** **Two triggers hit**, argued:
a new operator-facing surface exists where none did, and **four `POST` routes
begin requiring a token no caller sent before** (§3). Either alone would make
this a minor.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-03.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. What is wrong today, measured at `481dcab`

`GET /admin/console/clients` is **registered**, answers **200**, and renders
**"Page not found"** to a signed-in operator — because `clients::list` serves
the Leptos shell and `crates/frontend/src/app.rs` has **no route for that
path**, so `app.rs`'s `NotFound` fallback wins. This is the product's primary
integration action: **an operator cannot register an OIDC client through the UI
at all**, and the page that should let them lies about why.

**The backend has been complete since v0.85.0** and needs nothing:

```
GET  /admin/console/clients              -> clients::list        (the shell)
GET  /admin/console/clients.json         -> clients::list_json   (the data)
POST /admin/console/clients              -> clients::create
POST /admin/console/clients/:id          -> clients::update
POST /admin/console/clients/:id/rotate-secret -> clients::rotate_secret
POST /admin/console/clients/:id/delete   -> clients::delete
```

So cycle 2 is **a screen on a finished backend**: a CSR route, a component that
fetches `clients.json`, and the four write actions. No new port, no migration,
no new audit kind.

## 2. The screen

Follow `app.rs`'s existing operator-console conventions rather than inventing
layout. What it must do:

- **List** the clients from `clients.json` — id, name, type
  (`public`/`confidential`), redirect URIs, created-at. The list is the page's
  reason to exist: today an operator cannot see which clients exist.
- **Create**, with the field shape `clients::create` already validates
  (`ClientId::parse`'s rule is enforced server-side — surface its rejection,
  do not re-implement it client-side).
- **Rotate secret** and **delete**, each behind a confirmation that names the
  client, because both are irreversible for an integrator: a rotated secret
  breaks every deployed client using the old one.
- **The secret is shown exactly once.** `create` and `rotate_secret` are the
  only two responses that ever carry it (`RawSecret::expose()`), and the module
  doc says so. The screen must make that unmissable — an operator who closes
  the page without copying it has to rotate again, which breaks their
  integration a second time. **This is the one piece of UX in this cycle I care
  most about**: say it before the action, not only after.
- **Update** for the editable fields.

## 3. The part that is not just a screen, and why it is in scope

**The four write routes document a CSRF control they do not have, and the
screen is what makes that matter.** Their `route-contracts.md` cells read
`N/A (JSON)`, and `clients.rs`'s own module doc gives the reasoning:

> *"a cross-origin page cannot silently issue a cross-origin
> `application/json` POST — the browser's CORS preflight blocks it"*

**That is false, and it was verified false at 0.91.0's review.**
`worker::Request::json()` calls the Fetch `Request.json()`, which parses the
body **regardless of `Content-Type`**, and none of these handlers checks the
header. Live, against `wrangler dev`: `POST /admin/console/clients` with
`content-type: text/plain` and with `application/json`, same `{}` body, both
returned `id is required` — the body was parsed both times. **`text/plain` is
CORS-safelisted, so no preflight occurs.** The only thing protecting these
routes is the admin cookie's `SameSite=Strict`.

Today that is a latent documentation defect. **After this cycle it is not**: the
screen gives these four routes a real browser caller, authenticated by the
`__Host-cesauth_admin` cookie, on operations that mint and rotate OIDC client
secrets. Shipping a browser caller onto routes whose stated control does not
exist, three releases after we spent 0.90.0 and 0.91.0 fixing exactly that, is
not something I am willing to dispatch.

**So this cycle also gives those four routes the control**, and the design is
the one that fits a JSON endpoint:

1. **Require a non-safelisted request header** — `X-CSRF-Token` — and compare it
   to the CSRF cookie. **The header requirement alone is a complete CSRF
   defence for a JSON endpoint**: a cross-site form POST cannot set a custom
   header, and a `fetch` that does triggers a preflight this deployment never
   grants. The cookie comparison adds double-submit on top. **Do not** ask for a
   form field here — these are JSON bodies and a `curl` caller should not have
   to fake a form.
2. **The screen sends it**, from a token minted the way the operator console
   already does it (`operator_json_api::csrf_json` and its `{ csrf_token }`
   shape, which the existing `AdminCsrfForm` already consumes).
3. **The cells become `required (header token)`** — the mechanism form the table
   already uses for `required (Origin check)` — and **E6's mechanism table
   learns it**, so the claim is checked from this release on.
4. **Correct the module doc.** It is the source of the false reasoning and it
   explicitly says *"this is the same reasoning the webauthn and
   `/api/v1/anonymous/*` routes rely on"*, so the error has been cited
   elsewhere. Say what is actually true: the header requirement is the control,
   and `SameSite=Strict` is defence in depth.

**Scope boundary, firmly.** There are **11** mutating rows claiming
`N/A (JSON)`. **You fix four** — the clients routes, because this cycle gives
them a browser caller. **Leave the other seven** — the four webauthn routes,
`/me/security/delete-account`, and the two `/api/v1/anonymous/*` — to RFC 152
half D, which owns them and has a measurement stage for exactly this question.
Confirmed none of them checks `Content-Type` either, so half D's scope is real;
**do not widen into it**, and say in your report that you did not.

## 4. Tests

- **Component tests** for the list and the four actions, in
  `cesauth-frontend`, the shape the existing operator-console components use.
- **The once-only secret**: a test that the create/rotate response's secret is
  rendered where the operator will see it, and a test of whatever "you will not
  see this again" affordance you build. If that affordance is only CSS, say so —
  a warning that does not survive a narrow viewport is not an affordance.
- **The four routes' new check**: host-test the decision boundary — missing
  header rejected, wrong header rejected, matching header accepted — the way
  stage 1's `verify_csrf` tests do. The handler path itself needs `worker::Env`,
  so exercise it live and **capture the status lines**
  (`curl -s -o /dev/null -w "%{http_code}"`): no header → 400, wrong → 400,
  matching → success, and **`text/plain` with a JSON body and no header → 400**,
  which is the probe that proves the new control does what the old prose only
  claimed.
- **E6** must show the four rows moving from declared-uncheckable to checked:
  its census arithmetic will change, so state the new line in full.
- Full gate set. **Baselines at `481dcab` (tag `0.91.2`), each with its
  command** — per the 2026-11-03 ruling, since a cited figure without its
  invocation cost a cycle an afternoon:
  - host tests, `cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend -p cesauth-backend -p cesauth-adapter-cloudflare --features cesauth-frontend/csr` → **1,653 passed, 0 failed, 4 ignored, 12 `test result:` lines**;
  - `cargo test -p cesauth-migrate-test --test migration_chain` → **35**;
  - `bash scripts/route-contracts-check.sh` → 194 routes; E4 `218 = 194 + 24 + 0`; E5 `16 = 16 + 0 + 0`; E6 `94 = 76 claims + 18 declared + 0 unclassified`;
  - `bash scripts/drift-scan.sh` → clean; `rfcs/` links `167 checked, 0 broken`; reconciliation `141 tags vs 139 entries`;
  - `npx playwright test` in `e2e/` → **20**;
  - `./node_modules/.bin/wrangler deploy --dry-run --outdir bundled/` under gzip 1.15 → **896,301 B** total (`885,601` wasm + `10,700` shim).
  **E4, E5 and the bundle will all move** — you are adding a CSR route, a
  component and a fetch. Say what they become.

## 5. What to report

- What the screen shows, verbatim, for the once-only secret.
- The four status captures from §4, as captures.
- E6's new census line in full.
- Whether anything in `clients.json`'s existing shape was missing for the
  screen — if the backend turned out not to be as finished as I have claimed,
  that is the finding and I want it early.
- Anything you had to invent because `app.rs`'s conventions did not cover it.

## 6. Stop conditions

- `clients.json` does not carry what the list needs (§5);
- the header-token design collides with how the console's existing fetches are
  built — describe the collision and stop, because that design is mine;
- the four routes cannot take the check without touching the other seven
  `N/A (JSON)` routes (§3);
- the screen needs a backend change of any kind. The claim that the backend is
  finished is mine, and if it is wrong I would rather re-scope than have you
  work around it.
