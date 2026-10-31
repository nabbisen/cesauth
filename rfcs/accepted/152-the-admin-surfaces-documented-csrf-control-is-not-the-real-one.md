# RFC 152 — The admin surfaces' documented CSRF control is not the real one

**Status.** **Accepted** 2026-10-27. **Half A SHIPPED in v0.86.3** (patch —
the document made true, the real control pinned). **Half B dispatched
2026-10-31 as 0.90.0 (minor), in two stages:** stage 1, the missing checks
(`handoffs/152-the-admin-surfaces-documented-csrf-control-is-not-the-real-one/half-b-stage-1-handoff.md`);
stage 2, §6's `GET /admin/login` cookie fixation, its own cycle in the same
release. See §5.

**Half B SHIPPED in v0.90.0**, 2026-10-31, both stages. **Half A shipped in
v0.86.3.** **Half C is outstanding**, so this RFC stays in `accepted/`.

**Half C SHIPPED to `main` in `8162b51`** (not yet released; 0.91.0's cut waits
on one cycle-2 gate fix). Verified live by the architect through the real
two-step `/admin/login` flow: class A gives **400** with no token and **400**
with a wrong one, and a validation-error re-render carries a **fresh** token
whose cookie matches it; class B gives **401** to the admin session cookie alone
— the fix — and **200** to `Authorization: Bearer` with no cookie.

**The cycle moved one route against the handoff, and was right.**
`safety.rs::verify` was classed A on the strength of its content negotiation;
the HTML form it would redirect to **exists in no live path** —
`cesauth_frontend::admin::safety_page` is referenced only by its own module,
its own tests and a `pub use`, and `GET /admin/console/safety` serves a CSR
placeholder that says *"未実装 (RFC 161)"*. Reclassified as B. The architect's
classification rested on the handler and never asked whether the form existed,
which is the question the handoff itself told the team to ask about class B.

**Half D — now 29 rows across two cell values.** The second value was found in
cycle 2's review (2026-10-31): **11 mutating rows claim `N/A (JSON)`, and the
control that cell names does not exist.** The stated reasoning is that a JSON
`Content-Type` forces a CORS preflight the server never grants — but
`worker::Request::json()` calls the Fetch `Request.json()`, which parses the
body **regardless of `Content-Type`**, and no handler checks the header.
Verified live: `POST /admin/console/clients` with `content-type: text/plain` and
with `application/json`, same `{}` body, returned the same `id is required` —
the body was parsed both times. `text/plain` is CORS-safelisted, so no preflight
occurs. The real protection is `SameSite=Strict` again. The eleven include
`POST /admin/console/clients/{create,update,rotate_secret,delete}`.

**So half D's measurement stage has two questions**, not one: for the 18
`N/A (bearer)` rows, is there a real cookie-borne caller; and for the 11
`N/A (JSON)` rows, is the honest cell `N/A (SameSite=Strict)` — naming the layer
that actually holds — or do they want the control the cell currently claims.

**Half C cycle 2 SHIPPED to `main` in `5f011fc`.** E6 now has E4's census
property: every scanned mutating row is checked or **declared with a reason**,
an unrecognised cell is a hard failure, declared values carry the stale-entry
rule, and both arithmetics are asserted —
`94 = 76 claims + 18 declared + 0 unclassified` and
`76 = 58 resolved + 0 unresolved + 18 exempted`. The two cells it caught:
`POST /accept-invite` (no ambient credential and no state change — nothing for a
forged request to ride on) and `POST /userinfo`, whose `N/A (Bearer)` had been
skipped on a capital letter and whose claim is **true** — a renaming re-export
to a handler reading `Authorization` through its own `extract_bearer`, with no
cookie path, recognised now through a table keyed by handler name rather than a
widened regex.

**Half D, found while generalising E6 (2026-10-31).** **18 mutating rows claim
`N/A (bearer)` and accept a cookie**: `POST /admin/users`,
`DELETE /admin/sessions/:id`, and all 16 `/api/v1/*` mutating routes, which
funnel through `api_v1::auth::require` → `auth::resolve_or_respond`, the
cookie-accepting resolver. Not exploitable — no `Access-Control-Allow-Origin`
is set anywhere in the repo (the only two mentions are comments confirming it),
so `SameSite=Strict` holds — and **not fixed**: flipping the legacy admin API
and the whole tenant-management REST surface is a caller-obligation change of
its own size. Exempted by name in `E6_BEARER_LEGACY_EXEMPT` with a stale-entry
check, and recommended as **half D, opening with its own measurement stage**:
is there a real cookie-borne caller for any of the 18, the same question that
decided class A from class B here.

### Half C, measured — seven, not nine, in three classes (2026-10-31)

**Correction first: the count I reported was wrong, and it was mine.** The
stage-2 review said **nine** rows claim `required` with no check. It is
**seven**. `POST /admin/console/config/log_level/preview` and `…/apply` **do**
carry a CSRF control — not `csrf::verify`, but
`cesauth_core::admin::preview::verify_preview_token`, an HMAC'd preview token
with the submitted CSRF value **bound into it**; `apply` fails closed on
*"expired, tampered, or CSRF mismatch"*. My scan looked for three function
names and this is a fourth mechanism. **Fourth time in this project that a
matcher's silence was read as the code's silence**, and the second time it was
mine inside this RFC.

The seven, classified by what actually calls them — which is the measurement
half C was supposed to open with, done here so the cycle starts from an answer:

**Class A — real browser forms. Need the double-submit token, stage 1's
pattern (3):**

| Route | Renders |
|---|---|
| `POST /admin/console/tokens` | `token_new_form` / `token_created_page` — **mints an admin token** |
| `POST /admin/console/config/:bucket/edit` | `config_edit_form` / `config_confirm_page` |
| `POST /admin/console/safety/:bucket/verify` | content-negotiated; the HTML branch redirects back to its form |

**Class B — JSON endpoints whose only documented caller is `curl` with a bearer
header (4):** `…/tokens/:id/disable`, `…/config/:bucket/preview`,
`…/config/:bucket/apply`, `…/thresholds/:name`. All four return
`json_response` only; `crates/frontend/src/admin/config.rs` documents them as a
curl API in its own prose; **no view in the frontend fetches or posts to any of
them.** The one apparent exception is not one:
`pages/operator/console.rs:108` posts to `/admin/console/tokens/disable` — a
path with no `:id` that **no route serves** — inside a form with **no submit
button and no id field**, whose visible text says disabling is done by
specifying an id. That is a placeholder, RFC 161's class, and it belongs to
RFC 131 §0's console slices, not here.

**A double-submit token is the wrong control for class B.** A `curl` caller has
no cookie jar, so the token would be ceremony for the browser and an obstacle
for the documented caller. **The right fix is structural: make these four
reject a cookie-derived credential** and require the `Authorization` header.
`auth::bearer` reads the header first and *falls back* to the admin cookie for
browser clients; a header-only resolver removes the browser-attached credential
from these routes entirely, which is what makes CSRF possible in the first
place. Their cells then read **`N/A (bearer)`** — a value the table already
carries honestly on 12 other rows — and the claim is true by construction
rather than by a check.

**Class C — already controlled; one honest cell (2):**
`…/config/log_level/{preview,apply}`. The substance is there; the column's
`required` means double-submit elsewhere, so the cell should name this
mechanism — the table's existing `required (Origin check)` row is the
precedent.

**And E6 should check the control the cell names, not only `required`.** Today
it asserts `required ⇒ a verify call`. The end state asserts the cell's claim in
both directions: `N/A (bearer)` ⇒ the handler uses the header-only resolver,
`required` ⇒ a verify, `required (…)` ⇒ the named mechanism. That absorbs the 12
existing `N/A (bearer)` rows into the gate instead of trusting them, and it is
the same generalisation that needs E4's multi-line registration walk — so
RFC 163's single-extractor end state is now asked for by a third caller.

**Level: minor.** Class B changes a caller obligation — a client authenticating
to those four routes by cookie stops working. Scheduled **0.91.0, ahead of
RFC 141 cycle 2**, because a documented control that is absent outranks a
screen that does not exist yet.

**Half C PROPOSED 2026-10-31 — a third surface makes the same claim.** RFC 152
scoped itself to `/admin/t/*` and `/admin/tenancy/*` and never asked whether any
other surface documented the same control; the stage-1 handoff inherited that
scope and E6's path filter inherited it again. Asked during stage 2's review:
of **57 `POST` rows claiming CSRF `required`** across the whole table, E6 covers
34, and **nine of the rest claim `required` with no `csrf::verify`,
`verify_csrf` or `check_origin_or_referer` anywhere in the resolved handler
body** — all on the **operator console**:
`POST /admin/console/tokens` (which **mints an admin token**),
`…/tokens/:id/disable`, `…/config/:bucket/{preview,apply,edit}`,
`…/config/log_level/{preview,apply}`, `…/thresholds/:name`,
`…/safety/:bucket/verify`. Same shape, same non-exploitability for the same
single reason (`SameSite=Strict`), same document naming a control that is not
there. `tokens.rs` even calls `csrf_json()` — the surface serves tokens to its
pages and checks none coming back.

**Half C opens with a measurement stage, not code**: `safety.rs` has no frontend
view at all, the `config`/`thresholds` views live under
`crates/frontend/src/admin/` and may be inside RFC 161's disconnected set, and
the only form at the tokens surface posts to `/admin/console/tokens/disable`,
**a path no route serves** (RFC 166 §4b's recorded instance). Which of the nine
have a reachable caller decides whether half C is stage 1 again or RFC 161/166
material — and stage 1's two-renderer surprise is the argument for measuring
first. **E6 should also grow to cover every `required` row**, which needs E4's
multi-line registration walk: 10 rows outside E6's filter are registered as
multi-line closures. Second gate to ask for RFC 163's single-extractor end
state.

**Stage 2 SHIPPED to `main` in `994bde6`** (not yet released). `GET
/admin/login?token=…` validates against the store and sets nothing; it renders a
confirmation page naming the identity and role the operator is about to assume,
carrying a CSRF token; a new `POST /admin/login` verifies it, re-validates the
bearer and only then sets the cookie. Verified live by the architect: **200**
with no session cookie, **401** for a garbage token with no cookie, **400** for
a `POST` with no or wrong token, **303** with the full cookie attribute set for
a matching one — and **400** for a `POST` carrying the correct form field with
no CSRF cookie, which is what a cross-site submission looks like under
`SameSite=Strict`. `X-Frame-Options: DENY` is present on the confirmation page,
so the deliberate click cannot be harvested by framing, and the document's nonce
matches the response's CSP header (RFC 150's invariant holds on the new page).

**Stage 1 SHIPPED to `main` in `c9ae019`** (not yet released; 0.90.0's cut
waits on stage 2). **32 handlers gained `csrf::verify`**, the two
`routes/invitations.rs` routes among them; 34 of the 36 contract cells now read
`required` and **E6** fails the build if any of them stops being true. Verified
live by the architect, not read: no token and wrong token both **400**, matching
token **303**, and a validation-error re-render carries a **fresh** token whose
corrected resubmission succeeds. **Two routes were left honest rather than
flipped** — `tenant_detail::{suspend,restore}` read no form body and have no
caller anywhere, which is a finding for RFC 166's census (a registered route no
caller invokes) rather than an exemption.

**Half B's population re-derived route-scoped at dispatch** (2026-10-31): **36
`POST` rows, 34 without a `csrf::verify`, across 23 files** — not 33 of 35. The
RFC's figure predates `POST /admin/t/:slug/invitations/:id/revoke` (v0.88.0).
**Two of the 23 files are outside both surface directories** —
`routes/deletions.rs` (the 2 that *do* verify) and `routes/invitations.rs` (2
that do not) — so §2's warning about directory-scoped greps has a second
instance.

**Two findings from that measurement, neither in this RFC before:**

1. **For two of the 36 routes the browser already posts a CSRF token that
   nothing checks.** `pages/tenant_admin/forms.rs`'s generic `AdminCsrfForm`
   fetches `{ csrf_token }` and emits `name="csrf"` for
   `/admin/t/:slug/organizations/new` and `…/memberships/new`; neither `submit`
   verifies it. The control is three-quarters built on those two.
2. **§5 understated half B by one layer.** It sized ~32 form templates that
   take no token; the harder fact is that **two renderers exist** — 21
   server-rendered views under `frontend/src/{tenant_admin,tenancy_console}/forms/`
   in which the string `csrf` does not appear at all, and a CSR path that
   already does it correctly for the only **two** form paths `app.rs` routes.
   Stage 1's handoff decides for the SSR views and records the duplication as
   RFC 131/141's subject rather than resolving it inside a security fix.
**Tier.** P1 — not a live vulnerability, and that is established below rather
than assumed. It is P1 because **fifteen** destructive or disabling
operations rest on one undocumented layer while the document claims a different
one — a figure that is 15 of the 33, not of the 35.
**Size.** Small if the answer is "document it"; medium if the answer is "add the
check".
**Touches.** `docs/src/expert/route-contracts.md` (35 rows),
`crates/backend/src/routes/admin/tenant_admin/`,
`crates/backend/src/routes/admin/tenancy_console/`,
`crates/backend/src/routes/admin/admin_login.rs` (the cookie), and whatever
gate ends up asserting the claim.
**Depends on.** Nothing.
**Found by.** The **dev team**, 2026-10-27, while implementing RFC 145 cycle 2 —
outside that cycle's scope, reported rather than absorbed. Severity corrected by
the architect during review the same day.

## 1. Summary

All 35 `POST` routes on the tenant-admin and tenancy-console surfaces document
their CSRF column as **`required`**, which in this codebase means a
double-submit token check via `csrf::verify`. **Thirty-three of the 35 do not
call it.**

The two that do are `/admin/t/:slug/deletion-requests/:id/cancel` and
`…/execute` — **the newest routes on either surface**, written under RFC 147
cycle 2 three days ago. So the pattern is applied to new work and was never
retrofitted to the rest, which is a more useful thing to know than "it was
never applied here".

The surfaces are nonetheless protected — by the admin cookie's
`SameSite=Strict` attribute, which no row mentions and no test asserts. So the
defect is not an absent control. **It is a document that names the wrong one**,
across 35 rows, 14 of which destroy data.

## 2. What is established

**The documentation's claim.**

```
$ awk -F'|' '/^\| POST/ && ($3 ~ /admin\/t\/|admin\/tenancy/) {gsub(/ /,"",$9); print $9}' \
    docs/src/expert/route-contracts.md | sort | uniq -c
     35 required
```

Thirty-five rows, every one of them `required` — including the 33 where
nothing checks a token.

**The code's behaviour.** Measured by resolving each of the 35 `post_async`
registrations in `lib.rs` to its handler's module and checking that module for
`csrf::verify` — **not** by grepping the two surface directories, which is how I
first measured it and which was wrong: `/admin/t/:slug/deletion-requests/*` is
served from `routes/deletions.rs`, outside both directories. A directory-scoped
grep answering a route-scoped question is the same error that once made a
`grep -c 'operator_json_api::shell'` expectation wrong in an RFC 145 handoff.

```
POST routes on the two admin surfaces: 35
csrf::verify present:                   2   (deletion-requests cancel, execute)
NO csrf::verify:                       33
```

The function exists and is used widely in the same crate —
`console/audit_chain.rs:60`, `console/audit_export.rs:34`, `me/sessions.rs:101`
and `:216`, `me/totp/*`, `magic_link/*`, `deletions.rs:179` and `:243` — so this
is not a missing capability.

**The destructive subset of the 33** spans `groups/:gid/delete`,
`role_assignments/:id/delete` (and `role_assignment_delete`), four flavours of
`memberships/:uid/delete`, `…/status` on tenants and organizations (which
includes transitions to deleted), `tenants/:id/suspend`, and
`subscription/status`, on both surfaces. The non-destructive remainder still
creates tenants, mints tokens (`users/:uid/tokens/new`) and grants role
assignments, which is not a lesser concern.

**The surface is cookie-authenticated**, so CSRF is applicable in principle.
`routes/admin/auth.rs`'s `bearer()` tries the `Authorization` header first and
then **falls back to the admin cookie** "(browser Leptos clients)".

**And the cookie is `SameSite=Strict`.** `routes/admin/admin_login.rs:77`:

```rust
"{}={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}"
```

`__Host-cesauth_admin` is therefore not sent on **any** cross-site request. A
cross-site POST to any of the 35 arrives with no credential and is rejected by
the auth gate. **There is no exploitable CSRF path today**, and any report of
this finding that omits the cookie overstates it.

**The project already reasons this way.** `routes/session.rs:36`: *"SameSite=Lax
on the session cookie is the primary defense (cross-origin POST does not carry
the cookie, so logout is a no-op anyway). The Origin check is defense-in-depth."*

## 3. Why it is still P1

**The asymmetry is the tell.** The `/me` surface uses `SameSite=Lax` — it must,
so that following a magic link from an email works — **and** calls
`csrf::verify`. The admin surfaces use `Strict` and call nothing. As
engineering that is coherent: each surface has exactly the protection its cookie
policy requires.

As a **record** it is false, and the falseness is load-bearing:

1. **A reader checking whether these routes are CSRF-protected reads
   `required` and stops.** They conclude a token check runs. It does not. This
   is the project's named recurring defect class — documentation asserting what
   the code does not do — on a security control, 33 times out of 35.
2. **One attribute is the entire defence, and nothing guards the attribute.** No
   test asserts `SameSite=Strict` on `__Host-cesauth_admin`. If it is ever
   relaxed to `Lax` for a navigation reason — exactly the reason `/me`'s cookie
   is `Lax` — then fifteen destructive operations become cross-site reachable,
   **no test fails, and no document changes**, because the document already
   claims a protection that was never there.
3. **It cannot be fixed by changing the column alone.** Writing `N/A
   (SameSite=Strict)` into 35 rows makes the document true and leaves the single
   point of failure unguarded and unstated.

## 4. Direction, and the decision this RFC must make

**Three options. The choice is the work; do not treat it as obvious.**

1. **Document the real control and pin it.** Rewrite the 35 CSRF cells to name
   `SameSite=Strict`, add a host test asserting the cookie string, and add a
   gate assertion that the admin cookie carries `Strict`. Cheapest, honest, and
   leaves one layer.
2. **Add `csrf::verify` to the 33 and keep the column as written.** Makes the
   document true by making the code match it, gives the surfaces two layers like
   `/me`, and costs 35 handler edits plus a token in every admin form — several
   of which are rendered by templates this RFC does not own. **Preferred on the
   owner's standard** (*finally clean, safe and secure*): defence in depth is
   what the document already promises, and the promise was made for a reason.
3. **Both**, with (1) first as a patch and (2) as a follow-up cycle.

**Whichever is chosen, the gate is not optional.** The failure mode here is a
silent one — a cookie attribute edited for an unrelated reason — and the only
thing that catches it is an assertion that fails. RFC 145 §13 is the standing
example of a defect that was visible on every build and reported to nobody.

## 5. The open question, answered (architect, 2026-10-27)

The question was whether option 2's cost — a `verify` call in 33 handlers and a
token in roughly 32 forms — is worth a second layer behind a first layer that
currently holds. Tested against the owner's standard rather than returned to
them.

**Correcting my own measurement answered it.** I first reported that *no*
handler on either surface verifies. It is 33 of 35: the two deletion-request
routes **do**, and they are the newest routes on either surface, written three
days ago under RFC 147 cycle 2 — applied by the dev team without being asked,
because it is what this codebase does for a destructive POST.

So option 2 is not a new direction needing justification against its cost.
**It is the direction the codebase is already taking, and option 1 would mean
deliberately reversing it** for the 33 routes that predate the habit. On
*finally clean, safe and secure*, that settles it.

**Decision: option 3 — both, in this order.**

- **Half A (patch, 0.86.3).** Make the document true and pin the control that
  actually works: the 33 CSRF cells say what defends them today, a host test
  asserts the `__Host-cesauth_admin` cookie string including `SameSite=Strict`,
  and a gate fails if that attribute changes. **Half A lands first because the
  dangerous failure mode is silent** — a cookie attribute edited for a
  navigation reason, with nothing failing — and half A is what makes it loud.
  It is also small enough that it should not wait behind half B.
- **Half B (its own cycle, after 0.87.0).** The 33 `csrf::verify` calls and the
  ~32 form tokens, after which the cells revert to `required` and mean it.

**Half B is sized, not hand-waved**: 33 handlers and ~32 templates across
`tenant_admin/forms/*` and the whole `tenancy_console` tree, none of which
currently takes a token parameter. That is a cycle of its own and must not be
bolted onto another.

The owner may overturn this; it is a cost judgement, and I have made it rather
than handed it back.

## 6. `GET /admin/login` sets a cookie for an unvalidated token (2026-10-28)

Found while reviewing 0.86.3, which implemented half A. **Recorded here rather
than as a new RFC**: it is the same surface, the same shape, and half A's own
work extracted `admin_cookie_header` from this very handler. **Scheduled into
half B's cycle.**

### 6.1 The documentation claimed a validation that does not happen

`routes/admin/admin_login.rs`'s module doc said:

> *This handler: 1. Validates the token (same `auth::resolve_from_request`
> gate). 2. Sets the `__Host-cesauth_admin` httpOnly cookie.*

The handler screens `token.len()` between 16 and 256 and **sets the cookie**.
Its own body says so — `:24` explains why `resolve_from_request` cannot be
called there, `:31` says *"Here we just screen for"* length. **So one file
contained both the claim and its refutation**, eleven lines apart, and the
module doc is the half a reader meets first.

**Corrected in this release** — a doc fix on a security claim, in a file the
cycle was already editing. Not deferred to half B, because the next reader
should not meet the wrong version.

### 6.2 What remains for half B: the endpoint accepts a cookie value from anyone

Because the token is unvalidated at this point, **a crafted link sets an
arbitrary `__Host-cesauth_admin` cookie in whoever follows it.**

This is **not an authentication bypass** — the token is validated on the next
`/admin/*` fetch, so a garbage value fails immediately. Two consequences that
are real:

- **Login CSRF / cookie fixation.** An attacker holding a *valid* operator
  token can induce an operator to follow
  `…/admin/login?token=<attacker's token>` and thereafter the victim operates
  the console as **the attacker's principal**. Every admin action they take is
  attributed to the attacker's token in the audit chain. For a product whose
  audit log is hash-linked and tamper-evident (RFC 128), **writing correct
  entries against the wrong principal is the worse failure** — the record is
  intact and wrong.
- **Denial of console access.** The same link with a garbage token overwrites a
  working operator's cookie, locking them out of the console until they
  re-login.

**`SameSite=Strict` does not help here**, and the security-notes bullet
claiming it is *"CSRF-safe for a navigation-only endpoint"* overstated it.
`Strict` governs whether the cookie is **sent** cross-site; it says nothing
about this endpoint **setting** one after a top-level navigation the operator
was induced to make. That bullet is corrected in this release too.

### 6.3 Direction, for half B to decide

The constraint that produced this is real: the handler cannot call
`resolve_from_request`, because that resolver reads the credential from the
header-or-cookie path this handler is about to populate. Three candidates:

1. **Validate the token directly** against the admin-token store before
   setting the cookie, bypassing the request-shaped resolver. Removes both
   consequences. Likeliest right answer.
2. **Bind the cookie to a one-time, server-issued handle** instead of the
   bearer token, in the style of `post_auth`'s pending cookies — which also
   gets the bearer token out of URLs, browser history and logs, something the
   existing security note acknowledges and accepts.
3. **Accept it and document it accurately.** Honest, and leaves an
   audit-attribution hazard on the operator surface.

**(1) is cheap and (2) is better.** Half B's cycle should cost both before
choosing; the token-in-URL exposure is already accepted in writing, so (2) is
a larger change than the defect strictly requires.

### 6.4 Correction — (1) does not remove both consequences (architect, 2026-10-31)

**The sentence above claiming option (1) "removes both consequences" is wrong,
and it was mine.** It removes the **denial-of-access** consequence: nothing is
set before validation, so a garbage token can no longer overwrite a working
operator's cookie. It does **nothing** about **login CSRF**, because the
attacker's token is *valid* — that is the premise of §6.2's attack. Option (2)
narrows the window and does not close it either: an attacker can mint their own
one-time handle and induce the victim to consume that one.

**What fixes login CSRF is requiring the operator's intent.** The cookie must be
set by a request the operator deliberately submitted, not by a navigation they
were induced to make. **Stage 2 therefore does validation *and* a confirmation
step**: `GET /admin/login?token=…` validates against the store and renders a
page carrying a CSRF token and **the identity the operator is about to assume**
(the admin token's name and role); a new `POST /admin/login` verifies the CSRF
token and sets the cookie. `SameSite=Strict` means no attacker page can submit
that form, and an operator who followed an unexpected link sees whose console
they are about to hold.

The token-in-URL exposure is unchanged and still accepted in writing; option
(2) stays the recorded end state for its own RFC rather than riding on a defect
fix.

**Dispatched 2026-10-31** as stage 2:
`handoffs/152-the-admin-surfaces-documented-csrf-control-is-not-the-real-one/half-b-stage-2-handoff.md`.
