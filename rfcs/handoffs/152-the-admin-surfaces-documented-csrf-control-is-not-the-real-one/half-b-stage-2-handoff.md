# Developer Handoff — RFC 152 half B, stage 2: `GET /admin/login` sets a cookie for an unvalidated token

**Governing RFC.** `rfcs/accepted/152-the-admin-surfaces-documented-csrf-control-is-not-the-real-one.md` §6.
**Review of stage 1.** `.git-exclude/reviewed/152-half-b-stage-1-review.md`
**Builds on.** `c9ae019` on `main`. **Nothing to revert** — stage 1 stands; I
reproduced its control against a live Worker.

**Target release.** **0.90.0 — minor, unchanged.** Same release as stage 1, its
own cycle. **Trigger hit: the operator login flow changes.** An operator who
today pastes `…/admin/login?token=…` and lands in the console will, after this,
land on a confirmation page and click once. That is a documented flow changing
under an operator's feet — a minor on the same reading stage 1 used, and the
release is already minor. **The 0.90.0 cut waits on this.**

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-31.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. First: the RFC's own recommendation is wrong, and this handoff overrides it

RFC 152 §6.3 lists three candidates and says of the first — *validate the token
directly against the admin-token store before setting the cookie* — **"Removes
both consequences. Likeliest right answer."** That is wrong about the first
consequence, and I wrote it.

The two consequences §6.2 names are **login CSRF / cookie fixation** (an
attacker holding a *valid* operator token induces an operator to follow
`…/admin/login?token=<attacker's token>`, after which the victim operates the
console as the attacker's principal and every action is attributed to the
attacker in the hash-linked audit chain) and **denial of console access** (a
garbage token overwrites a working operator's cookie).

**Validating the token removes the second and does nothing about the first**,
because the attacker's token is valid — that is the premise of the attack.
Option 1 alone leaves the worse of the two consequences exactly where it is:
*"writing correct entries against the wrong principal"*, in §6.2's own words.

Option 2 (a one-time server-issued handle) narrows the window but does not close
it either: an attacker can mint their own handle and induce the victim to
consume that.

**What actually fixes login CSRF is requiring the victim's intent** — the cookie
must be set by a request the operator deliberately submitted, not by a
navigation they were induced to make.

## 2. The design

**`GET /admin/login?token=…` stops setting a cookie.** It:

1. **Validates the token against the store**, directly —
   `CloudflareAdminPrincipalResolver::new(env).resolve(&token)`, the same call
   `auth::resolve_from_request` makes after it has pulled the bearer out of the
   request. The reason §6.3 gives for the current state (*"the resolver reads
   the credential from the header-or-cookie path this handler is about to
   populate"*) applies to `resolve_from_request`, not to the resolver itself;
   the resolver takes a `&str`. **This is the whole of option 1 and it is two
   lines.** An unknown or disabled token gets the same failure treatment any
   other `/admin/*` request gets — including the `AdminLoginFailed` audit
   event, which this path does not currently emit.
2. **Renders a confirmation page** carrying a freshly minted CSRF token
   (`csrf::mint` + `csrf::set_cookie_header`, the pattern stage 1 standardised
   in `tenancy_console/forms/common.rs`), a hidden field carrying the bearer,
   and **the identity the operator is about to assume** — the token's `name`
   and `role` from the resolved principal. Say it plainly: *"You are about to
   sign in to the operator console as **&lt;name&gt;** (role: **&lt;role&gt;**)."*
   An operator who followed a link they did not expect sees whose console they
   are about to be holding, which is the whole point.

**`POST /admin/login`** — new route — verifies the CSRF token, re-validates the
bearer, sets `__Host-cesauth_admin` via the existing `admin_cookie_header`, and
`303`s to `/admin/console`.

Why this closes both: a cross-site top-level navigation can still *land* the
operator on the confirmation page, but `SameSite=Strict` means no attacker-
controlled page can make the browser submit that form with the CSRF cookie
attached, and the operator must click a button that names the identity. The
garbage-token lockout is gone at step 1 — nothing is set before validation.

**What this does not fix, and must not pretend to:** the bearer token still
travels in a URL, in browser history and in logs. That exposure is already
accepted in writing in `admin_login.rs`'s own security notes. **Do not** build
option 2's one-time-handle scheme here — record it as the end state, in the RFC,
with the token-in-URL rationale attached, and it gets its own RFC when someone
decides to spend that. **Say in your report that you did not do it and why.**

## 3. Riders — small, and all in files this cycle already opens

### (a) Stage 1 left two now-false security claims in `admin_login.rs`

**Mine, from scoping that file out of stage 1.** Half A extracted
`admin_cookie_header` precisely so one place would state the real control —
and that statement is now wrong:

- `:50-51` — *"it is the **entire** defense for every `POST` on the
  tenant-admin and tenancy-console surfaces (33 of 35 routes; the remaining
  two … additionally call `csrf::verify`)"*. After stage 1 it is **34 of 36
  that verify** and `SameSite=Strict` is **defence in depth**, not the entire
  defence.
- `:187` — the test's own assertion message says *"SameSite=Strict is the
  entire CSRF defense for 33 of 35"*. The assertion still passes; its stated
  reason is false. **Keep the test** — the cookie attribute is still worth
  failing loudly on — and correct what it says about why.

Half A existed because a document named the wrong control. Leaving its own
explanation behind after changing the control is the same defect with the
authors reversed.

### (b) E6's function-body boundary

`e6_fn_body` in `scripts/route-contracts-check.sh` stops only at the next
**top-level `pub async fn`**, so a non-`pub` `async fn` following a handler is
swallowed into the slice — eight files in stage 1's own set have that shape.
**No false pass today**: I re-derived all 34 rows with brace counting and E6
agrees row for row. Harden it anyway — stop at any top-level `fn`, or count
braces — and **prove the hardening with the same negative test stage 1 used**
(neutralise one `verify_csrf`, confirm exit 1 names that row, restore and
byte-diff).

### (c) The two caller-less routes get a sentence, not a cell change

`tenancy_console/tenant_detail.rs::{suspend,restore}` keep
`N/A (SameSite=Strict)` — correct, verified: neither reads a form body, and
`cesauth_core::routes::tenant_suspend`/`tenant_restore` are referenced nowhere
outside their own definitions. **Do not change those two cells** (they are true,
and E6 keys on the exact `required` string). Add **one sentence of prose beside
the table** recording that these two paths have no caller and are superseded by
`tenant_set_status.rs`'s preview/confirm flow, so a reader does not mistake an
honest `N/A` for an unexamined one.

They are deletion candidates on RFC 159's precedent, and **neither gate can see
them** — E4 passes because they *are* registered, E5 cannot because a form
`POST` is not a `.json` fetch. That is a third category for RFC 166's census:
**a registered route no caller invokes.** Recorded there; **not** this cycle's
work. Do not delete them here.

## 4. Tests

- **Host-testable, and that is where the value is:** the confirmation page's
  rendering is a pure function of (name, role, csrf, bearer) — assert that it
  escapes all four (RFC 108 escape contract), that the hidden bearer field and
  the CSRF field are both present, and that the operator's **name and role
  appear in the visible text**. The last one is the user-facing promise of this
  design; a page that sets a cookie without naming whose it is would pass a
  CSRF test and fail the point.
- The CSRF decision itself reuses stage 1's `verify_csrf`, already covered.
- **What cannot be host-tested** is the handler path (`worker::Env`, D1, cookie
  headers). Exercise it against `wrangler dev` and **capture the status lines**:
  `curl -s -o /dev/null -w "%{http_code}"` for each of — `GET` with a valid
  token (200, no `__Host-cesauth_admin` set), `GET` with a garbage token (not
  200, no cookie), `POST` with no CSRF (400), `POST` with a wrong CSRF (400),
  `POST` with the matching CSRF (303 **and** `__Host-cesauth_admin` present).
  **Status codes carry no secret** — redact tokens, capture the codes. Stage 1's
  live evidence was prose about exactly this, which is the one thing in that
  cycle I could not take on trust and had to re-run myself.
- Full gate set. **Baselines at `c9ae019`:** host tests **1,644 passed / 0
  failed / 12 lines**, `migration_chain` **35**, route-contracts 193 registered,
  **E4 `215 = 193 + 22 + 0`, E5 `16 = 16 + 0 + 0`, E6 `36 scanned / 34 required
  / 34 resolved / 0 unresolved / 2 distinct field names`**, Playwright **20**,
  manifest **13 + 1 = 14**. Expect E4's and E5's figures to move: you are adding
  a route and a page.
- `route-contracts.md` needs a row for `POST /admin/login`, and `GET
  /admin/login`'s existing row needs its view/rendering cells re-checked against
  what it now returns.

## 5. What to report

- The three `GET`/`POST` status captures above, as captures.
- What the confirmation page says, verbatim — I will read it as an operator
  would, not as a diff.
- Whether validating in the `GET` changed any existing behaviour you did not
  expect (an audit event that now fires, a redirect that no longer does).
- E6's coverage line after the hardening, and the negative test's output.
- Surface-contract disclosure: the login flow change, stated for the CHANGELOG.
- Anything in §2 you believe is wrong. **I have now been wrong twice in two
  handoffs on this RFC** — once on which file serves the invitation form, once
  on whether option 1 fixes the attack — and both times you found it. Keep
  doing that.

## 6. Stop conditions

Stop and report rather than widening scope if:

- the resolver cannot be called with a bare `&str` without dragging in a
  request-shaped dependency — that is §2 step 1 being wrong, and it is mine;
- the confirmation step breaks an existing documented operator procedure beyond
  the one extra click (check `docs/src/deployment/` before assuming it does not);
- option 2's one-time handle starts to look necessary to make §2 work at all;
- the e2e or smoke suites depend on the current cookie-on-`GET` behaviour —
  report what they assert before changing them.
