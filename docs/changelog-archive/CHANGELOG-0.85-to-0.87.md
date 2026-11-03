# cesauth — CHANGELOG (archive: v0.85–v0.87)

> This file is part of the changelog archive.
> Current releases are in the root [`CHANGELOG.md`](../../CHANGELOG.md).

## [0.87.1] - 2026-10-28

### Two silent failures made loud — RFC 148 §7, RFC 156

Both changes are about the same thing: something could stop working and nobody
would find out.

### Fixed

- **The invitation-email scrub now reports whether it happened.** v0.87.0 made
  account deletion scrub the address from `invitation_tokens`; the scrub
  necessarily runs after the user row is already gone, so a failure cannot be
  reported as a failure to delete the user — and it was reported as nothing at
  all. `execute_deletion` now returns the outcome (`scrubbed`,
  `no_email_on_file`, or `failed`), both the admin route and the daily sweep
  record it in the `deletion_executed` audit event and log a failure as an
  error, and "there was no address to scrub" is distinguishable from "the
  scrub did not happen" — which it was not before.

### Added

- **A manifest of the gates a release must pass, and a check that they ran.**
  Nothing previously noticed if a CI workflow stopped running: a missing job is
  twelve green checks instead of thirteen, and nobody counts. The required set
  is now checked in at `.github/release-gate-manifest.json`, with a separate
  category for workflows deliberately off the release path — each needing a
  stated reason, which the check enforces. A new workflow verifies, on every
  push to `main`, that every required gate triggered and that nothing
  triggered which the manifest does not know about. **It reports; it does not
  block**, consistent with every other gate here.
- The JWT-parser fuzz job gains a **weekly schedule**. It triggers on pull
  requests touching the parser and on demand, but on no push — so no release
  had ever been covered by it. Keeping it off the release path is deliberate
  and now recorded as a decision with its reason: a non-deterministic
  60-second run should not gate releases that go nowhere near the parser.

---

## [0.87.0] - 2026-10-28

### The `/me` surface tells the truth about itself — RFC 149, RFC 148, RFC 154

### Added

- **A user can request deletion of their own account, and cancel it.** The
  endpoint had existed since v0.53.0 with **no caller** — no form, no link, no
  test — so the capability was documented and unreachable. `/me/security` now
  carries a "Delete account" section stating the consequence and the grace
  period in days, read from the same constant the server enforces so the number
  shown cannot drift from the number applied. A pending deletion's notice now
  states the deadline, that it can be stopped, and carries the control that
  stops it; previously it was an alert naming a date with no way out and no
  explanation of who could act. Both forms post natively with a double-submit
  CSRF token. **Nothing implies an executed deletion is reversible, because it
  is not.**
- **Six audit events for the second factor.** Enrolment, verification success,
  verification failure, the attempt-limit lockout, disablement and
  recovery-code use each now write a record. None did before: an operator
  investigating a suspected compromise could not tell whether the second factor
  had been satisfied, and the attempt lockout tripped silently, so a
  brute-force attempt against a TOTP gate left no trace. `mfa_verified` had
  been declared since its introduction and emitted nowhere.

### Changed

- **`POST /me/security/delete-account` answers JSON, not a redirect.** It
  returned `302` both when a deletion was scheduled and when the caller was not
  authenticated, so a client following redirects received `200` and an HTML
  page in both cases and could not tell whether it had just scheduled the
  destruction of an account. It now returns `200` with `{"scheduled_at": …}`,
  `401` for an unauthenticated caller, and JSON bodies for the `409` and `400`
  cases. **The `Content-Type: application/json` requirement is unchanged** —
  it is this route's CSRF control.
- Seven audit event kinds that are deliberately never emitted now say so on the
  variant, naming the kind that supersedes each. One of their existing comments
  was itself wrong about which events fire; corrected.

### Fixed

- **Deleting an account now scrubs the user's email address from
  `invitation_tokens`**, the one table that holds a deleted user's personal data
  and no foreign key to `users`. The address is replaced with a per-row
  tombstone; the administrative record of what an admin did — who issued the
  invitation, when, and with what role — is kept, because that is not the
  deleted user's data to erase. **The scrub is best-effort and its outcome is
  not yet reported**: it necessarily runs after the user row is gone, and a
  failure currently leaves the address in place with nothing recording it.
  Tracked, and the reason that RFC is not yet closed.
- Two `jq` examples in the first-OIDC-flow tutorial selected a field shape the
  dev audit route has not returned for some time.

---

## [0.86.3] - 2026-10-28

### Three documented security controls now have something that fails — RFC 150, RFC 152 half A, RFC 155

Each of these controls was described in the project's own records, held in
practice, and was enforced by nothing. None was being violated. All three now
have a test or gate that has been demonstrated to fail when the control is
removed.

### Fixed

- **The CSP nonce was per-isolate, not per-request** (RFC 150). Seven HTML
  responders outside the admin console never generated one, so the
  security-headers middleware reused whatever the isolate's previous request
  had left — header and document agreed, nothing looked wrong, and the nonce
  was no longer unpredictable per response. Measured directly: a nonce minted
  for one request appeared unchanged in the next, unrelated one. All seven now
  mint through a single shared helper, and the operator login page's inline
  `<style>`, which carried no `nonce` attribute at all, now carries one.
- **The admin surfaces' CSRF column named the wrong control** (RFC 152 half A).
  Thirty-three of thirty-five `POST` routes under `/admin/t/:slug/*` and
  `/admin/tenancy/*` documented CSRF as `required`, meaning a double-submit
  token check, and performed none. The actual defence is the admin cookie's
  `SameSite=Strict`, which no row mentioned and no test asserted. The rows now
  name it, and the cookie's attributes are pinned by a host test and a live
  smoke-check probe. **No behaviour changed**; the token checks themselves are
  separate work and are not in this release.
- **A secret could reach `Debug` output** (RFC 155). `MagicLinkPayload` carried
  a derived `Debug` while documenting its `code` field as *"Secret. OTP
  plaintext"*; for invitations that field holds a full accept URL rather than
  an expiring code. Nothing formatted the payload, so nothing leaked. `code`
  now renders as a redaction marker, asserted against both shapes.
- **The generic auth-failure messages were unasserted** (RFC 155).
  `/magic-link/verify` correctly refuses to distinguish an expired code from a
  wrong one, and no test said so — splitting the two for a friendlier error
  would have restored the information oracle silently. Both messages are now
  asserted at the decision boundary.
- **The admin login page's documentation claimed a check it does not perform.**
  Its module header said the handler validates the token before setting the
  session cookie; it screens the token's length, as the handler's own comments
  explain. Corrected, along with a security note that overstated what
  `SameSite=Strict` protects.

### Added

- A route-contract gate: `Response::from_html` must not be reached without a
  nonce being minted in the same function, with one named indirection that is
  **re-verified on every run** rather than trusted, and a hard failure when the
  enclosing function cannot be resolved.

---

## [0.86.2] - 2026-10-27

### The tenancy console's twenty-one dead pages, and the gate that closes the class — RFC 145 cycle 3

Twenty-one `GET` routes under `/admin/tenancy/…` were documented as
client-rendered, served the Leptos shell, and had no route in the client
router. Each now renders the template its own `POST` sibling already used on a
failed submit: organization detail and set-status; create-group, add-member and
remove-member under an organization, a group and a tenant; delete-group; tenant
set-status and create; subscription history, plan and status; a user's role
assignments, the grant form and the revoke form; and token minting.

No screen was designed — every template already existed.

**This completes RFC 145**: thirty-five routes across three releases
(v0.85.1, v0.86.1, v0.86.2).

### Added

- **The route-contract check now fails on a client-declared `GET` with no
  working client route.** It distinguishes three outcomes rather than two:
  *exact* (pass), *absent* — no route of any shape — and ***shadowed***, where
  a sibling route's `:param` captures a literal segment. The shadowed case is
  the worse symptom and the one that had gone undetected: a path like
  `/admin/tenancy/tenants/new` binds `new` to `:tid` and renders the
  **tenant-detail page for a tenant named "new"**, rather than a Not Found.
  One named exemption, `/admin/console/clients`, which RFC 141 owns.

### Fixed

- **The tenancy console's three add-member forms posted to a path the worker
  does not serve** (`…/memberships`, missing the `/new` suffix), so a submit
  would have returned 404. Latent until now, because the page that renders the
  form had never been reachable. Recorded as open since RFC 108.

---

## [0.86.1] - 2026-10-27

### Twelve tenant-admin pages stop answering 200 with Not Found — RFC 145 cycle 2

Twelve `GET` routes under `/admin/t/:slug/…` were documented as
client-rendered, served the Leptos shell, and had no route in the client
router — so the fallback rendered **HTTP 200 with a Not Found page**, after the
server had authenticated the administrator and authorised the read. Each one
now renders the template its own `POST` sibling already used on a failed
submit:

- organization detail, and the set-status form
- create-group and add-member forms under an organization
- delete-group, add-member and remove-member under a group
- remove-member at the tenant level
- a user's role assignments, the grant form, and the revoke form

No screen was designed and no surface was added: every template already
existed. Two `.json` companions — `organization_detail` and
`role_assignments` — were deleted with the pages they existed to feed, having
no other consumer. Route count 192 → 190.

Each converted row is now declared `server`, which brings it under the
route-contract check that fails if a handler goes back to serving the shell.

### Fixed

- **A runtime smoke probe became an assertion instead of disappearing.** The
  probe for the deleted `…/organizations/:oid/detail.json` now asserts `404`
  rather than being removed. The generic unknown-route probe proves the router
  404s paths it does not know; only this line proves this route is gone.

---

## [0.86.0] - 2026-10-27

### Account deletion works — RFC 147 cycle 2, completing RFC 047

**Nothing in cesauth had ever executed a deletion.** 0.85.1 stopped three
endpoints claiming otherwise; this release makes them work.

A user can now request deletion of their own account and see it pending in the
security centre, read from their own state rather than from a URL parameter. A
tenant admin sees the tenant's queue of pending requests on a server-rendered
page, and can cancel a request or execute one immediately. The daily cron
executes requests whose 30-day grace period has passed.

Three things that were wrong underneath are fixed with it:

- **The self-service route required an administrator.** `POST
  /me/security/delete-account` has always checked the admin bearer resolver, so
  a user's own session was rejected and the route was unreachable by the only
  principal it existed for. It now authenticates the user.
- **The sweep was never called.** `sweep_pending_deletions` was written,
  correct, and reachable from nothing — the daily cron ran only the
  anonymous-trial retention sweep. It is now wired, and verified by driving the
  real scheduled handler rather than the function.
- **The audit subject was the wrong principal.** Deletion events recorded the
  *admin* as the subject, or nobody at all; they now record the affected user,
  with the acting principal kept on the request row where it is queryable.

A request id that does not exist, or belongs to another tenant, returns 404 and
writes **no** audit event — and no event is written for any operation that did
not occur.

**What deletion does and does not remove.** The user row and every child table
with a foreign key to it: authenticators, sessions, TOTP state, tenancy
memberships, role assignments — 28 tables. **`invitation_tokens` is not
removed**: it has no foreign key to the user, and carries a plain-text email
address, so a deleted user's invitation history for the tenant survives.
Whether to purge or scrub it is a separate decision and is recorded as one.

**Deletion is irreversible, and the documentation now matches the code at every
step** — including the cron description, which claimed for several releases that
pending deletions were being executed.

### Removed

- `GET /admin/t/:slug/deletion-requests.json` — it returned only a CSRF token,
  and the queue page it served is now rendered server-side. **Route count 193 →
  192.**

## [0.85.1] - 2026-10-27

Everything in this release was asserting something it could not back.

### Three deletion endpoints stop claiming success — RFC 147 cycle 1

`POST /me/security/delete-account`,
`POST /admin/t/:slug/deletion-requests/:id/cancel` and
`…/execute` each wrote an audit event, logged, and redirected with a success
parameter — **without touching the deletion-request repository.** An admin who
"executed" a deletion got `DeletionExecuted` in the audit log, a redirect saying
`executed=1`, and no deletion. The id was never validated, so the event could be
written for a request that did not exist.

They now emit **no** audit event and return **`501 Not Implemented`**, after
their existing authentication, authorization and CSRF checks. The success
parameters are gone, and the operator documentation no longer promises an
irreversible deletion it does not perform.

**This is a withdrawal, not a fix, and it is deliberate.** Nothing here
implements deletion — that is the next release. Ending a false claim requires
implementing nothing, so it ships first. No flow is lost: no screen links to any
of the three, and the self-service route has always required an admin bearer, so
no end user could reach it.

**Nothing in cesauth has ever executed a deletion.** The sweep that was supposed
to — `sweep_pending_deletions` — is fully written and is called by nothing; the
daily cron runs the anonymous-trial retention sweep only. Found while verifying
this change, and fixed in the next release.

### The admin surface's CSP nonce can match its own document — RFC 146

The helper that renders every admin page minted its Content-Security-Policy
nonce **after** its caller had already rendered the body. Arguments are
evaluated before the call, so the document was built from whatever nonce the
previous request left behind: body and header named different nonces, and the
inline stylesheet every admin page carries was blocked by its own policy.

Measured on a running Worker before the fix, the second request's body nonce was
**exactly the first request's header nonce**. The helper now takes a closure and
renders inside it, so the body cannot exist before the nonce does. 77 call sites.

This makes the stylesheet those pages already carried take effect. It is not a
styling change.

### Two admin pages render instead of answering "Not Found" — RFC 145 cycle 1

Thirty-five admin `GET` routes documented as client-rendered serve the
single-page-app shell, while the client router has no route for any of them — so
each answers **200** with a Not Found page, after an administrator has
authenticated. `/admin/console/tokens/new` was the only one reachable by
following a link: an operator clicking "new token" on the working tokens screen
landed on it.

That route and `/admin/console/config/:bucket/edit` now render the server
template their own modules already contained — the same template their form-error
path has always rendered. **Thirty-three remain**, deliberately, and are the next
patch release.

### A gate that could not see what it was written to detect

The check that enforces server-side rendering scanned a handler's own body for
the shell call. Both shell helpers wrap it one level down, so a handler serving
the shell through either **passed the check** — which is every one of the
thirty-five routes above. It now follows one level of indirection and
re-verifies each wrapper's own body on every run, failing loudly rather than
passing silently if that stops being true.

## [0.85.0] - 2026-10-25

### An OIDC client can be registered over an API — RFC 141

Registering a client meant hand-writing `INSERT INTO oidc_clients (…) VALUES
(…)` against D1, with the column list elided in the guide and a secret hash the
operator had to compute themselves. The product's primary integration action had
no API.

Now there is one, under `/admin/console/clients`: create, list, read, update,
rotate the secret, and delete. **The secret is shown once, at creation and at
rotation, and is never retrievable afterwards** — the record stores a hash, so
a lost secret is rotated, not recovered. Validation runs through the same code
that enforces the record later, rather than a second copy of the rules that
could drift from it.

`token_auth_method` is now **enforced at `/token`**: a client registered for
`client_secret_basic` that presents its secret in the request body is rejected,
and the method is checked before any secret comparison. The method is editable
on an existing client; `client_type` is not, because changing it would
invalidate what every issued token was authorized against.

An integrator chapter documents the whole flow. **There is no console screen
yet** — this release ships the API, and the screen is the RFC's second cycle.

### The second factor works without JavaScript — RFC 143

A user who signed in with JavaScript disabled and had TOTP enrolled reached a
second-factor page that required JavaScript. The first factor had already
succeeded and the gate cookie was set, so they were **stranded mid-sign-in**,
with no way forward and no way back.

The server-rendered page they needed already existed, was locale-aware, and was
already being served in production — but only by the *wrong-code* path, so the
only way to reach it was to submit a form they could not see. `GET
/me/security/totp/verify` now renders it directly, and the client-rendered
duplicate is deleted.

Two defects went with that duplicate. Its "Use a recovery code" affordance was a
link issuing a **GET** to a route that accepts only **POST**, so it returned a
bare 404 — to the one user it existed for, who had lost their authenticator. And
it used **no** localized strings where the server template uses twenty-nine, so
a Japanese user read English at the second factor and Japanese again if they
mistyped. Both are fixed by rendering the template that had them right all
along.

**This was verified by driving the whole path against a running worker** — real
enrolment, genuine time-based codes, the gate reached by a second sign-in — not
by a browser test. The automated suite does not reproduce it; what CI now
guards is that the page cannot silently revert to requiring JavaScript, and that
the form's CSRF token and its cookie carry the same value.

### A CSRF control the route contract claimed, and the code lacked

`POST /admin/console/audit/export` was documented as requiring a CSRF token and
did not check one, while reading a form-encoded body — exactly the content type
that requires it. The control now exists. A forged request could have forced an
export and an audit event; the exported data reached the victim's own browser,
not an attacker.

### A timing advisory accepted, with its reasoning recorded

RUSTSEC-2026-0387 (`crypto-bigint`, timing variability in operations intended to
be constant-time) has no compatible update. It is reached only through
`p256`/`ecdsa`, and cesauth's only path into that crate is WebAuthn **signature
verification**, which holds a public key and a public challenge — the
authenticator keeps the private key, and JWT signing is Ed25519 throughout. A
timing side-channel discloses something about secret inputs; on this path there
are none.

**It is accepted, not fixed**, with the reasoning beside the advisory id and a
condition that voids it: if cesauth ever signs with P-256, the dependency stack
must be upgraded first.

