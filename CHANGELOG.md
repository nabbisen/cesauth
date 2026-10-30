# Changelog

All notable changes to cesauth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

cesauth is in active development. The public surface — endpoints,
`wrangler.toml` variable names, secret names, D1 schema, and
`core::ports` traits — may change between minor versions. Breaking
changes will always be called out here.

---

## Older releases

**v0.84.x and earlier are in [`docs/changelog-archive/`](docs/changelog-archive/README.md)**,
split by minor range and never edited after creation. This file keeps the most
recent five minor versions, under the ~80 KB budget RFC 028 set — enforced by
`scripts/changelog-archive-split.sh`, which refuses to split a file already
under budget.

---

## [0.89.4] - 2026-10-31

### The operator console stops claiming features it does not have — RFC 161 §9(a), RFC 167 slice 1

No behaviour changes in this release. It corrects documents and on-screen copy
that described a working operator console where there is none, and a front page
that contradicted its own chapters.

### Fixed

- **Eight rows of the route contract named views that do not render.**
  `/admin/console/{cost,safety,audit,audit/chain,config,alerts}` were documented
  as *"cost page"*, *"audit search page"*, *"chain status page"* and so on;
  `/admin/console/tokens` as *"token list"* (it lists nothing) and
  `/admin/console/clients` as *"client list"* (it renders a 404 page over a
  `200`, because no client-side route exists for it). All eight now say what
  they actually serve. A ninth, `/admin/console`, was overstated rather than
  false and got a corrective note.

- **Eight handler doc comments described rendering that never happens.** The
  worst specified a feature in full: `audit.rs` documented **nine query
  parameters** — `prefix`, `limit`, `kind`, `subject`, `actor`, `event`, `from`,
  `to`, `cursor` — with per-field matching semantics and parsing rules, and the
  handler reads none of them. `overview.rs` claimed to roll up alert counts, the
  last five safety alerts, the last ten audit events and three recently-verified
  buckets, *and* said who could see them. Those claims are gone; every accurate
  sentence about the real `POST` handlers behind the same modules survives
  untouched.

- **The operator incident-response chapter sent readers to a page that does not
  exist.** `docs/src/deployment/observability.md` presented
  `/admin/console/audit` as *"the admin console's audit browser"*, with
  per-filter behaviour and an edge case about invalid timestamp bounds, then
  said the console *"covers most needs"* for day-to-day incident response. It
  also listed four `Console: <filter>=…` recipes alongside working SQL, under an
  introduction claiming *"the two syntaxes that actually exist."* There is one.
  The chapter now names `wrangler d1 execute --remote` as the production read
  path, which it already documented, and says the console surfaces are not
  built.

- **The six placeholder pages promised data too.** Each said the information
  *"will be displayed here"*. They now say the feature is not built, and only
  the audit page names an alternative — because only the audit page has one. The
  chain page distinguishes what works (the daily verification cron, and the
  re-verify action) from what does not (any way to see or trigger either from
  that page).

- **Two false claims on the front page.** `README.md` said operators forward
  audit events to an external SIEM via Cloudflare Logpush; Logpush carries
  Worker log lines, and audit events are D1 rows — the deployment chapter says
  in as many words that cesauth does not push them anywhere today. And three
  badges advertised a `cesauth` crate on crates.io and docs.rs: what is
  published there is a **`0.0.0` name reservation**, every workspace crate
  carries `publish = false`, and the README now says so next to the badges.

### Changed

- **The README's Quick start is split by reader.** *"Run it locally"* is the
  contributor and evaluation loop it always was. *"Deploy it"* is new: the spine
  of a real deployment in the order you actually do it — pre-flight and
  provisioning, migrations `--remote`, secrets, confirming `WRANGLER_LOCAL` is
  off, cron triggers, `wrangler deploy`, your first OIDC client, observability,
  day-2 — each line linking the chapter that owns the procedure. The two chapter
  steps it leaves out are named, so the spine does not become its own
  incomplete list.

  One line departs from the chapter's numbering and says so where you read it:
  registering your first OIDC client comes *after* deploy, because the chapter's
  own Step 5 curls a URL that Step 9 is what deploys.

### Notes

- **Nothing shipped here restores a console feature.** The six surfaces were
  built, shipped, and disconnected by one commit in May; restoring them is
  scheduled, and this release only stops four kinds of document from claiming
  the work is already done.

---

## [0.89.3] - 2026-10-30

### A tenant owner's first page asked for a URL nothing serves — RFC 162

### Fixed

- **The tenant-admin overview showed an error instead of the tenant.**
  `/admin/t/<slug>` fetched `/admin/t/<slug>.json` for its data — one segment
  short of `/admin/t/<slug>/detail.json`, the route that actually serves it.
  Because `:slug` is a path-segment capture, it swallowed the whole segment
  *including* the literal `.json`, so the request matched the shorter HTML route
  and asked it for a tenant named `"<slug>.json"`, which does not exist: **404**,
  surfaced to the page as a generic error. This was the first page a tenant's
  owner reached on the console v0.89.0 had just made reachable for the first
  time.

- **The system-admin tenant detail page rendered empty, with no error at all.**
  `/admin/tenancy/tenants/<tid>` fetched `/admin/tenancy/tenants/<tid>.json`,
  the same mistake — but here the capture resolves to a **registered page
  route**, which answered `200` with the Leptos bootstrap HTML. Parsing HTML as
  JSON failed, and `.ok()` turned the failure into "no data", so the page
  rendered its empty branch silently.

  Both fetches now point at the `…/detail.json` routes that exist. Each page
  also gained a host test witnessing what its *existing* failure path shows the
  caller — neither page's error handling was changed.

- **Visible only on client-side navigation**, which is how the console's own
  links work: a hard load is served the shell by the correct HTML route, so
  the broken fetch ran only after the app had mounted.

### Added

- **A check for the opposite direction of v0.89.2's.** RFC 159's `E4` asks
  whether a registered handler is reachable; the new `E5` asks whether a URL the
  frontend *fetches* is. A `.json` URL in `crates/frontend/src` — literal or
  `format!`-built — must resolve to a registered `GET` route, and the build
  fails if it resolves to none or resolves **only by being swallowed by a
  capture**, which is the defect above and is invisible to a check that compares
  segment counts alone.

  Candidate routes of the same length are tried **fewest captures first**, not
  in registration order. Without that, an already-correct, fully-literal route
  is reported as swallowed by an unrelated capture — a false positive that
  appeared in two independent prototypes of this check before the ranking was
  added.

  Inside the existing script and workflow, so the release-gate count is
  unchanged at 13.

### Removed

- **`TenancyFormPlaceholder`**, a third component building a broken `.json` URL
  (against form routes whose `.json` companions v0.88.1 deleted) and checking
  only `status() == 200` without parsing the response. It had no caller
  anywhere. Deleted rather than exempted from the new check.

### Changed

- **`cargo test` now needs `--features cesauth-frontend/csr`** to run the whole
  suite, and CI and the contributing guide were updated together. The
  frontend's `pages` module — which holds both pages fixed above — is gated
  behind that feature, so without the flag neither it nor its tests compiled
  during testing at all. The feature is purely additive: no test that ran
  before stops running, and the suite goes from 1,630 to 1,636.

---

## [0.89.2] - 2026-10-30

### Ten handlers no lint could see, and a check that would have seen them — RFC 159

### Removed

- **Ten request handlers that no route pointed at, invisible to every lint the
  project runs.** RFC 157 had deleted twenty-nine of the same kind one release
  earlier, on the premise that the compiler reports the rest through unused
  imports and unused variables. For these ten it cannot: each one *uses* its
  `req` and `ctx` — passing them to a helper, or into a response it builds —
  before doing nothing anyone can reach. Nothing was unused, so nothing warned,
  and the gate added by that release shipped green over all ten.

  Nine were `page_json` companions beside operator- and tenancy-console pages.
  The tenth, `admin::console::preview::handler`, was found by the new check on
  its own first run: a leftover `501` stub superseded by `config::preview`,
  whose **doc comment claimed "the route itself is registered"** when the live
  route at that path resolves to the other function entirely. A reader who
  opened the file to check was told it was fine.

### Added

- **A routing check that asks the question no previous gate asked: is this
  handler registered at all?** `scripts/route-contracts-check.sh` gained an
  `E4` section — inside the existing script and workflow, so the gate count is
  unchanged at 13 — which fails the build when a handler-shaped `pub async fn`
  under `crates/backend/src/routes/` has no qualified path reachable from
  `lib.rs`, directly or through one level of `pub use` re-export (brace or
  renaming form, both of which this codebase uses).

  It works off each handler's **full qualified path**, never its bare name.
  That distinction is the whole point: RFC 157's census missed these ten
  because a bare-name test clears every function that shares a name with a
  routed one, and `page`, `page_json` and `handler` are shared many times over.

- **The check measures its own coverage, and fails when it cannot.** Four
  properties, each with a fires/does-not-fire probe behind it: every
  `pub async fn` in `routes/` must be classified as a handler or named as a
  non-handler with a reason, and an unrecognised signature shape is a hard
  failure rather than a silent skip; the coverage figures must sum to the number
  scanned on every run, reported as a bug in the check rather than a finding
  about the code; and an entry in the named-non-handler list that matches
  nothing is a hard failure, because such an entry is a pre-authorised
  exemption for whatever is written at that path next.

  Handlers are recognised structurally, not enumerated: a handler **owns** its
  request, being the entry point, and a helper **borrows** it, being called by
  one. So adding a route costs no edit to the gate, and only the by-reference
  helpers need naming.

### Fixed

- **A route disabled by commenting out its registration no longer reads as
  live — or as documented.** Every extractor in the check that reads `lib.rs`
  now reads one shared comment-stripped view of it. Before, commenting out a
  single registration left the handler certified reachable *and* left
  `route-contracts.md` still required to document, and still credited with
  documenting, a route the Worker no longer serves. One edit now produces both
  the dead-handler finding and the stale-documentation warning.

  Whole comment lines only, deliberately: `lib.rs` registers the literal path
  `"/*catchall"`, which a block-comment stripper would read as an opening fence
  and consume the rest of the file from.

### Notes

- **No behaviour change.** Nothing registered, served, rendered or stored moves:
  the ten deleted functions were unreachable, and the rest of the release is a
  CI check. Host tests stay at 1,630 passed over 12 `test result` lines —
  unchanged, because not one of the ten had a test of its own, which is part of
  how they survived. The Worker bundle is byte-identical.

---

## [0.89.1] - 2026-10-29

### A missing reference is no longer reported as a duplicate one — RFC 160

### Fixed

- **An operator who mistyped a tenant owner's id was told their slug was
  taken.** Every D1 constraint failure was classified by whether its message
  contained the word `constraint`, which all four classes do — UNIQUE, FOREIGN
  KEY, CHECK and NOT NULL — so all four became `PortError::Conflict`. A
  foreign-key violation means *a row you referenced does not exist*, which is
  not a conflict with an existing one, and the console's own
  "Owner user id not found" message could never be reached by the cause it was
  written for.

  The classification now matches SQLite's extended result code, which D1
  embeds verbatim: `SQLITE_CONSTRAINT_FOREIGNKEY` maps to `NotFound`,
  `SQLITE_CONSTRAINT_UNIQUE` to `Conflict`, and anything else is left exactly
  as it was. One shared helper now serves all ten
  call sites that previously each carried their own copy of the test. CHECK and
  NOT NULL are deliberately **not** classified: no caller can produce either,
  because every `CHECK` column is written from a Rust enum and every `NOT NULL`
  column from a non-optional field, and branching on cases nothing can reach
  would put untestable code in the helper this release exists to fix.

- **`POST /api/v1/tenants` with an unknown `owner_user_id`** answered `409
  conflict`, indistinguishable from a slug collision. It now answers **`400`
  naming the field**. This route has no path parameter and mints its tenant row
  in the same call, so a missing reference can only be the owner.

- **`POST /api/v1/tenants/:tid/groups`** now resolves the tenant before
  creating the group, so an unknown `:tid` is an honest **`404`** and an unknown
  `organization_id` is a **`400` naming that field** — previously both were
  folded into one `409`.

- **Creating a user against a tenant that does not exist** reported
  "email already in use". The same cause, at a call site whose spelling of the
  test — `constraint failed` rather than `constraint` — had kept it out of the
  original survey.

### Changed

- Several admin-console forms begin showing a message they have always
  contained: a mistyped user id in the membership forms now reads
  **"User id not found"** rather than "Storage error", and the tenant-create
  form distinguishes a bad owner id from a taken slug. No new messages were
  written for this — the arms existed and could not fire.

## [0.89.0] - 2026-10-29

### A new tenant's owner can reach their own console — RFC 158

### Added

- **Creating a tenant now assigns its owner's home tenant.** `/admin/t/<slug>/*`
  — the 35-route tenant-admin console — is gated on `users.tenant_id` matching
  the tenant in the URL, and **nothing had ever set that column to anything but
  the default**. Every tenant except the default one was therefore unreachable
  by its own administrator, and by anyone else: there is no system-admin bypass
  on that surface, by ADR-003's design. A tenant's owner can now open it.

  The assignment happens **inside `create_tenant`**, not at its callers. It has
  two independent ones — the tenancy console's create form and
  `POST /api/v1/tenants` — and a third would otherwise be able to omit it and
  reintroduce exactly this defect.

- **`UserRepository::assign_tenant`**, a dedicated single-field port method
  with its own audit event (`user_tenant_assigned`), shaped like the existing
  `set_status`/`set_plan` methods rather than widening `update()`. `update()`'s
  statement deliberately omits `tenant_id` and silently ignores a changed one —
  now documented in place, because nothing complains when a caller tries.

- **`POST /api/v1/tenants`' `201` response gains an `owner_home` field.**
  **Additive**: every field the response already carried stays at the top
  level. It reports what this call did to the owner's home tenant —
  `assigned`, `kept_existing_home` or `failed` — which a caller has no other
  way to learn, there being no `GET /api/v1/users/:uid`.

### Changed

- **An owner who already administers another tenant keeps that home.** Moving
  it would revoke their access to the tenant they already administer — this
  release's own defect, inflicted on someone else. The tenant is still created
  and the owner membership still written; only the home column is left alone.
  A refusal (`409`) was considered and rejected: naming an already-homed user
  as owner succeeds today, and the membership row, which is what confers
  ownership, is unaffected.

- **The tenancy console reports the outcome to the operator**, instead of only
  to the audit table. When the owner's home was assigned, the form redirects as
  before. When it was kept or could not be written, a page says the tenant was
  created, why the owner's home is what it is, and that **the owner cannot open
  this tenant's console yet** — the one fact the operator could not previously
  learn from any surface.

### Fixed

- **A failed home assignment is never reported as a failed tenant creation.**
  The tenant and membership rows already exist by that point, so the outcome is
  returned as a value and recorded in the `tenant_created` audit detail, not
  propagated as an error. A config-load failure on that path cannot turn the
  created tenant into a `500` either.

## [0.88.1] - 2026-10-29

### Twenty-nine unreachable handlers removed, and a guard against more — RFC 157

### Removed

- **Twenty-nine request handlers that no route pointed at.** Each was a `.json`
  companion sitting beside a registered form handler, with no registration of
  its own, reachable by nothing, fetched by nothing, and — for all but a few —
  not even exercised by a test. They had accumulated because nothing failed
  when one was added: the router does not notice a handler it was never told
  about.

  Deleting them was a decision, not a default. Every client-rendered admin page
  was read first to establish whether any of them fetches the endpoint in
  question; two such pages do fetch a form companion, and both of those
  companions are registered and were left alone.

### Added

- **`unused_imports` and `unused_variables` are now build errors in the Worker
  crate**, as a crate-level attribute rather than a CI flag — so a local build
  enforces exactly what CI does, and the setting travels with the source rather
  than living in a workflow file. A deliberately narrow pair: the wider
  "deny all warnings" remains rejected, because it would make every future
  toolchain's new lint a release-blocking failure.

### Fixed

- The import leftovers the previous cycles' work had made redundant. These had
  been kept on purpose: while the pages they belonged to were still broken,
  the compiler's complaints about them were the clearest evidence of what was
  wrong. That evidence stopped being needed when the pages were fixed in
  v0.86.1 and v0.86.2, and the reason for keeping them had outlived the rule.

---

## [0.88.0] - 2026-10-29

### An invitation now grants what it offers — RFC 153

### Added

- **Accepting an invitation places you in the tenant that invited you, with
  the role it named.** Neither had ever happened. An invitation recorded an
  email, a tenant and a role, sent a link, and applied none of it: the
  invitation was marked accepted *before* any account existed, with a
  placeholder in place of a user id; the identifier meant to carry the
  invitation forward was read nowhere; the role was read exactly once, into an
  audit message; and registration always placed the new user in the default
  tenant. The flow now creates the user in the invitation's tenant, grants the
  membership with the invitation's role, records the real user id, and emits
  the audit event — **in that order**, so a failure at any step leaves the
  invitation usable instead of consuming it.
- **A user who abandons the flow is no longer locked out of their own
  invitation.** Previously the first submission consumed it, so returning later
  produced *"Already accepted. Please sign in"* to someone with no account, and
  only a fresh invitation from an administrator could recover it.
- **Invitations can be revoked.** `POST /admin/t/:slug/invitations/:id/revoke`,
  with the invitations page listing what is pending and a per-row control. The
  revoked state has been described by the schema since invitations shipped and
  nothing could produce it.
- An invited email that **already has an account** now gains the membership and
  role too, rather than signing in and silently receiving neither. Their own
  home tenant is left as it was.

### Fixed

- **The page that begins acceptance redirected to a URL that does not answer.**
  It sent the browser to a `GET` of an endpoint registered only for `POST`, so
  the invitee landed on a 404 — the flow was dead one step earlier than its
  own design described. It now renders the next step directly.
- Two administrative forms — add a member, grant a user-scoped role — returned
  403 for every tenant but one, because they require the target user to belong
  to the tenant and nothing could place a user in one. They succeed for an
  invited user now.
- Values interpolated into the invitation-acceptance page are escaped. The
  page's own policy already prevented scripts from running, so this was markup
  injection rather than a scripting hole, available only to someone who can
  already issue invitations.

---

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

