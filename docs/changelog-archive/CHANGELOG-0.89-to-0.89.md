# cesauth — CHANGELOG (archive: v0.89–v0.89)

> This file is part of the changelog archive.
> Current releases are in the root [`CHANGELOG.md`](../../CHANGELOG.md).

## [0.89.5] - 2026-10-31

### A reader who wants to deploy now has one ordered path — RFC 167 slice 2, RFC 028

No behaviour changes. No Rust, no routes, no schema. This release adds the
sequence that fifteen good deployment chapters did not have between them, and
enforces a volume policy that had been written and unenforced for forty minor
versions.

### Added

- **`docs/src/deployment/first-production-deploy.md` — one ordered pass from an
  empty Cloudflare account to a tenant completing an OIDC flow.** Placed
  **first** under `# Deployment`, before the pre-flight checklist, because it is
  the page that tells a reader in which order to read the other fifteen. Eleven
  sections: §0 for the one prerequisite a walkthrough cannot discover for you
  (the **Workers Paid plan** — the daily cron maintenance passes alone exceed
  Free-plan subrequest and D1-query limits), the ten `production.md` steps in
  the order they actually run, and *"Prove it works"*, which hands off to
  `beginner/first-oidc-flow.md`. Each step is a paragraph of what and why, then
  a link to the chapter that owns the commands — a second copy of a command is a
  second thing that can drift from the first.

- **The page was rehearsed, not just written.** The whole sequence was walked
  locally with the local analogue substituted for each of the six genuinely
  remote-only commands, through to a real OIDC flow: a client registered via the
  documented `POST /admin/console/clients`, a user created, a Magic Link
  requested and verified, an authorization code exchanged over HTTP Basic, and a
  refresh token rotated. Evidence terms are split per step rather than hedged
  across the page — the sequence is **exercised**; the six remote-only commands
  are **reviewed**, named individually, each with what would exercise it.

### Fixed

- **The deploy spine omitted the step without which every token fails
  verification.** `README.md`'s *"Deploy it"* list had no line for
  `production.md` Step 3, seeding the public half of the JWT signing key into
  `jwt_signing_keys` — and it was not among the two steps the list names as
  deliberately left off. Without it `/jwks.json` serves `{"keys":[]}` and every
  token cesauth issues fails verification everywhere. Found by the rehearsal
  reproducing the symptom against an emptied local D1, not by reading the list;
  three reviews had read past it. The list is now ten lines.

- **`first-oidc-flow.md` cannot be followed as written against a production
  deployment**, which nothing had said. Its Step 4b uses
  `/__dev/stage-auth-code`, which the walkthrough's own step 5 gates off on
  purpose, and a `confidential` client authenticates at `/token` by HTTP Basic
  rather than the tutorial's bare `client_id` form field. Both adjustments are
  now stated in the new page's closing section, so the chapter it hands off to
  does not strand the reader it was handed.

- **`README.md` used the same numerals for two different things.** The closing
  paragraph's *"Step 7"* and *"Step 8"* are `production.md`'s numbering, two
  lines below a list whose **own** items 7 and 8 are deploy and client
  registration. Both now say *"the chapter's Step N"*, and the paragraph closes
  by stating which numbering is meant.

- **`contributing.md` told contributors to expect the wrong test count, and had
  since the 0.83.0 era.** §Running tests promised **1,403 passed** with a
  per-crate breakdown in which every figure was stale — core 789, frontend 276,
  backend 200, adapter-test 133, adapter-cloudflare 1, `migration_chain` 31,
  against an actual **1,636** (924 / 324 / 229 / 151 / 8) and **35**. A
  contributor running the gate could not tell growth from defect. Corrected, and
  **de-claimed**: the figures now cite the commit they were measured at, say
  they are a snapshot no gate protects, and name the actual signal — a *lower*
  count, a non-zero `failed`, or a line count other than 12.

- **RFC 028's volume policy, enforced for the first time since it was written.**
  The policy keeps the five most recent minor versions in `CHANGELOG.md` under
  an 80 KB budget; the file had reached **318 KB** with **40 minor versions
  inline**, and the archive stopped at v0.49. RFC 028 is not wrong — it
  specified its own CI budget check in full, as runnable bash, and that check was
  never built, so the rule rotted for forty minor versions while the RFC's own
  Status said *Implemented*. Four splits later (`0.50-0.59`, `0.60-0.69`,
  `0.70-0.79`, `0.80-0.84`) the root file is **42 KB**, and the set of
  `## [version]` entries across root plus archives is identical to the 83 before
  the split — no history lost, none duplicated.

- **Three defects in `changelog-archive-split.sh`, found by running it**, all
  repaired **in the output and not yet in the tool** (recorded in RFC 028
  §Outstanding — do not run it blind): an archive-README `sed` using `|` as both
  delimiter and replacement text, invalid and swallowed by `|| true`; a
  duplicate `## Older releases` section appended on every run; and relocated
  content keeping repo-root-relative links, which broke five links the pre-split
  check had not looked for — it measured links *into* the CHANGELOG, not links
  *out of* the content being moved. **The original 2026 migration had the
  identical defect**, and four links in `CHANGELOG-0.1-to-0.30.md` had been
  broken ever since. All nine now resolve.

- **`drift-scan.sh` went red on the moved content**: six patterns matched
  historical prose in the new archive files, which are a record rather than a
  live claim. `docs/changelog-archive/` is now excluded in all six, the same way
  the root CHANGELOG already was.

### Documentation

- **Four release rulings recorded in `contributing.md` §Cutting a release**, each
  written where the next cut will read it: an **MSRV bump is a minor**; **a
  dispatch handoff states its level and the trigger it hits**, with *"no trigger,
  therefore a patch"* an argument to be made rather than a default; **the Worker
  bundle is measured at the release commit, after the version bump**, because the
  workspace version reaches the compiled wasm through symbol mangling (0.89.4's
  recorded 882,900 B describes a 0.89.3 tree; the tagged artifact is 882,830 B);
  and **a handoff's baseline figures cite the commit they were measured at**,
  which is how that offset was found rather than argued. The bundle ruling was
  established by experiment — reverting the version and rebuilding reproduced the
  earlier figure with both sha256 digests byte-exact, which also re-confirms
  RFC 133 half A's reproducibility guarantee.

- **A fifth condition on the `cesauth-core` → `cesauth` rename**: publishing
  hands the compatibility rubric to Cargo, where `^0.x` makes each `0.x` its own
  compatibility unit, so the rename must happen before the first publish or not
  at all.

- **The versioning policy in `ROADMAP.md`** now states that a catch-all test
  added for a case callers must handle is a **caller obligation, not an
  observable difference** — the distinction the level table turns on.

- **RFC 168 accepted** — the release rules are written and unenforced: nothing
  reads `CHANGELOG.md`, nothing compares tags to entries, and nothing compares a
  release's level to what it changed. Forward-only at the owner's direction.
  Scheduled immediately after RFC 164, which shares the script.

### Known and unfixed

- **Eleven of the book's eighty pages are absent from `docs/src/SUMMARY.md`**, so
  `mdbook` never builds them and `mdbook build` is clean about it — among them
  `expert/contributing.md`, `expert/route-contracts.md`,
  `deployment/email-delivery.md` and ADRs 016–018. One is already a dead link in
  the published book: `expert/view-rendering-policy.md` points twice at
  `route-contracts.md`, the page it names as the enforcing document. Found while
  reviewing this release; needs its own RFC and the owner's acceptance.

- **The ROADMAP half of RFC 028 is outstanding** — 134 KB against its own 40 KB
  budget, 61 shipped rows inline. There is no script for it and the convention is
  *summary + link* rather than a verbatim move, so each row must be condensed,
  which is judgement rather than a shell loop. Scoped separately rather than
  improvised at 134 KB.

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

