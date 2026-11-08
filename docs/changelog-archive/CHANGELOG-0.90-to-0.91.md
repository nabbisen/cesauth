# cesauth — CHANGELOG (archive: v0.90–v0.91)

> This file is part of the changelog archive.
> Current releases are in the root [`CHANGELOG.md`](../../CHANGELOG.md).

## [0.91.2] - 2026-11-03

**Patch.** Three rules this project wrote down and never gated now have gates.
Nothing gains capability: every change is a check, a link target, an exemption
list, or a workflow line that lets a check run at all.

### The gates — RFC 164, RFC 168, RFC 165 §3

- **Cross-reference links in `rfcs/` are checked.** RFC 000 mandates a link
  sweep whenever an RFC moves between folders, and nothing enforced it. **167
  relative `.md` links are now verified on every push**, and a broken one fails
  the build. Twenty were broken when this cycle began — against the fourteen
  expected, because **six had rotted in since the audit six days earlier**,
  during the releases in which the sweep was being run by hand at every move.
  One of the six was a link this project's own architect broke and then swept
  past: a sweep that greps the old full path cannot see a sibling file linking
  with `./slug`, which is the case for a check rather than a habit.

- **Tags and CHANGELOG entries are reconciled, both directions.** **140 tags
  against 138 entries**, with "tagged, never documented" and "documented, never
  tagged" reported separately because they have different remedies. The
  historical mismatches are a named, reasoned, staleness-checked exemption of
  **ten** — not the six this project's own RFC claimed, nor the five
  `contributing.md` listed; both figures were wrong, both are corrected, and
  five of the ten are tags from before CHANGELOG record-keeping began.

- **Four exemption lists in `route-contracts-check.sh` are staleness-checked**
  (`E3_EXEMPT`, `GATE_42_EXEMPT`, `NONCE_EXEMPT`, `E4_EXEMPT`), each with its
  own coverage line. An entry that no longer matches anything is now a hard
  failure, because a stale exemption is a pre-authorised pass for whatever is
  written at that key next. **The question RFC 165 was written to ask is
  answered: none of the four is stale.**

### Fixed

- **The new checks could not have run in CI.** `drift-scan.yml` checked out
  with no `fetch-depth` or `fetch-tags`, and no workflow in this repository
  fetched tags — so the two checks that read `git tag` would have seen none.
  Verified in a `--depth 1 --no-tags` clone: the gate **exits 2** with
  *"compared ZERO tags"* rather than passing vacuously, which is the designed
  failure mode and the reason the defect was caught before the release rather
  than after. `fetch-depth: 0` added, with the reason recorded in the workflow.

- **The reconciliation check could not survive its own release.** A cut writes
  the CHANGELOG entry in the very commit the tag will point at, so at the
  release commit the entry exists and the tag cannot — and the check read that
  as *"documented, never tagged"* and failed. **Every release commit would have
  failed it**, making it impossible to cut with a green gate. Found while
  cutting this release, which is the first cut the check has ever seen. An entry
  with no tag is now permitted for **exactly one version — the workspace version
  in `Cargo.toml`** — which is stricter than a blanket "newest entry" allowance
  would be: an entry for any other untagged version still fails, and so does one
  written for a version nobody bumped to. If that version cannot be read, the
  check exits rather than quietly stopping to exempt.

- **Twenty broken links**: six real fixes (three ellipsis-inside-link-syntax
  targets whose correct form sat one line above them; a repo-root-relative link
  inside a subdirectory — RFC 028's own defect class in RFC 028's own file; a
  bare filename the same file writes correctly 185 lines earlier; and one
  folder-move rot from this project's own 0.89.5 cut), and fourteen
  illustrative examples in the two documents that define the cross-reference
  rule, de-linked rather than exempted so that a file-level exemption cannot
  later excuse real rot in them.

### Documentation

- **A release entry records its level in its first line** (ruling): the first
  non-blank line after a `## [X.Y.Z]` heading begins `**Patch`, `**Minor` or
  `**Major`, prose allowed after the word. This exists so RFC 168's level
  backstop can be built at all — of the twelve entries before this one, only
  three recorded the level in any parseable form. Scoped to `0.90.0` and above;
  older entries are named out of scope rather than back-filled, because
  back-filling a level onto a past cut is guessing at what it intended.

- **Any baseline figure in a handoff names the command that produced it**
  (ruling), generalising the existing rule about bundle figures after a cited
  test count without its invocation cost a cycle an afternoon.

### Known and unfixed

- **RFC 168's level backstop** — a patch must add no route, migration or MSRV
  change versus the previous tag. Now a one-cycle build with no design question
  left, given the ruling above.
- **RFC 164 §3b's byte budgets** — 80 KB for `CHANGELOG.md`, 40 KB for
  `ROADMAP.md`. Not built, and it could not have been: `CHANGELOG.md` is 67 KB,
  but **`ROADMAP.md` is 137 KB**, so the gate would be red on arrival until
  RFC 028's ROADMAP half lands. That sequencing is now recorded.
- Unchanged from 0.91.1: **29 mutating rows document a CSRF control that is not
  the one protecting them** (RFC 152 half D); **no gate observes the admin
  cookie's attributes on a live response** and **RFC 147's deletion sweep has no
  `exercised` gate**, both blocked on the same missing capability (RFC 170,
  accepted); and **nothing rate-limits unauthenticated audit appends**.

**No RFC closes with this release.** RFC 164 keeps §3b, RFC 168 keeps its
backstop, RFC 165 keeps §4 — each a named remainder rather than a silent gap,
which is the distinction RFC 151 exists to enforce.

---

## [0.91.1] - 2026-11-01

### The book now contains its own pages — RFC 169

**Patch.** Nothing gains capability. Pages that were always part of this book
become reachable in it, two links start resolving, and a check starts failing
when either stops being true.

`mdbook` builds exactly what `SUMMARY.md` lists. **Eleven of the eighty `.md`
files under `docs/src` were not listed**, so the published book did not contain
them — and `mdbook build` was clean about it, because there is no symmetric
option to `create-missing = false` for a file with no entry.

### Fixed

- **Nine pages are in the book.** Among them: `expert/route-contracts.md`, the
  route-contract table every route gate reads; `expert/contributing.md`, where
  every ruling this project makes is written down; `deployment/email-delivery.md`,
  a deployment chapter; and **ADR-016, ADR-017 and ADR-018 — the three most
  recent decision records**, so a reader of the ADR index no longer concludes
  ADR-015 is the latest.

- **Two links in the published book were already 404s.**
  `expert/view-rendering-policy.md` links to `./route-contracts.md` twice — once
  under the words *"Enforced by"* — and that page was not in the book. Adding
  the target to `SUMMARY.md` was the entire fix; the page itself was not edited.

- **`expert/data-model.md` pointed at a directory that does not exist.** Its
  ADR-010 link read `adrs/010-audit-chain.md` — plural `adrs`, and a filename
  that never existed. Found by the new link check on its first run, unrelated to
  the eleven, corrected to `adr/010-audit-log-hash-chain.md`.

### Added

- **Two checks in `scripts/drift-scan.sh`**, which already walks `docs/`, so no
  workflow was added and the release-gate manifest stays at **14**:
  - **coverage** — every `docs/src/**/*.md` is reachable from `SUMMARY.md` or on
    a named, reasoned, stale-checked declared-out list;
  - **link integrity** — no page the book builds links to a `.md` the book does
    not build.

  Both report their own census and both fail loudly rather than quietly: a
  stale declared entry is an error, a zero scan count is an error, and the
  link check **asserts its own arithmetic closes** — it counts only the links it
  validates, and names each class it skips (absolute/`http`, and targets
  resolving outside `docs/src`) rather than folding them into a denominator that
  would overstate what was checked.

- **Two pages are declared out of the book, with reasons**:
  `expert/rfc-110-baseline.md` (an audit of the v0.71.0 codebase, taken for
  RFC 110) and `expert/nodejs-compat-investigation.md` (RFC 025 Step 2's
  investigation). Both are records of a moment rather than pages a reader
  navigates to. The test that separates them from the nine: those two are
  artifacts of doing gated work, addressed to nobody, while a page that names an
  ongoing reader role belongs in the book.

### Known and unfixed

Unchanged from 0.91.0 and restated because none of it moved: **29 mutating
rows document a CSRF control that is not the one protecting them** (RFC 152
half D); **no automated gate observes the admin cookie's attributes on a live
response**, and **RFC 147's deletion sweep has no `exercised` gate** — both
blocked on the same missing capability, a CI job with migrated D1 state and a
seeded credential (**RFC 170**, accepted); and **nothing rate-limits
unauthenticated audit appends**.

---

## [0.91.0] - 2026-10-31

### The operator console's turn — RFC 152 half C

**Minor, for two reasons.** Three `POST` routes begin requiring a CSRF token no
caller sent before, and five begin **rejecting a cookie-derived credential**
outright: a client that authenticated to them with the
`__Host-cesauth_admin` cookie alone now gets **401**, and only
`Authorization: Bearer` works.

Half B gave the tenant-admin and tenancy-console surfaces the control their
documentation claimed. **Half C asked the question half B never did — whether
any other surface made the same claim** — and the operator console did, on
**seven** rows. (First reported as nine; two of those, `config/log_level/`'s
preview and apply pair, carry an HMAC'd preview token with the submitted CSRF
value bound into it, through a mechanism the scan behind that figure did not
know to look for.)

### Added

- **Three browser forms get the double-submit token**, stage 1's pattern:
  `POST /admin/console/tokens` — which **mints an admin token**, the credential
  every other admin route accepts — `.../config/:bucket/edit`, and their error
  re-renders. `tokens.rs::create` re-renders on **four** validation paths, not
  the three the handoff enumerated; the fourth is a token-hash collision, and it
  mints a fresh token like the others.

- **Five JSON endpoints reject a cookie entirely.** A new header-only resolver
  sits beside the existing pair, sharing one `resolve_bearer` body rather than a
  third copy of the resolve-and-audit logic: same store lookup, same
  `admin_login_failed` audit, **no cookie fallback**. Applied to
  `.../tokens/:id/disable`, `.../config/:bucket/{preview,apply}`,
  `.../thresholds/:name` and `.../safety/:bucket/verify`. A `curl` caller has no
  cookie jar, so a double-submit token would have been ceremony for a browser
  that never calls them; this makes CSRF impossible by construction instead of
  checked.

- **E6 now checks the control each cell names, repo-wide**, in both directions:
  `required` ⇒ a verify call, `required (<mechanism>)` ⇒ that named mechanism,
  `N/A (bearer)` ⇒ the header-only resolver. It also **has a census**: every
  mutating row is checked or **declared uncheckable with a reason**, an
  unrecognised cell is a hard failure rather than a silent skip, declared values
  and exemptions both carry the stale-entry rule, and two arithmetics are
  asserted — `94 scanned = 76 claims + 18 declared + 0 unclassified`, and
  `76 claims = 58 resolved + 0 unresolved + 18 exempted`. The workflow count
  stays at **14**.

### Fixed

- **`POST /admin/console/tokens` minted admin tokens with no CSRF check** while
  its row said `required` — and its own `.json` endpoint was already serving a
  token to that surface that nothing checked coming back.

- **`safety.rs::verify` was reclassified mid-cycle**, against the dispatch. It
  was listed as a browser form on the strength of its content negotiation; the
  form it would redirect to **exists in no live path** — its template is
  referenced only by its own tests, and `GET /admin/console/safety` serves a
  placeholder that says the feature is not built (RFC 161). Bearer-header-only
  instead, with the reasoning recorded at the function rather than only in a
  report.

- **`POST /userinfo`'s CSRF cell read `N/A (Bearer)`** with a capital letter, so
  E6's exact match skipped it: a row making a claim, unchecked, because of one
  character. Normalised, and the claim verified true — that endpoint reads its
  credential through its own `extract_bearer` with no cookie path at all.

- **`POST /accept-invite`'s cell was a bare `N/A`** with no reason recorded.
  It now says why: no ambient credential and no state change, so a forged
  request has nothing to ride on.

### Documentation

- `route-contracts.md`: the seven cells corrected, two of them to
  `required (preview-token binding)` so they name the mechanism they actually
  have, five to `N/A (bearer)`.

### Known and unfixed

**Twenty-nine mutating rows document a CSRF control that is not the one
protecting them.** Both sets are exempted by name with stale-entry checks, so
neither can be forgotten quietly, and both are the subject of **RFC 152
half D**, which opens with a measurement stage rather than code:

- **18 rows claim `N/A (bearer)` and accept a cookie** — `POST /admin/users`,
  `DELETE /admin/sessions/:id`, and all 16 `/api/v1/*` mutating routes, which
  funnel through one resolver that reads the header **or** the cookie.
- **11 rows claim `N/A (JSON)`**, on the reasoning that a JSON `Content-Type`
  forces a CORS preflight. **It does not**: the Fetch `Request.json()` these
  handlers call parses the body regardless of `Content-Type`, no handler checks
  the header, and `text/plain` is CORS-safelisted. Verified live — the same
  `{}` body under `text/plain` and under `application/json` produced the same
  response. These include
  `/admin/console/clients/{create,update,rotate_secret,delete}`.

**Neither set is exploitable today, for the same single reason as the original
finding**: the admin cookie is `SameSite=Strict`, so a forged cross-site
request arrives with no credential and dies at the auth gate. That one cookie
attribute is doing more work than any document says, which is what this whole
RFC has been about.

Also carried forward: **no automated gate observes the admin cookie's
attributes on a live response** (`runtime-smoke-check.sh` could only assert them
while the login handler set the cookie from an unvalidated token); **nothing
rate-limits unauthenticated audit appends**; **RFC 147's deletion sweep has no
`exercised` gate** — it is `observed`, driven once against `wrangler dev`, and
the durable fix needs the same missing capability as the cookie witness, a CI
job with D1 state; and **eleven of the book's eighty pages remain absent from
`SUMMARY.md`** (RFC 169, accepted, next).

---

## [0.90.0] - 2026-10-31

### The admin surfaces now have the CSRF control their documentation claimed — RFC 152 half B

**Minor, because 34 endpoints begin requiring something no caller sent before.**
A `POST` to any of them that omits the token, or sends one that does not match
the cookie, now gets **400 Bad Request** where it previously succeeded. Nothing
in this release was broken; a second layer was added on purpose.

RFC 152 (2026-10-27) found that all 35 — now **36** — `POST` routes under
`/admin/t/*` and `/admin/tenancy/*` documented their CSRF column as `required`
while **34 of them never called `csrf::verify`**. Half A (v0.86.3) made the
document true by writing `N/A (SameSite=Strict)` where nothing checked a token,
and pinned the cookie attribute that was in fact carrying the whole defence.
This release adds the control and makes the cells say `required` and mean it.

### Added

- **34 admin `POST` routes verify a double-submit CSRF token**, across 23
  handler files. Two of those files sit **outside** both surface directories —
  `routes/deletions.rs` (already verifying, the RFC 147 pattern the rest now
  copy) and `routes/invitations.rs` — so the population was derived by
  resolving each documented row through its `.post_async` registration rather
  than by walking a directory tree.

- **Every server-rendered admin form carries a token, and every re-render mints
  a fresh one.** The 21 form views gained a `csrf` parameter and the handlers a
  shared `mint_csrf` / `attach_csrf_cookie` / `verify_csrf` boundary. The
  re-render case is the one an operator would have met: a form rejected for a
  validation error and re-displayed with a spent token would fail the corrected
  resubmission for a reason the page never explains. Verified end to end —
  validation error, fresh token, corrected resubmission accepted.

- **`E6`, in `scripts/route-contracts-check.sh`.** Every `POST` row whose CSRF
  cell reads `required` on these surfaces must resolve, through its exact
  registration in `lib.rs`, to a handler that actually calls the check. It
  reports its own coverage, fails on an unresolved row, asserts a non-zero
  count so a matcher that stops matching fails loudly, and prints how many
  distinct CSRF field names it finds — which is how the `csrf` / `csrf_token`
  split stays visible instead of becoming folklore. The workflow count stays at
  **14**; E6 runs inside the existing route-contracts job.

- **`POST /admin/login`.** See below.

### Fixed

- **`GET /admin/login?token=…` set a session cookie for a token it had not
  validated** (RFC 152 §6). It screened the length and set
  `__Host-cesauth_admin`; validation happened on the *next* `/admin/*` fetch.
  Two consequences followed: a crafted link with a garbage token locked a
  working operator out of the console, and — worse — a link carrying an
  **attacker's valid** token made the victim operate the console as the
  attacker's principal, so every action they took was attributed to the attacker
  in the tamper-evident audit chain. **Correct entries against the wrong
  principal** is the failure a hash-linked log cannot help with.

  `GET` now validates the token against the admin-token store and **sets
  nothing**. It renders a confirmation page naming the identity and role the
  operator is about to assume — *"you are about to sign in as X (role: Y);
  continue only if you opened this link yourself"* — carrying a freshly minted
  CSRF token. The new **`POST /admin/login`** verifies that token, re-validates
  the bearer, and only then sets the cookie and redirects.

  **This changes the operator login flow**: a bookmarked or scripted `GET` to
  that URL no longer signs anyone in by itself. One deliberate click does.

  Why the confirmation step rather than validation alone: validating removes the
  lockout consequence and **does nothing** about the first, because the
  attacker's token is valid — that is the premise of the attack. Only requiring
  the operator's own submission closes it, and `SameSite=Strict` then means no
  attacker page can make that submission. (RFC 152 §6.4 records the correction;
  §6.3 had recommended validation alone.)

- **An unknown or disabled token at `/admin/login` now writes
  `admin_login_failed`**, as every other `/admin/*` path already did. The old
  length pre-screen silently skipped the audit write for exactly the malformed
  input most worth recording.

- **Two now-false security claims in `admin_login.rs`.** Half A extracted
  `admin_cookie_header` so that one place would state the real control; after
  half B stage 1 that place still said `SameSite=Strict` was *"the entire
  defense for 33 of 35"*. It is defence in depth on top of a check 34 of 36
  routes now run. The cookie test's assertions are unchanged — the attribute is
  still worth failing loudly on — only its account of why.

### Documentation

- **`route-contracts.md`**: 32 cells flipped back to `required`, rows added for
  `POST /admin/login` and the changed `GET`, and a note recording that
  `POST /admin/tenancy/tenants/:id/{suspend,restore}` have **no caller** — no
  view posts to either, neither reads a form body, and both are superseded by
  `tenant_set_status.rs`'s preview/confirm flow. Their `N/A (SameSite=Strict)`
  cells are true, not unexamined.

- **Four rulings in `contributing.md`**: which handler serves a route is
  answered by its registration, not by the directory a file sits in; **which
  form posts to a route is answered by the form's `action`**, not by the file's
  name; a bundle figure names the command that produced it, and **sha256 plus
  raw bytes are the portable identity — gzip size is a property of the
  compressor too**; and a live probe's evidence is its captured status lines,
  not prose about them.

### Known and unfixed

- **Nine `POST` rows on the operator console claim CSRF `required` and no
  handler among them calls any CSRF check** —
  `/admin/console/tokens` (which **mints an admin token**),
  `…/tokens/:id/disable`, `…/config/:bucket/{preview,apply,edit}`,
  `…/config/log_level/{preview,apply}`, `…/thresholds/:name` and
  `…/safety/:bucket/verify`. RFC 152 scoped itself to two surfaces and never
  asked whether a third made the same claim; E6's path filter inherited that
  scope and cannot see these. **Not a live vulnerability**, for the same single
  reason the original finding was not: the admin cookie is `SameSite=Strict`, so
  a forged cross-site `POST` arrives with no credential. Found while reviewing
  this release, proposed as **RFC 152 half C**, which opens by measuring which
  of the nine have a reachable caller at all.

  **Corrected 2026-10-31, after that measurement: seven, not nine.**
  `…/config/log_level/{preview,apply}` do carry a control — an HMAC'd preview
  token with the submitted CSRF value bound into it, failing closed on
  mismatch — through a mechanism the scan behind the figure above did not know
  to look for. The entry above is left as written rather than rewritten,
  because a shipped entry is a record; this is the correction, in the place a
  reader of that claim will meet it.

- **No automated gate observes the admin cookie's attributes on a live
  response** any more. `runtime-smoke-check.sh` could assert them only because
  the old handler set the cookie from an unvalidated placeholder token; that is
  now impossible, and the gate runs with no secrets and no migrations by design.
  The host test still pins the exact string the builder produces. Restoring a
  live witness needs a CI job with D1 state, which no job has today.

- **Nothing rate-limits unauthenticated audit appends.** Any unauthenticated
  `/admin/*` request writes an `admin_login_failed` row into the hash-linked
  chain; `/admin/login` is now one more such path rather than a new property.

- **Eleven of the book's eighty pages remain absent from `SUMMARY.md`**, and
  `expert/view-rendering-policy.md` still links twice to one of them. Carried
  from 0.89.5; awaiting a decision on its own RFC.
