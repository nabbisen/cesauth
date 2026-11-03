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

**v0.87.x and earlier are in [`docs/changelog-archive/`](docs/changelog-archive/README.md)**,
split by minor range and never edited after creation. This file keeps the most
recent **five** minor versions (0.88–0.92) under the ~80 KB budget RFC 028 set,
enforced by `scripts/changelog-archive-split.sh`, which refuses to split a file
already under budget.

**RFC 152 half D (2026-11-03) ran the split.** At the 0.92.0 cut this file held
eight minors (0.85–0.92) at 79 KB of the 80 KB budget — under budget, so the
script's own guard would have refused to run, even though the five-minor rule
it does not check was already being broken. Archived 0.85, 0.86 and 0.87 to
[`CHANGELOG-0.85-to-0.87.md`](docs/changelog-archive/CHANGELOG-0.85-to-0.87.md),
by the rule rather than the guard. The script's own `sed` for the archive
index and its second `## Older releases` section are both still broken the
same way the 2026-10-31 split found them — fixed by hand again here, not
re-fixed in the script, which is its own change with its own verification.

---

## [0.92.0] - 2026-11-03

**Minor.** The OIDC clients screen now exists — the product's primary
integration action could not be reached from the console at all — and a
duplicate value, anywhere in this schema, stopped answering 500.

### The clients screen — RFC 141 cycle 2

- **`GET /admin/console/clients` answered 200 and rendered *"Page not found"***
  to a signed-in operator, because no CSR route existed for it. The screen now
  lists, creates, updates, rotates and deletes OIDC clients. The backend had
  been in place since v0.85.0 — except for one field: `clients.json` could not
  report `created_at`. That column has existed since migration 0001 and `create`
  always wrote it, but `OidcClient` carried no field and both `find` and `list`
  omitted it from their `SELECT`s. Threaded through, with one clock read at the
  route layer so `cesauth-core` stays clock-free and the written row matches the
  create response.
- **A minted secret is shown exactly once**, in a `role="alert"` panel with a
  deliberate dismissal rather than a toast, and the operator is warned *before*
  each action that would mint one.
- **Two CSP violations, both found by running the screen rather than reading
  it.** An inline `style=` was blocked live; removing it exposed an inline
  `onclick` that `script-src` would have blocked the first time anyone clicked
  it. Neither was visible to the host tests, to review, or to any of the
  thirteen gates.

### Four write routes gained the CSRF control their own documentation claimed

- `clients.rs`'s module doc said a cross-origin `application/json` POST was
  impossible because preflight blocks it. **The handlers never checked
  `Content-Type`, and `text/plain` is CORS-safelisted** — so the documented
  reasoning was false and the routes were unprotected. All four write routes now
  require an `X-CSRF-Token` header matched against the cookie, which is a
  complete defence for a JSON endpoint: a cross-site form POST cannot set a
  custom header.
- Verified live, as captured status lines: **no header 400, wrong header 400,
  `text/plain` with a JSON body and no header 400** — the exact request the old
  module doc called impossible — **matching header past the gate to 201.**
- `clients.json` now returns `{"clients": [...], "csrf_token": "..."}` in one
  response, their cells read `required (header token)`, and the route gate's
  **E6** checks the mechanism each cell names.

### A duplicate value answered 500 — RFC 141 cycle 2b, correcting RFC 160

- **`classify_insert_message` matched only `_UNIQUE` and `_FOREIGNKEY`.** SQLite
  reports a duplicate **primary key** as `SQLITE_CONSTRAINT_PRIMARYKEY`, in a
  message whose English still reads `UNIQUE constraint failed` — the classifier
  reads the code, so the prose was never the thing to trust. Of 61 `PRIMARY KEY`
  declarations in `migrations/`, exactly one is `INTEGER`, so **RFC 160's
  `Conflict` was unreachable wherever the primary key is the uniqueness
  constraint**, which here is nearly everywhere.
- **Ten shipped paths branched on that `Conflict`:** six written *"User is
  already a member of this tenant/organization/group"* messages across two
  consoles, all falling through to *"Storage error"*; three `api_v1` membership
  responses answering **500** where they document **409**; and
  `magic_link/verify.rs`'s invitation idempotency arm — whose failure left the
  invitation `pending` with **no acceptance record and no audit row,
  permanently**, because the membership still existed and the retry it logged
  about failed identically.
- **One `||` repaired all ten.** RFC 160 had already migrated the three
  `add_*_membership` sites to the shared classifier, so only the classifier was
  blind. A duplicate client id now answers **409** — *"a client with that id
  already exists"* — in place of 500 *"storage error"*.
- The classifier's doc census, which listed four constraint classes and
  justified omitting two, is **replaced by all twelve** of SQLite's constraint
  extended codes, each either classified or named with a reason and the command
  behind it. **A more precise matcher is not a more correct one until its
  vocabulary has been enumerated.**

### Why nothing caught it — RFC 171, accepted

- `adapter-test`'s in-memory double returned `Conflict` on a duplicate
  membership; the D1 adapter returned `Unavailable`. **Two implementations of
  one port disagreed about the one error the port documents, and the double was
  the one that was right** — so every host test over those paths was green
  against behaviour production did not have, and no test asserted any of the six
  messages. Nothing in the gate set asks whether a matched variant has a
  producer, or whether a test double agrees with its adapter. RFC 171 is
  accepted and scheduled; its parity half waits on RFC 170's credentialed CI
  job, which is the only environment that can run it.

### A retraction, and it is the architect's own measurement error

- The **~4.1 KB bundle "cross-environment offset"** recorded during cycle 2 —
  attributed to `cargo install worker-build` lacking `--locked` and written into
  RFC 133 half B as its first real cross-environment datum — **was neither
  cross-environment nor worker-build.** It was `gzip -9` against this project's
  established default level. Same bytes, gzip 1.15, measured both ways at this
  release commit: **896,672 B** at the default level, **892,451 B** at `-9`, a
  difference of **4,221 B**. `contributing.md` already carried the ruling that a
  gzip size is a property of the compressor too; the flag was printed in the
  cycle's own evidence log. **Retracted from RFC 133 half B.** `worker-build`
  installing without `--locked` remains a real reproducibility hazard — it is
  now recorded as hygiene with no datum behind it, which is what it always was.

### Release figures

- Worker bundle at this commit, after the version bump, via
  `./node_modules/.bin/wrangler deploy --dry-run --outdir bundled/`, gzip 1.15
  at its default level: **896,672 B** (885,972 wasm + 10,700 `shim.js`), raw
  2,451,977 + 61,887 bytes.
  `sha256 e0064ad099def12a2a1deb6b1c830e55093c3528b3c9180f661a5438d57f2127`
  (wasm) and
  `42db389be1ccb68dc47074cd4d52faf5d3c31e0b4bf448cb9ef0cb3a7b42b0f4` (shim).
  Against **896,301 B** — measured at `481dcab`, tag `0.91.2`, with the same
  command and the same default compression level, and recorded in RFC 133
  §16 — **+371 B**. The 0.91.2 entry itself records no bundle figure, so the
  provenance is named rather than implied.
- Host tests **1,677** passed / 0 failed / 4 ignored across 12 `test result:`
  lines, via the five-crate invocation in `contributing.md` §Running tests;
  `migration_chain` **35**; 194 routes; E4 `218 = 194 + 24 + 0`; E5
  `17 = 17 + 0 + 0`; E6 `94 = 80 claims + 14 declared + 0 unclassified`;
  Playwright **20**.

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

---

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

