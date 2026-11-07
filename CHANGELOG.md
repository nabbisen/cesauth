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

**v0.89.x and earlier are in [`docs/changelog-archive/`](docs/changelog-archive/README.md)**,
split by minor range and never edited after creation. This file holds
**0.90–0.92 at 63 KB** of the ~80 KB budget RFC 028 set.

**Correction, 2026-11-07, at the 0.92.6 cut: there was never a conflict between
two rules, and the previous note here was wrong twice.** It said RFC 028's
five-minor rule and its ~80 KB rule were "in open conflict" and that "the byte
rule has a script behind it … so the enforced rule won." Measuring both claims
found neither holds:

- **The five was derived from the budget, not asserted beside it.** RFC 028
  Requirement 1 reads *"the most recent ~5 minor versions (a number large enough
  to cover most 'what shipped recently' queries, **small enough to keep the file
  under ~80 KB**)"* — the byte budget is given as the *reason for* the five. One
  rule, one derived estimate. The estimate went stale because its input moved:
  **releases per minor rose from 1.0–1.17 (v0.31–v0.49) to 2.90 (v0.70–v0.79) to
  4.00 (v0.89–v0.92)**. "Five minors" meant ~5 entries when written and ~20 now.
- **Entry size was the wrong variable, and it has been falling, not rising.**
  Mean bytes per entry by archive file: 9,316 (0.31–0.40) → 3,302 (0.70–0.79) →
  2,644 (0.85–0.87) → 2,150 (0.88). The previous note blamed entry length and
  reported trying shorter entries; the cadence was doing the work.
- **Neither rule is enforced.** `git grep` for the budget across `scripts/`,
  `.github/workflows/` and `Makefile` finds it in exactly one place:
  `scripts/changelog-archive-split.sh`'s own guard, which only runs when a human
  runs the script. **RFC 028 Step 5 specified a CI budget check as runnable bash
  and it was never built** — the RFC's own header says so. The byte rule did not
  win by being enforced; it won by being noticed at a cut.

**This cut archives 0.89** (six entries, 25,206 B) to
[`CHANGELOG-0.89-to-0.89.md`](docs/changelog-archive/CHANGELOG-0.89-to-0.89.md),
taking the root from 81,024 B to 55,818 B — reconciled: the archive file is
25,370 B including its 164-byte header. The split goes **down to a floor**
rather than just under the ceiling, so it buys several cuts of headroom instead
of firing again next release. Direction for the rule itself is in RFC 028's
2026-11-07 note: delete the derived figure, build the gate Step 5 already
specified.

---

## [0.92.6] - 2026-11-07

**Patch.** Colour contrast, keyboard ordering, two new gates, and a corrected
record. **No behaviour changed for any API caller**; every code change is a
colour value, a markup order, a heading string, or a check.

### Accessibility — RFC 176 §6.1 / §6.1b, RFC 177 §4.1 / §4.2

Answering the owner's question of whether the UI is kind enough to older users.

- **Nine semantic colour pairs moved to WCAG AAA (7.0:1).** `--success`
  `#125d32`, `--warning` `#7a4a00`, `--danger` `#9b2020`, `--info` `#14548f`,
  with the dark-theme backgrounds moved to match. Five of the nine previously
  failed **AA** for normal text — `--success` at 3.11 and `--warning` at 3.76
  in light, `--danger` 3.62 and `--info` 4.07 in dark, `--scope-tenant` 3.49
  on white.
- **The fix had to land twice, and the first pass missed the half the question
  was about.** `crates/frontend/src/templates/chrome.rs` carries its own copy
  of the four semantic tokens, so §6.1 fixed only the operator console while
  `/`, `/login` and `/me/security` kept the failing values. §6.1b brought
  `chrome.rs` to parity and widened the gate to both files. The exclusion came
  from the §6.1 handoff's own wording (*"do not change any template's inline
  CSS"*), which named out the file that mattered.
- **The existing axe `wcag2aa` job could not have caught any of this**: it
  loads `/` and `/login` only, where these tokens never render.
- **`/me/security` no longer leads with its most destructive action.**
  *"Request account deletion"* was the first heading read and the first control
  reached by keyboard, ahead of two-factor and sessions. Order is now
  `Enable two-factor` · `Manage sessions` · `Request account deletion` ·
  `Sign out`, deletion last under its own heading. Markup and order only.
- **The sessions page gained a section landmark**, and its heading now reads
  `Signed-in devices` rather than `Sessions` — an `h2` that merely re-worded
  the `h1` above it gave a screen-reader user a landmark with no information.

### Added — the colour-contrast gate

- **Colour contrast, in `scripts/drift-scan.sh`.** Computes WCAG relative
  luminance from the declared hex pairs in both token files and asserts 7.0:1,
  in POSIX `awk` with `index()`-based hex parsing — no `strtonum`, no
  `python3`, so it runs anywhere the rest of the script does. Census:
  **`22 = 19 checked against 7.0:1 (AAA) + 3 declared out + 0 unclassified`**.
  No browser needed; it closes the class rather than one instance.

### Added — the end-user app ships no stylesheet (RFC 178)

Checking RFC 176's colour fix found something larger: **the Leptos CSR app at
`/` and `/login` loads zero stylesheets, zero `<style>` tags and zero author
CSS rules.** The body renders at browser defaults (Times New Roman, 16px), and
any `sr-only`-class element — having no rule to hide it — is visible to every
user rather than to screen readers alone. `design_tokens.rs` styles nothing on
these routes; `chrome.rs` styles the server-rendered templates only.

Two gates now hold this, **both reporting rather than blocking**:

- `e2e/specs/stylesheet-presence.spec.ts` asserts at least one author CSS rule
  per public route. **Three outcomes, not a skip**: a route named in
  `KNOWN_NO_STYLESHEET` with zero rules passes *and prints its exemption and
  the owning RFC on every run*; a named route that gains a rule **fails as
  stale** and the entry must be deleted, after which it enforces permanently;
  an unnamed route has no exemption at all. Both public routes are named
  today, dated, citing RFC 135 §4 and RFC 131 R3.
- `.github/workflows/trunk-release-build.yml`'s stylesheet-presence step
  reports and exits 0, with the `exit 1` left in place as a comment naming the
  day to restore it.

**The gap itself is not new and not this release's to close.** It is recorded
in `rfcs/done/135-wasm-under-csp.md` §4 and RFC 131 — the presentation wiring
belongs to **RFC 131 R3**, an unbuilt slice of an accepted programme, not a
short cycle. Landing the gates bare would have made every cut red forever;
removing them would return the project to documented-and-ungated, which is the
condition that let the gap persist unnoticed for months.

### Changed — the CHANGELOG archive rule, and a correction to its record

**0.89 archived** (six entries, 25,206 B) to
[`CHANGELOG-0.89-to-0.89.md`](docs/changelog-archive/CHANGELOG-0.89-to-0.89.md),
taking this file from 81,024 B to **55,818 B**. The split now runs **down to a
floor** instead of just under the ceiling, so it buys several cuts of headroom
rather than firing every release.

**The 0.92.5 record of RFC 028's "two rules in open conflict" was wrong twice,
and is corrected under *Older releases* above.** The five-minor figure is
*derived from* the ~80 KB budget inside Requirement 1's own parenthesis, not a
second rule beside it; it went stale because **releases per minor rose from
1.0–1.17 (v0.31–v0.49) to 2.90 (v0.70–v0.79) to 4.00 (v0.89–v0.92)**. Entry
size, which that note blamed and claimed to have tried shortening, has been
*falling* throughout: **9,316 → 3,302 → 2,644 → 2,150 B per entry**. And
**neither rule is enforced** — the budget appears nowhere in `scripts/`,
`.github/workflows/` or `Makefile` except the split script's own guard, which
a human must run. RFC 028 Step 5 specified a CI budget check as runnable bash
and it was never built.

### Bundle

Measured after the version bump, `./node_modules/.bin/wrangler deploy --dry-run
--outdir bundled/`, **gzip at its default level** (not `-9`):

| file | raw B | gzip B | sha256 (first 16) |
|---|---|---|---|
| `…-index_bg.wasm` | 2,433,374 | 878,272 | `3c3fef99558f356a` |
| `shim.js` | 61,887 | 10,700 | `a530d68e8c8e9aa6` |
| **Worker total** | | **888,972** | |

**888,972 B, down 22 B from 0.92.5's 888,994.** `chrome.rs`'s colour values are
the only Worker-path source this release changed; `pages/sessions.rs` and
`pages/security_center.rs` are CSR-only and do not enter the Worker.

**The frontend static asset was not measured here.** `trunk` is not installed on
the machine this cut was made from, so `make build-frontend` cannot run locally;
the 317,718 B gzip figure for `cesauth-frontend_bg.wasm` comes from the dev
team's report, not from an independent measurement, and CI's `Trunk release
build` job is what actually exercises it. **No gate budgets that file** —
recorded in `ROADMAP.md`.

### Known gaps

- **No stylesheet exists for the end-user app** (above). Owned by RFC 131 R3,
  exempted by name in both gates, reported on every run.
- **The ~80 KB CHANGELOG budget still has no gate**, and RFC 028 still carries
  the stale five-minor figure. Both are directed in RFC 028's 2026-11-07 note:
  delete the derived figure, build the check Step 5 already specifies.
- **Every focusable element on `/`, `/login` and `/me/security` is under
  44 px**, the smallest 17 px — measured on the rendered page. The control-
  height floor and `rem` typography tokens are RFC 176 §6.2/§6.3, a **minor**,
  not dispatched.
- **`/login`'s first control is still "Sign in with passkey"**, a credential
  no user can create: the WebAuthn protocol, all four routes and 33 host tests
  exist, but **no screen enrolls a passkey**. RFC 177 §4.4 remains open — the
  button moves behind the email path, or enrolment gets built.
- **Eleven of the book's eighty pages remain absent from `SUMMARY.md`**, and
  `expert/view-rendering-policy.md` still links twice to one of them. Carried
  from 0.89.5; awaiting a decision on its own RFC.

---

## [0.92.5] - 2026-11-04

**Patch.** A gate. **No Worker code changed** — the bundle moves by 49 bytes, which is the version string reaching the wasm through symbol mangling and nothing else.

**E7** in `scripts/route-contracts-check.sh` answers RFC 171's producer
question on every push: **a method's caller-matched `PortError` set must be a
subset of what its production adapter can actually return.** Before this, a
handler could branch on an error nothing produced and every gate stayed green —
which is how six operator messages, three API status codes and an invitation
acceptance were lost (RFC 160 §4.11), and how an admin token could report itself
disabled when it was not (RFC 175).

- **`156 = 8 resolved + 31 DEFECT + 117 no_caller`**, recomputed from source
  every run; no committed data file.
- **The 31 are two shapes, kept apart**: **5 `written`** — a caller with a
  distinct outcome for a variant the adapter cannot produce — and **26
  `chokepoint`**, where the only match comes from a shared dispatcher arm that
  maps the variant identically, so no outcome is lost. Both exempted by name,
  dated, staleness-checked; **a new `written` defect fails the build**, and so
  does an entry that stops matching.
- The check caught two of its own design defects during the cycle: a
  receiver-blind match that credited one trait's calls to another, and a
  registry entry stale on its first run.

**Archive split** — `CHANGELOG.md` crossed RFC 028's 80 KB guard, so 0.88 is
archived. **That leaves four minor series against the rule that says five**, and
the two rules are now in open conflict; the byte rule is the one with a script
behind it, so it is the one followed. Recorded for the owner to settle.

### Release figures

- Host tests **1,675** / 0 failed / 4 ignored / 12 lines; `migration_chain`
  **35**; 192 routes; E4 `216 = 192 + 24 + 0`; E6 `92 = 83 + 9 + 0`; **E7
  `156 = 8 + 31 + 117`**; Playwright **20**; `runtime-smoke-check` passed.
- Bundle, `wrangler deploy --dry-run --outdir bundled/`, **gzip 1.15 default**:
  **888,939 B** (878,238 wasm + 10,701 `shim.js`), raw 2,433,318 + 61,887.
  `sha256 adeae02e31e16aae81cf1175a3a1ba86907dbb9899b11b4ecf2652b5100396e0` and
  `974430800e7db0fdc18f68d17c738b7cd87076d256a1455489b4827b23d0d20f`. Against
  0.92.4's **888,890 B**: **+49 B**, which is the version string itself — the
  workspace version reaches the wasm through symbol mangling, which is why this
  project measures the bundle *after* the bump (0.89.4's own case was 70 bytes).
  **No Worker code changed in this release.**

## [0.92.4] - 2026-11-04

**Patch.** Two adapter call sites on the admin-token surface — RFC 175, found by
RFC 171's producer census on its first use, in a trait that RFC never examined.

- **`disable` now asks whether the `UPDATE` matched a row.** D1's `run()`
  succeeds on zero rows, so disabling an id that does not exist or is already
  disabled used to return success **and write `AdminTokenDisabled` into the
  hash-chained audit log** for an action that did not happen. The handler's
  `Err(PortError::NotFound) => 404 "unknown token"` arm was already written and
  could never fire; it now does. Verified live, all three cases: a nonexistent
  id **404**, a real live token **303** with `disabled_at` genuinely set, the
  same token again **404** — and **zero** audit rows for the 404s against one
  for the real disable, not two.
- **`create` now classifies its INSERT failure** via `classify_insert_err`
  instead of plain `run_err`, so the *"token hash collision"* retry arm written
  for `admin_tokens.token_hash`'s real `UNIQUE` constraint is reachable.
  Astronomically unlikely to fire — the plaintext is server-minted and 256-bit —
  and fixed because a known-dead arm teaches the next reader the wrong lesson.
- **Not an exposure, and the severity was corrected during review.** No live
  token ever stayed valid while the caller was told otherwise, and probing the
  route showed it is bearer-header-only with **no console affordance at all** —
  `GET /admin/console/tokens` renders no form and never mentions `/disable`. The
  reachable caller is a script or direct API client, so the RFC's own **P1
  became P2**, and its claim that an operator could reach this from a stale list
  page was withdrawn.
- **`create_user_bound` has the identical gap and was left alone**, disclosed
  rather than folded in: it belongs with RFC 171's other classifier-adoption
  findings.

### Release figures

- Bundle after the version bump, `wrangler deploy --dry-run --outdir bundled/`,
  **gzip 1.15 at its default level**: **888,890 B** (878,192 wasm + 10,698
  `shim.js`), raw 2,433,462 + 61,887.
  `sha256 6bb48d8f475185b47bf5f0ab6908b27aebbd61b431e58b849c8490c24ddec7d0` and
  `61162129fb9909d7d877d4858a60ee6d143bf23959a8a468a60966da84093ad0`.
  Against 0.92.3's **888,787 B**: **+103 B**.
- Host tests **1,675** / 0 failed / 4 ignored / 12 lines (unchanged — this file
  needs `worker::Env` and has no host-testable surface); `migration_chain`
  **35**; **192 routes**, E6 `92 = 83 + 9 + 0`; Playwright **20**;
  `runtime-smoke-check` passed.

**Entry deliberately short.** `CHANGELOG.md` is near RFC 028's 80 KB guard while
already holding the five minor series its other rule wants, and recent entries
ran 5–7 KB because the architect duplicated RFC detail into them. The detail
lives in the RFCs; this is the first entry written to that correction.

## [0.92.3] - 2026-11-03

**Patch.** Nothing gains capability and nothing an operator could reach changes
behaviour. A console action that could never complete is gone, along with the
two modules that existed only to serve it.

### The log-level apply flow is removed — RFC 174(b)

- **`POST /admin/console/config/log_level/apply` wrote to a KV namespace this
  project does not declare**, nothing would have read the value if it had
  landed (`LogConfig::from_env` reads `env.var("LOG_LEVEL")` and never touches
  KV), and the handler then wrote an `OperationApplied` audit row saying the
  level was applied.
- **Probed before anything was built, and the RFC's own framing was wrong.**
  `GET /admin/console/config` returns **200 with zero `<form>` elements** — the
  control never existed in the UI — and the preview page's form carries an empty
  `csrf_token`, so `apply` answered **400 `csrf_token required`** before
  reaching either the KV write or the audit row. **No `log_level applied` audit
  row has ever existed.** The RFC claimed the operator was told it worked; that
  was `reviewed`, it was tiered P1 on a reading, and the probe moved it to
  **P2**. The correction is recorded in the RFC rather than quietly in this
  entry.
- **Removed**: both handlers, their registrations, their two
  `route-contracts.md` rows, and the comments that described a binding
  requirement never met and a `from_env` preference that never existed.
  **Routes 194 → 192**; E4 `216 = 192 + 24 + 0`; E6 `92 = 83 + 9 + 0`.
- The two deleted URLs are now absorbed by the surviving `:bucket` wildcard and
  answer **401** without a credential, **404 `unknown bucket`** with one — the
  generic handler's own checks, captured rather than predicted. Both fail safe
  and nothing references either path.
- **The log level remains a deploy-time `wrangler.toml` `[vars]` value**, which
  is what every page in the book already said. This release makes the code agree
  with the documentation rather than the other way round.

### And the two modules that served only that flow — 19 tests, 682 lines

- After the removal, **every public item in `cesauth_core::admin::preview` and
  `cesauth_frontend::admin::preview` had zero references outside those two
  files** — `mint_preview_token`, `verify_preview_token`, `PreviewTokenPayload`,
  `DiffEntry`, `ImpactStatement`, `ImpactSeverity`, `log_level_impact`,
  `admin_token_rotation_impact`, `preview_body`, `preview_body_noop`.
- **An architect instruction to keep part of it was reversed.** The removal
  handoff said to keep the HMAC token pair because the generic bucket
  preview/apply flow was its *"obvious future consumer"* — that flow returns a
  plain `json_response` and never used any of it. Keeping two dead modules on a
  speculative consumer, in the release that removed their only real one, would
  have been a deliberate instance of the class RFC 166 exists to stop.
- **Deleted**, with a dated entry in RFC 166 naming the cluster and the commit
  it is recoverable from — and the recovery commands were run, not just written.
  Host tests **1,694 → 1,675**, exactly the 19 tests the deleted modules owned.
- `admin_token_rotation_impact` went with the file. It never had a caller at
  all, which predates this work.

### Found in review, recorded not fixed

- **`config::apply` — the generic bucket apply, three functions from the
  deleted one — was already correct**: it writes `attempt:{bucket}`
  unconditionally and `ok:{bucket}` only on success, with a comment saying why.
  So RFC 174 was never a class; it was one handler that did not follow its own
  sibling's pattern.
- **`unused_imports` is denied in `cesauth-backend` only**, and `cesauth-core`
  and `cesauth-frontend` carry three live warnings to show it matters —
  pre-existing, and found because deleting two modules could not have caused
  them.
- Removing the last rows that use an E6 mechanism leaves its `case` arm matching
  nothing, and **nothing fails**: the staleness discipline covers the exemption
  lists, not the mechanism table. The arm was removed by hand this cycle.

### Release figures

- Worker bundle at this commit, after the version bump, via
  `./node_modules/.bin/wrangler deploy --dry-run --outdir bundled/`, **gzip 1.15
  at its default level**: **888,787 B** (878,087 wasm + 10,700 `shim.js`), raw
  2,433,164 + 61,887 bytes.
  `sha256 a8a98a21ab2d5ad3f2f192ff89b5515b2187763e7bbfc7ff460682b502e1e98d`
  (wasm) and
  `c5a27a553aa08e39f87ae6b0ac5647f3bccaa9add998ad9afac1c92acdece5c3` (shim).
  Against 0.92.2's **897,191 B**, measured the same way after its own bump:
  **−8,404 B**, the first decrease in this series. Almost all of it is the
  deleted handler's complete styled HTML document; the module deletion added
  only −192 B, because the linker had already dropped the unreachable functions
  and the 19 tests never entered a release build.
- Host tests **1,675** passed / 0 failed / 4 ignored across 12 `test result:`
  lines; `migration_chain` **35**; **192 routes**; E4 `216 = 192 + 24 + 0`; E5
  `17 = 17 + 0 + 0`; **E6 `92 = 83 claims + 9 declared + 0 unclassified`**,
  `83 = 65 + 0 + 18`; Playwright **20**; `runtime-smoke-check` passed.

## [0.92.2] - 2026-11-03

**Patch.** Nothing gains capability. CI can now drive a credentialed flow for
the first time, which closed two findings that had been stuck at `observed` —
and found a third on its very first run: a detector that had never run once and
reported success every day for six months.

### CI can drive a credentialed flow — RFC 170, both halves

- **Every other gate in this project runs with no credential and no migrated D1
  state**, so two findings could not reach `exercised`: a gate has to be able to
  fail when the behaviour stops working, and nothing could drive these.
  `.github/workflows/credentialed-flows.yml` applies migrations to a local D1,
  seeds one per-run random admin token — **sha256 only, masked, never logged,
  never committed** — and makes exactly two assertions.
- **RFC 147's deletion sweep: `observed` → `exercised`.** The job triggers
  `/__scheduled?cron=0+4+*+*+*` against a real `wrangler dev --test-scheduled`
  with an already-due request and asserts **three facts, not a status**: the
  user row is gone, the request reads `executed`/`sweep`, and the audit chain
  carries `deletion_executed` with `subject` = the deleted user.
- **RFC 152 half A's admin cookie witness: restored.** The job walks the real
  two-step `/admin/login` flow and asserts the `Set-Cookie` string carries
  `__Host-`, `Path=/`, `HttpOnly`, `Secure` and `SameSite=Strict`, reporting a
  missing attribute **by name** with the header withheld from the log.
- **The release workflow set is now 14** (15 files with the one off-path entry),
  and the manifest, `contributing.md`'s three prose counts and a new
  stale-phrase guard moved with it.
- **RFC 147's remainder, also shipped**: the sweep's decision core is lifted
  into `cesauth_core::deletion::sweep_due_deletions`, a pure function over the
  repository ports, with `sweep_pending_deletions` reduced to the `Env`-bound
  shell that produces the log lines and audit events only `Env` can. Four host
  tests, one pinning RFC 147 cycle 2 D5's own regression — the audit call that
  once passed `None` as the subject.

### A detector that had never read a row, and said so daily — RFC 173

- **`session_index_audit` bound an `i64` straight into D1.** `wasm_bindgen`
  turns that into a JavaScript BigInt, which D1 rejects outright, so
  `fetch_active_rows` failed on **every run since 2026-05-06** — six months.
  The exact pitfall, and its fix, are documented at the top of the adapter
  crate's `ports/repo.rs`; the helper that implements it is `pub(crate)` and was
  **unreachable from the one caller outside that crate.**
- **Its error path returned `Ok`.** So the operator-facing cron status recorded
  a **successful** session-index audit, with no error string and 0 rows walked,
  every day. Zero drift is also what a working detector reports — there was no
  observable difference to notice. Both early returns now propagate, including
  the identical `Config::from_env` arm three lines above the one the RFC named.
- **What was lost**: the only signal for a class whose own documentation reads
  *"the user sees a phantom row in their list"* and *"DO is revoked but D1 still
  thinks active … the page would render this as still-active and offer a no-op
  revoke button."* Whether drift is occurring is **unknown**, not zero, and the
  first green run is the first datum — **no historical figure is claimed.**
- **And no cron pass had ever been recorded at all.**
  `cron_status::record_cron_pass` called `env.kv("CESAUTH_KV")`; this project
  declares exactly one KV namespace, `CACHE`, and a namespace can only come from
  `wrangler.toml`. All six daily passes failed there, the error discarded by
  `let _ =`. Zero `cron:last-run:*` keys before the one-line fix; six after.
- **RFC 170's third assertion**, which its scope fence said would arrive only
  when a third finding needed one: the job now asserts the recorded pass has
  `processed_count >= 1`, not `success` alone — which is precisely what six
  months of this looked like.

### Found in review, recorded not fixed

- **`POST /admin/console/config/log_level/apply` writes a hash-chained
  `OperationApplied` audit row for a change that cannot happen** — the KV
  binding it writes to is undeclared, and `LogConfig::from_env` never reads KV
  anyway. The operator is told it worked, the record of truth says it worked,
  and the log level cannot be changed at runtime. **RFC 174**, P1, accepted
  2026-11-03.
- `operations_route.rs`'s `CronRecord` is never constructed, so nothing displays
  the cron records that now finally persist.
- `required (Content-Type)` is sound only while no `Access-Control-Allow-Origin`
  exists anywhere in this worker — an absence nothing guards.

### Release figures

- Worker bundle at this commit, after the version bump, via
  `./node_modules/.bin/wrangler deploy --dry-run --outdir bundled/`, **gzip 1.15
  at its default level**: **897,191 B** (886,492 wasm + 10,699 `shim.js`), raw
  2,454,460 + 61,887 bytes.
  `sha256 ef6fbd1885b3a0eb5fbcba61ab30a9f8620ccd0c4645e3d51ea47856deddb362`
  (wasm) and
  `d4de41a41795a276889f81c538b3d193d41d9e7e934a619e92cf39d335ed146e` (shim).
  Against 0.92.1's **896,990 B**, measured the same way after its own bump:
  **+201 B** — RFC 170's refactor adds real code to the shipped Worker, which is
  a change in bytes and not in behaviour.
- Host tests **1,694** passed / 0 failed / 4 ignored across 12 `test result:`
  lines; `migration_chain` **35**; 194 routes; E4 `218 = 194 + 24 + 0`; E5
  `17 = 17 + 0 + 0`; **E6 `94 = 85 claims + 9 declared + 0 unclassified`**,
  `85 = 67 + 0 + 18`; Playwright **20**; `runtime-smoke-check` passed.

## [0.92.1] - 2026-11-03

**Patch.** Nothing gains capability. A passkey registration route that
authenticated nobody now authenticates its subject; a CSRF control three rows
documented did not hold and now does; seven more rows say what actually protects
them.

### A passkey could be registered on any account — RFC 172 (P0)

- **`POST /webauthn/register/start` read the account it was registering a
  passkey for out of the request body**, with no cookie, no `Authorization`
  header and no token. `register_finish` wrote the authenticator for it and then
  issued a session, under its own comment *"Registration doubles as a
  first-login"*. **Given a user id, that was account takeover in two
  unauthenticated requests.**
- **Exposure was none: nobody has deployed this tree.** That is the only thing
  that kept this from being an incident, and it is not a mitigation.
- **Fixed**: the subject comes from the session, resolved before anything else
  in the handler. `RegisterStartBody::user_id` is **deleted**, so no field exists
  for a caller to set, and the type now makes the defect unrepresentable.
  Failure answers **401 JSON**, not a 302 — RFC 149 §2's ruling, because a
  redirect-following client cannot tell a 302-to-success from a
  302-to-failure.
- **Witnessed, both halves**, because a 401 alone would also be produced by a
  fix that rejected everything: naming another account with no session answers
  **401**; with a real magic-link session it answers **200** and
  `public_key.user.id` is the **session's** user, byte-for-byte, with the body's
  id appearing nowhere in the response. **No ceremony was driven to completion
  and no exploit was written** — the missing check was the defect.
- **`register_finish` deliberately still requires no session**, and the reason
  matters: `complete_auth` signs the caller in as the *challenge's* subject, so
  a bare *does-a-session-exist* check would let a second valid session complete
  someone else's pending registration and be signed in as them — worse than
  none. The `Content-Type` control added to that route closes the matching
  session-fixation shape instead.
- **Found by RFC 152 half D stage 1**, which recorded *"no ambient credential is
  ever consulted"* as a correct CSRF justification without noticing that the
  sentence was also the whole defect.
- **Not fixed here, named instead**: there is still no screen for passkey
  registration, so the route is correct and uncalled; and nothing in the gate
  set asks whether a handler that writes security state authenticates the
  subject it writes it for.

### The CSRF control three rows documented did not hold — RFC 152 half D stage 1b

- **`is_json_content_type` compared a substring.** It used
  `.contains("application/json")` to tolerate `; charset=utf-8` — and a
  **parameter** satisfies it too. `Content-Type: text/plain; x=application/json`
  has a **CORS-safelisted MIME essence**, so a cross-site
  `fetch(…, {credentials:'include'})` sends exactly that value **with no
  preflight** and walks past the control.
- **`/me/security/delete-account` carried this since RFC 149 §2**, under a doc
  comment reading *"this check IS the CSRF control"*. A forged cross-site
  request could reach the handler and schedule the victim's account deletion.
  Not exploitable — `SameSite=Strict` held — but the control the code claimed
  did not.
- **Fixed** by comparing the MIME essence: split at the first `;`, trim,
  compare exactly. Not by lengthening the substring, which would have left the
  same class of bypass one parameter away.
- **Third instance of this RFC's own sentence, one per half.** Half B: the
  documented control did not exist. Half C: seven rows claimed one they did not
  have. Half D: the control three rows claimed did not hold.

### Seven rows now say what protects them — RFC 152 half D stage 1

- **The measurement, which was the point.** For the 18 rows claiming
  `N/A (bearer)` while accepting a cookie: **no real cookie-borne caller
  exists** — no `fetch` or form POST to any of those paths anywhere in the
  frontend, the e2e suite or `scripts/`. Recorded as `reviewed` and left
  unchanged; flipping them is a caller-obligation change of its own size.
- **Seven `N/A (JSON)` rows resolved per row**, not globally. One of them —
  `/me/security/delete-account` — already enforced the check and its cell was
  *understating* a control it had; the other six claimed one they did not have.
  Three now carry `required (Content-Type)` with the check; the rest carry an
  honest `N/A (no ambient credential)`.
- **Two latent gate bugs, fixed.** E6's registration-line matcher was a literal
  substring that could not match the **88** column-aligned `.post_async  (`
  registrations in `lib.rs`, and its file resolver had no case for a brace-list
  re-export. Both were invisible because the affected rows were `declared`, so
  the resolver returned before using a silently-empty name. **A gate's unused
  code path is not a working code path.**

### `CHANGELOG.md` holds the five minor series it claims — RFC 028

- The file said it keeps the most recent five and held **eight** (0.85–0.92) at
  **79 KB of its 80 KB budget**, so the byte guard had never fired and the
  five-minor rule was checked by nothing. 0.85–0.87 are archived to
  `docs/changelog-archive/CHANGELOG-0.85-to-0.87.md`; the root file is **59 KB**
  over 0.88–0.92.

### Surface-contract changes, stated as changes

- **`POST /webauthn/register/start` requires a session and no longer accepts a
  `user_id`.** A caller may not choose the account.
- **Three routes reject `Content-Type` values they previously accepted** —
  anything whose MIME essence is not `application/json`.
- **No caller exists to break**: re-confirmed this release that nothing under
  `crates/` calls either register path.

### Recorded, not fixed

- **`required (Content-Type)` is sound only while no
  `Access-Control-Allow-Origin` exists anywhere in this worker.** True today,
  documented in prose at `routes/deletions.rs:70`, and enforced by nothing —
  add a CORS header and **four routes silently lose the control their rows
  claim** while every gate stays green. The gate is one line.
- `E6_BEARER_LEGACY_EXEMPT`'s comment says *"17 routes"* where its list has 18.

### Release figures

- Worker bundle at this commit, after the version bump, via
  `./node_modules/.bin/wrangler deploy --dry-run --outdir bundled/`, **gzip 1.15
  at its default level**: **896,990 B** (886,291 wasm + 10,699 `shim.js`), raw
  2,453,743 + 61,887 bytes.
  `sha256 830173cfb147b8ac4a9c8a4a66be2dd2fd00acecf6cd0140768cee09c03a2504`
  (wasm) and
  `9d506c4c5c4ad441dd29397eb15cd32cef06f46e17f8218e02cc08543618f1d7` (shim).
  Against 0.92.0's **896,672 B**, measured the same way after its own bump:
  **+318 B** — real new control flow (session resolution and three
  `Content-Type` checks), not noise.
- Host tests **1,690** passed / 0 failed / 4 ignored across 12 `test result:`
  lines; `migration_chain` **35**; 194 routes; E4 `218 = 194 + 24 + 0`; E5
  `17 = 17 + 0 + 0`; **E6 `94 = 85 claims + 9 declared + 0 unclassified`**,
  `85 = 67 + 0 + 18`; Playwright **20**; `runtime-smoke-check` passed.

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
