# cesauth — CHANGELOG (archive: v0.92–v0.92)

> This file is part of the changelog archive.
> Current releases are in the root [`CHANGELOG.md`](../../CHANGELOG.md).

## [0.92.7] - 2026-11-07

**Patch.** Nine lines of imported CSS, and a gate redesigned so importing them
cannot silence it. **No API behaviour changed**; no route, wire format, schema,
cookie or permission slug touched.

### Fixed — six elements authored invisible were rendering visible (RFC 179)

The CSR app loaded no author CSS, so `class="sr-only"` did nothing and every
element relying on it was shown to everyone:

| site | what was visible |
|---|---|
| `pages/operator/tenancy.rs:175` | **the operator's CSRF token**, labelled `csrf: ` |
| `pages/operator/clients.rs:281` | a raw OIDC client id |
| `pages/operator/clients.rs:350`, `sessions.rs:96`, `tenant_admin/invitations.rs:83` | three table headers meant to be empty columns |
| `pages/login.rs:114` | a `Passkey sign-in` heading meant for screen readers |

**Not a vulnerability and not reported as one.** A CSRF token authorises nothing
without the session cookie; the cost is one layer of defence in depth against
screenshots and screen-sharing, plus five confusion defects. All six verified
invisible **in a browser** — `getBoundingClientRect()`/`getComputedStyle()`, not
Playwright's `isVisible()`, which does not detect clip-based hiding.

### Changed — the fix was an import R2a left behind, not design work

RFC 178 attributed the missing stylesheet to **RFC 131 R3**, an unbuilt slice of
an accepted programme. **That was wrong.** R2a — shipped in **0.82.0** —
imported 17 primitives, `view_models` and `icons` from the mockup at pin
`df3d9d0`, ~1,489 LOC, and left the four stylesheets beside them. Its changelog
entry named one thing outstanding: *"a future RFC wires them to real data."* The
**data** half. So for fourteen releases the project described a missing file copy
as unstarted design work.

`crates/frontend/static/base.css` now carries `.sr-only` **verbatim from that
same pin**, `sha256 42b849b2…e722695`, confirmed byte-identical by `diff`.
Imported rather than authored on purpose: a hand-written rule would be a second
presentation source to reconcile later. Served at `/assets/base.css` by the
path `webauthn.js` already used — **no `Makefile`, `wrangler.toml`, Trunk or CSP
change**; `style-src 'self'` already permitted it.

**The root cause, stated properly**: `BASE_CSS` already defines
**`.visually-hidden`** at `templates/chrome.rs:184-192` — the *same* clip-rect
rule — and the server-rendered templates use it successfully. The CSR pages use
`sr-only`, the mockup's name. **Two names for one behaviour, one styled and one
not.** Converging them is deferred, and neither rule may now change without the
other.

### Changed — the stylesheet gate is a census, because the fix would have silenced it

RFC 178's gate asserted `ruleCount > 0`, which **a stylesheet containing only
`.sr-only` satisfies.** Landing the import alone would have deleted
`KNOWN_NO_STYLESHEET` as stale and flipped the gate to quietly passing while 95
of 96 class names stayed unstyled — trading a check that printed its own gap for
a green tick proving one rule exists.

- **Census, derived from source every run, no committed data file**:
  **`96 = 1 declared-and-matching + 95 not-yet-styled + 0 unclassified`**.
- **96, not 84.** 84 is what a literal `class="…"` grep sees; **nine `class=`
  sites compute their value in Rust** and contribute 12 names no such grep can
  find. Two of those constructs take a caller-supplied prop, are **not
  statically enumerable**, and are declared out by name.
- **Declares the *styled* set, not the unstyled one** — one entry today. The
  remainder is computed, so a future import costs one line instead of 83
  deletions.
- **Staleness points both ways**: a declared name losing its rule fails as a
  regression; an undeclared name gaining one fails as unreviewed growth. Both
  forced and restored.
- `.github/workflows/trunk-release-build.yml`'s `exit 1` is **restored** — with
  a stylesheet present, a missing one is a real failure again.

### Known gaps

- **The census overstates the gap by ~3×, and the ambiguous spec was the
  architect's.** 67 of the 95 unstyled names come from the 17 imported
  primitives, **every one of which has zero call sites** — so they cannot render
  at all. Only **29** names are reachable today. A reachability partition is
  queued; so is dropping a declared-out clause (*"no `<Badge` usage exists"*)
  that will expire when R3 lands while the exemption stays correct.
- **The server-rendered half is mostly unstyled too, and had never been
  measured.** `admin/`, `tenancy_console/`, `tenant_admin/` and `templates/` use
  **75** distinct class names against the **22** selectors `BASE_CSS` defines —
  **17 styled, 58 with no rule anywhere.** `btn-primary`, `card`, `data-table`,
  `badge-ok`, `alert-info` and 53 more. Queued with its own measurement, because
  these files write `class=\"…\"` escaped inside `format!` strings (31 sites)
  which the CSR matcher cannot see.
- **`trunk` cannot be installed on this machine**, so the frontend static
  asset's size and hash are **unverifiable locally by anyone** and the
  long-standing `317,718 B` figure has never been independently confirmed. Only
  CI's `Trunk release build` exercises it. Playwright, the live census and the
  six-element check are therefore `observed` from the dev team's runs, not
  `exercised` at review.
- **Eleven of the book's eighty pages remain absent from `SUMMARY.md`**, and
  `expert/view-rendering-policy.md` still links twice to one of them. Carried
  from 0.89.5.

### Bundle

Measured after the version bump, gzip **at its default level** (not `-9`):

| file | raw B | gzip B | sha256 (first 16) |
|---|---|---|---|
| `…-index_bg.wasm` | 2,433,590 | 878,371 | `d11c79a9abd2aa4f` |
| `shim.js` | 61,887 | 10,701 | `d840d5ea14574091` |
| **Worker total** | | **889,072** | |

**+100 B from 0.92.6's 888,972** — 77 B for the `<link>` line and its comment
reaching the Worker through `leptos_shell.rs`, the rest the version string.
`wrangler deploy --dry-run` requires `crates/frontend/dist` to exist; an **empty**
one was created to measure, which is sound here only because `LEPTOS_JS` and
`LEPTOS_WASM` are hardcoded consts (`leptos_shell.rs:85-86`) rather than read
from it. The frontend asset is **not** reported: see *Known gaps*.

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
