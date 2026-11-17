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

**v0.101.x and earlier are in [`docs/changelog-archive/`](docs/changelog-archive/README.md)**,
split by minor range and never edited after creation. This file holds
**0.102 and later** — the 0.93–0.101 split at the 0.107.0 cut (RFC 028
slice B) took it from 99,916 B to 40,081 B. With that cut's own entry and
this paragraph, the file measures **≈ 49 KB** — around 60% of budget,
leaving **≈ 33 KB of headroom**, roughly four more entries at this cut's sizes
— and holds the most recent six minors (the figure shifts with every
edit to this self-describing paragraph and with every entry added, so it
is given as measured at the commit that wrote it; `drift-scan`'s
changelog-budget line prints the live number every run and is the
authority). See the archive README's own dated note for the split's own byte
reconciliation, computed against the pre-rewrite size.

**The budget is now gated**, not just stated here: `scripts/drift-scan.sh`'s
changelog-budget section fails the moment this file exceeds 81,920 B
(80 KB), naming `scripts/changelog-archive-split.sh` as the remedy. Before
this cut the only thing reading the budget was that split script's own
guard, which only ran when a human ran it by hand — RFC 028 Step 5
specified a CI-shaped check as runnable bash and it had never been built.
At this cut's entry sizes (0.106.0 alone was 10.8 KB), the headroom above
is roughly six releases, not a fixed number of cuts — the gate will fire
again, and when it does, `scripts/changelog-archive-split.sh` is the tool
to run, not a hand-split.

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

**The 0.95.0 cut archives 0.92** (eight entries) to
[`CHANGELOG-0.92-to-0.92.md`](docs/changelog-archive/CHANGELOG-0.92-to-0.92.md),
taking the root from 74,482 B to **30,034 B** — reconciled: 44,448 B left the
root, 44,443 B landed in the archive, and the 5-byte difference is the `---`
separator the archive replaces with its own header. **Split to a floor, not to
just under the ceiling**: headroom goes from 7,438 B — one entry from breaching
— to **51,886 B**. The 0.93.0 cut archived 0.90–0.91 the same way, and 0.92.6
archived 0.89.

Direction for the rule itself was in RFC 028's 2026-11-07 note: delete the
derived "~5 minor versions" figure, and build the gate Step 5 already
specified. **Both done at the 0.107.0 cut** — Requirement 1's figure is
deleted with an amendment line in the RFC itself, and the gate above is
that build. **That note's §4 also records that RFC 028's diagnosis of
`ROADMAP.md` is wrong** — `## Planned (0.x)` is 93.3% of that file while
`## Shipped`, the section Step 3 says to archive, is 3.3%. `ROADMAP.md`
itself gets no gate this cut — D2 of the RFC 028 slice B handoff says
why, and `ROADMAP.md` carries its own dated row recording its size
(414,711 B, 10.1× its own ~40 KB budget) instead.

---

## [0.107.0] - 2026-11-18

**Minor** — two rules this project had already decided, now actually
enforced: every visible timestamp goes through the one formatter, and the
CHANGELOG's byte budget fails the build instead of being restated. RFC 111
slice A (three review rounds) and RFC 028 slice B (two), both reviewed and
closed.

### Fixed — the audit viewer printed a raw epoch under a column headed "Time (UTC)"

RFC 111 settled in v0.73.0 that **every visible timestamp is UTC ISO-8601
in the `Z` form**, produced by
`cesauth_core::util::format_unix_as_iso8601`. Its Status line has said
since then that the per-file formatters were removed. **Twenty-three
render sites disagreed**, and the three worst were:

- **`pages/operator/audit.rs`** rendered `{e.ts}` — the integer — in the
  column whose own key reads `時刻 (UTC)` / *"Time (UTC)"*, while its
  sibling screen `audit_chain.rs` formatted the same kind of value
  correctly two files away.
- **`pages/sessions.rs` and `pages/operator/clients.rs`** each carried
  their own formatter emitting `2024-01-01 00:00` — no `T`, no seconds, no
  `Z` — and `sessions.rs`'s comment claimed *"For now emit ISO-8601"*
  about a format that is not ISO-8601. The server-rendered security centre
  shows **the same session timestamps** through the canonical formatter,
  so two surfaces disagreed about one user's data.
- **Twenty more raw-epoch cells** across the `admin/`, `tenancy_console/`
  and `tenant_admin/` templates, five of them in files a live route
  renders today.

All 23 now go through the canonical formatter. Both per-file formatters
are **deleted**, not left wrapping it. **Seven stale `(unix)` column
labels** are dropped, because the value under them no longer is one.

**This is a visible change in both locales.** `/me/security/sessions`,
the OIDC client list, the audit viewer, and the tenancy/admin tables now
read `2024-01-01T00:00:00Z` where they read `2024-01-01 00:00` or a bare
integer. Timestamps remain locale-independent by RFC 111's own design.

### Added — the gate RFC 111's acceptance criteria specified and nobody built

`scripts/drift-scan.sh` gains a timestamp-rendering section that **fails
five distinct ways**: a reverted conversion, a new conforming site that
moves the pinned count, a raw timestamp-field access written as a
binding, the same written as an HTML interpolation, and a stale
exemption. It pins **24 canonical-formatter calls across 15 files** and
carries **five named exemptions**, each with its reason.

**Why five ways and not one.** RFC 111's own acceptance criteria grepped
for `OffsetDateTime::from_unix_timestamp` and `fn format_unix_local` — and
a raw `{ts}` interpolation matches **neither**. The RFC verified the
absence of two spellings and claimed the absence of a class. Two
successive drafts of this gate's matcher reproduced that same error in
miniature (one matched only a format-string shape; one treated every line
ending in `>` — i.e. every HTML render line in this codebase — as a
comparison to skip), and each was caught the same way: by planting a
regression in the shape the codebase actually writes, not the shape the
matcher was written against.

### Fixed — RFC 111's Status line, with the history it got wrong

The *"per-file legacy formatters removed"* claim now carries three facts
instead of one: it was **already false when written** (at tag `0.73.0`,
`crates/ui/src/admin/overview.rs` rendered raw epochs at three lines);
RFC 111 **did** remove the formatter it named; and the pattern **regrew
twice afterwards**, with CSR migrations at `0.79.3` and `0.92.0`. The
record now says *why a gate is needed* — the class comes back every time a
screen is rewritten — rather than implying a one-time miscount.

### Added — the CHANGELOG byte budget, gated

RFC 028 specified a CI-shaped budget check **in full, as runnable bash**,
and five enforcement notes over seven months recorded that it did not
exist. It exists now: `drift-scan.sh` fails the moment root
`CHANGELOG.md` exceeds **81,920 B** — the same KiB definition the split
script's own guard uses, so a gate and its remedy tool cannot disagree by
1,920 B — and names the remedy with the right parameter.

**The file was a quarter over budget at this cut's start** (99,916 B
against ~80 KB), so the split ran too: **v0.93–v0.101 archived**, nine
entries, **59,836 B moved byte-identically** into
`docs/changelog-archive/CHANGELOG-0.93-to-0.101.md`, root down to **~41 KB**
— half the budget, about six releases of headroom at this cut's entry
sizes.

**The split tool had three recorded defects and had never been run.** Both
previous splits were done by hand, which is exactly why the defects
survived two opportunities to be found. All three are fixed — an invalid
README-index `sed` whose failure was swallowed by `|| true`, a duplicated
*"Older releases"* block, and root-relative links breaking two levels
down — **plus a fourth that only running it could reveal**: the archive
README's *"Current releases (vX.Y.Z and newer)"* sentence, which the
script never updated and both previous splits fixed by hand without
folding the fix back.

### Changed — two stale derived figures deleted from RFC 028

Requirement 1's *"~5 minor versions"* and Step 1's *"50-100 KB range"* are
gone, each with an amendment line. The 2026-11-07 enforcement note had
already ruled the five was derived **from** the byte budget rather than
standing beside it, and that releases per minor had risen from ~1 to ~4
while the figure stayed fixed. **The rule is the byte budget; how many
minors it holds is an outcome.**

**`ROADMAP.md` is 10.4× its own ~40 KB budget and is deliberately
ungated.** Its only real remedy is condensing shipped rows to summary +
link, which RFC 028 itself calls *"judgement rather than a shell loop"* —
and a gate whose remedy is an unscoped judgement job would be red the day
it lands. `drift-scan` prints the number every run instead, and the
ROADMAP carries a row that points at that line rather than a figure which
goes stale the moment the row is edited.

### Added — one environment fact that cost an hour

`docs/src/expert/contributing.md` now records that `wrangler dev
--local`'s fetch-handler D1 binding and its bundled Local Explorer API can
resolve the same `--persist-to` directory and binding name to **two
different physical `.sqlite` files**, so rows seeded through the Explorer
API are invisible to the real route handlers. Every earlier G2 in this
programme exercised CSR shells, which is why nobody had met it before.

### Security answer

The diff touches no file under `crates/backend/src/routes/`,
`crates/core/src/{jwt,totp,webauthn,oidc,authz,session,audit}` or
`migrations/`, so the release rubric's path list does not fire. Stated
anyway, because this cut changes a surface operators read for integrity:
the audit viewer's time column now renders the same instant, in the same
form, as the chain-status screen beside it, which **strengthens** an
operator-facing surface rather than changing what any route accepts. No
route, query parameter, payload or permission moved — **197 routes, 0
added, 0 removed**, all seven coverage figures unchanged. No migration, no
schema change, no dependency change.

### Gates

Host tests **1,737 / 0 / 4 across 12 `test result:` lines** — **+5** over
`0.106.0` (six new caller tests, one obsolete test deleted with the
function it called). Migration chain **39**. Route surface **197, 0 added,
0 removed**. `drift-scan` clean: i18n ceiling **103 / 65 / 69, 0
violations**, operator-console negotiation **13 / 13**, release
reconciliation **163 tags / 162 entries, 0 unexempted** (plus `0.107.0`,
the release being cut), timestamp
rendering **24 / 15 with 5 named exemptions**, changelog budget
green — the root file at **≈ 49 KB of its 81,920 B budget**, ≈ 33 KB of
headroom. No exact byte figure is quoted here on purpose: this entry is
inside the file it would be measuring, and `drift-scan`'s own
changelog-budget line prints the live number every run. Clippy 0 errors,
`cargo deny` ok in all four sections, wasm32
backend check clean. Catalog unchanged at **314** arms — timestamps are
locale-independent, so this cut adds no `MessageKey`.

---

## [0.106.0] - 2026-11-17

**Minor** — the OIDC client manager answers `Accept-Language`, which makes
**thirteen of thirteen** shell-rendering operator screens negotiate, and a
new gate holds them there. RFC 185 §5.3 screen 5, one copy gate and two
implementation rounds, all reviewed.

### Added — the thirteenth screen, and the heaviest copy slice in the programme

`/admin/console/clients` resolves its locale per request and renders from
the catalog: **33 new `MessageKey`s** and **8 existing keys reused**,
taking the catalog from **281 to 314** arms. Driven over real HTTP: three
requests under `wrangler dev --local` — `en`, `ja`, no header — all `200`,
`<html lang="en">` with *"OIDC clients — cesauth"* and twice
`<html lang="ja">` with *"OIDC クライアント — cesauth"*.

**This screen is the one whose code shape had to change**, because three of
its strings could not be keyed as they stood:

- **A sentence wrapped around interpolated markup.** The delete and
  reissue confirmations were a Japanese prefix, a bold client name, and a
  Japanese suffix — two halves that are only a sentence in Japanese word
  order. Each is now one key with a `{name}` placeholder, split on the
  placeholder at render time so the name stays bold. The split uses
  `expect`, not a silent fallback: a delete confirmation that quietly drops
  the client's name is worse than a panic, and the new test below makes the
  panic unreachable.
- **A noun slot with an interpolated verb.** The secret-reveal heading was
  `format!("クライアント「{}」の{}", label, verb)` where `verb` was
  `"再発行"` or `"作成"`. No English frame takes those two nouns in that
  slot, so the struct field became the key — `Revealed.heading:
  MessageKey` — and each call site now carries a whole heading.
- **Three one-time-secret warnings in fragments**, each collapsed into a
  single looked-up sentence.

**Both one-time-secret warnings now say the whole consequence, in both
places and in both locales.** An operator who reads the confirmation and
an operator who reads the panel after the fact need the same four facts —
the old secret dies immediately, every integration using it stops
authenticating, the new one is shown once, copy it now — and neither
sentence hedges *"cannot be shown again"*.

### Added — a gate that keeps thirteen screens negotiating

`drift-scan.sh` gained a section that enumerates every file under
`routes/admin/{console,tenancy_console}/` calling a shell helper and
requires each to contain `resolve_locale`, pinning the population at
**13**. It fails in both directions: if the scanned count moves off 13 (a
route started or stopped rendering a shell) or if any of the 13 stops
negotiating. Review broke it three ways on a copy of both directories — a
converted route losing `resolve_locale`, a well-behaved fourteenth
shell-rendering file, and a route ceasing to render a shell — and it
caught all three. Twelve routes earned a negotiated locale across five
slices with nothing stopping any of them from regressing; that is now
closed.

**The gate's population is those two directories, which is §5.3's scope
and not the whole tree.** Repo-wide, 22 files call one of the two shell
helpers; six non-definers outside the scanned roots do not negotiate. The
roots widen when the next family converts.

### Added — one test the rest of the suite cannot make

Four tests assert that each `{name}`-bearing key contains the placeholder
**exactly once in both locales**. Nothing else checks this: the duplicate
test compares whole values without looking inside them, and the literal
ceiling only counts strings outside the catalog. A translator edit that
drops the placeholder would silently drop the client's name; one that
doubles it would leave `{name}` sitting in rendered prose.

### Changed — four copy decisions, each visible

- **A column header that hides its unit now states it.** `作成日時 (UTC)` /
  *"Created (UTC)"*: the cell is built from `OffsetDateTime::from_unix_timestamp`,
  which is UTC, and keying the header as *"Created"* would have cemented the
  omission. Screen 1 reverted exactly this when a CSR rewrite turned
  `時刻 (UTC)` into `時刻`.
- **Both secret-reveal headings name the secret in Japanese too.** The
  proposed Japanese said *client X's reissue* while the panel was showing a
  **secret**, and the English already said *"Secret reissued for X"* — two
  locales telling an operator different things on a credential screen.
- **A dialog's button answers the dialog's question.** *"Yes, delete"* and
  *"Yes, reissue"*, not a second *"Delete"* / *"Reissue secret"*: Japanese
  distinguished the table's button from the dialog's by noun-versus-verb
  form (`削除` / `削除する`), and English does not get that distinction for
  free.
- **A warning's leading space moved into the markup.** Whitespace inside a
  catalog value is invisible to review, invisible to the duplicate check,
  and the first thing a translation tool trims.

OIDC wire values stay untranslated and are now named as such:
`confidential`, `public`, `client_secret_basic`, `client_secret_post` go
back to the API verbatim — the carve-out the cron identifiers already have.
The file's literal ceiling went **60 → 2**, the two being the second pair
above.

### Fixed — one column header that five keyed siblings outvoted

`<th scope="col">"ID"</th>` was a hardcoded literal while the other five
headers in the same `<thead>` went through `lookup`. It is now
`ClientsColId` (`ID` in both locales), because a hardcoded literal cannot
be translated by a locale this catalog has not met yet, and an equal value
today is a translation rather than an omission. Found by instrumenting the
ceiling matcher to print its hits instead of counting them: the row said 3
and the slice's report explained all three as wire values, which two of
them were.

### Not closed: §5.3, and the sign-in page

RFC 185 §5.3 is the CSR surface converted per screen. **What closed is
slice 3's thirteen shell-rendering operator screens.** Measured from the
ceiling table at this cut, **65 files still carry 956 counted literals**:
789 across the 44 server-rendered files under `admin/`,
`tenancy_console/` and `tenant_admin/`; 22 across seven dormant RFC 180
chrome components mounted by no page; 1 in `templates/chrome.rs`; 8
declared carve-outs under `pages/operator/`; and **136 across ten live,
routed CSR pages that no slice plan covers** — `security_center.rs` 31,
`sessions.rs` 18, `totp.rs` 17, `pages/tenant_admin/*` 62, and
`login.rs` **8**. Thirteen operator screens negotiate and **the sign-in
page does not**. Recorded here rather than discovered later, because three
earlier done-claims in this project had to be retracted against the tree.

### Security answer

The diff touches `crates/backend/src/routes/admin/`, which the release
rubric's path list names, so the question fires. **No new
security-relevant surface**, and this is what was checked: the one backend
line changed hands `resolve_locale(&req)` to a shell helper whose
`resolve_admin` gate is untouched and still runs first; no route, query
parameter or payload moved (197 routes, 0 added, 0 removed);
`crates/backend/src/i18n.rs` is untouched, so `Accept-Language` is parsed
by the same code in use since `0.99.0`; and this screen's JSON `fetch()`
mutations and their `X-CSRF-Token` header predate this cut and were not
touched. Named explicitly because the screen handles a credential: the
plaintext secret still renders into its own `readonly` field, and the two
new heading keys interpolate the client **label** only — `{name}` is
substituted from `client_label`, never from the secret — with the new
placeholder tests pinning that each heading carries exactly one
substitution point in each locale.

### Gates

Host tests **1,732 / 0 / 4 across 12 `test result:` lines** — **+4**, the
four placeholder tests. Migration chain **39**. Route surface **197, 0
added, 0 removed**, all seven coverage figures unchanged. `drift-scan`
clean, i18n ceiling **103 scanned / 65 hit / 69 entries, 0 violations**,
plus the new negotiation line at **13 scanned / 13 negotiating**. Clippy 0
errors, `cargo deny` ok in all four sections, wasm32 backend check clean.
Catalog **281 → 314** arms.

**Bundle, CI to CI**, with the code and the version bump in separate
commits as the rule requires:

| commit | `Cargo.toml` | gzip |
|---|---|---|
| `1c242b7` (`0.105.0` tag) | `0.105.0` | 904,367 B |
| `c55ba60` (this cut's code, round 2) | `0.105.0` | 905,883 B |
| `996cd22` (`0.106.0` tag) | `0.106.0` | **906,093 B** |

**Code delta at the pinned version: +1,516 B** — the programme's largest
copy slice, 33 keys and their values in two locales. **Absolute at the tag:
906,093 B, +1,726 B** over `0.105.0`, **34%** of the 2,621,440 B budget.
**The version string accounts for +210 B** — and it is *up* this time,
against −104 B at `0.105.0`, −144 B at `0.104.0` and −829 B at `0.101.0`,
which is a reminder that the version-string effect is an artifact of
compression neighbourhoods rather than a trend.

**A local sum agreed with CI to 3 B this time** (905,880 B against
905,883 B on `c55ba60`), where this programme's history had 31–293 B of
disagreement. It changes nothing about the rule — CI is the authority and
the local figure is declared not comparable — but the spread is worth
recording in both directions.

**This release's check-run total was 16, and the composition is not what
`0.105.0`'s note implied.** That note explained its own 16 as 15 plus a
scheduled workflow firing on the same tip, which was true there — a
`deny.yml` `schedule:` run. It is not the general rule. Measured across
seven recent commits:

- **14 push workflow runs** on every push to `main`, all `success`. This
  is the only stable number, and it is the one the release-gate manifest
  pins.
- **15 check runs** as the base, because `worker-build.yml` emits two jobs
  (`worker-build`, `runtime-smoke`).
- **A sixteenth, named *"Security audit"*, appears on some commits and not
  others** — present on `c55ba60`, `5b3df94` and this release commit,
  absent on `d129545`, `38e736d`, `5483791` and `1c242b7`. It is not a job
  of any workflow: `audit.yml` declares one job, named `cargo audit`, and
  `rustsec/audit-check@v2.0.0` holds `checks: write` and creates a check
  run of its own through the Checks API, which GitHub attaches to whichever
  check suite is at hand (here, `docs.yml`'s — whose file declares exactly
  one job, `mdbook`).
- **Plus any workflow whose own `schedule:` fires on that tip**, which is
  how `5483791` reached 17.

So the condition to wait on is what it already was — a **stable** count
with nothing pending and no failures — but the reason is broader than one
scheduled workflow, and a release whose check-run total differs from the
last one's by one is not evidence of anything on its own.

---

## [0.105.0] - 2026-11-15

**Minor** — seven more operator screens answer `Accept-Language`, and the
last three Japanese literals outside `pages/operator/` come from the
catalog. RFC 185 §5.3 screen 4, one copy gate and one implementation
round, both reviewed.

### Added — the console's seven, and twelve of thirteen

`/admin/console` and its six sub-screens (`operations`, `tokens`,
`safety`, `cost`, `alerts`, `config`) resolve their locale per request and
render from the catalog: **9 new `MessageKey`s** and **10 existing keys
reused**, including `OperatorConsoleBackLink` alone covering six
occurrences of `← コンソール`. **Twelve of the console's thirteen
shell-rendering screens now negotiate**; `clients.rs` is the thirteenth.

Driven over real HTTP: 21 requests under `wrangler dev --local` — seven
routes × {`en`, `ja`, no header} — all `200`, seven `<html lang="en">`
with English titles, fourteen Japanese.

**The ceiling row for this screen went 44 → 4, not 44 → 0, and the four
are right.** `retention_sweep`, `audit_chain_verify`,
`session_index_audit` and `session_index_repair` are cron job identifiers,
not prose — the same carve-out `chain_hash` and `seq` already have on the
chain-status screen. The gate's rows are values, not targets.

### Added — the skip links, from a key that existed for three releases

`admin/frame.rs`, `tenancy_console/frame.rs` and `tenant_admin/frame.rs`
each hardcoded `メインコンテンツへスキップ`. **`SkipToMainContent` has held
that string since RFC 077** and was already wired into the end-user chrome
(`templates/chrome.rs`), so the three admin frames were the divergent
ones, not the key. They now use the same shape, `escape(lookup(…,
locale))`, escaping included — not because the old constant was
injectable, but because three more raw-HTML splices should not depend on
us happening to own the value.

**This closes a claim `0.99.0`'s tag got wrong**: that the i18n gate
bounded the Japanese debt exactly. It did not — these three sat outside
it.

### Changed

- **The four RFC 161 placeholder screens share one key.** Each already
  names itself in its `<h1>`, so the body only has to say the status; four
  bespoke sentences would have been four translations written to be
  deleted when RFC 131 restores those screens.
- **One condition, one verb.** The overview's status-check failure reads
  `⚠ 状態の確認に失敗しました` / `⚠ Failed to check status` rather than
  *"could not check"*, joining the `失敗しました` / *"Failed to …"* family
  that `0.104.0` consolidated. A visible wording change in both locales,
  and the alternative was a fourth phrasing of one condition.
- **A generic error key, minted once.** `エラーが発生しました。` /
  *"An error occurred."* appears on this screen and again in
  `clients.rs`, which is the next slice's file; naming it now is what stops
  the second variant from existing. Its key says what its value says —
  the `Performer`-key/`Actor`-value lesson from `0.103.0`.
- **A title may be shorter than its heading, when the heading contains
  it.** `安全性チェック` ⊃ `安全性` and `cesauth オペレーターコンソール` ⊃
  `コンソール` both stay, each its own key, and the containment is a rule
  about wording rather than bytes.
- Thirteen Japanese doc-comment lines in the two converted screens are
  now English, matching `audit.rs` and `audit_chain.rs`, which were
  authored that way.

### Fixed — a test pinning a policy that had been retracted

`crates/frontend/tests/acceptance_harness.rs` asserted that the three
admin frames render Japanese-only *"per ADR-013"*, in a fixture comment
and in a test named after that ADR. **ADR-013 was amended on 2026-11-11 to
close exactly that deferral** — console multilanguage is now required —
so the harness was pinning a position the governing document had already
withdrawn, which is the same deferral-hardened-into-settled-law pattern
RFC 185 §2 found across nine documents. The citation is corrected: the
frames are JA-only because they still hardcode `<html lang="ja">`, the
amendment is named, and the test now says in its own panic message that it
inverts when RFC 185 reaches those frames. **The inversion is not done
here** — it belongs to the cut that converts the server-rendered admin
family, and reversing a policy pin should be that cut's deliberate act
rather than a red test someone meets under pressure.

### Security answer

The diff touches `crates/backend/src/routes/admin/`, which the release
rubric's path list names, so the question fires. **No new
security-relevant surface**, and this is what was checked: the seven
routes changed only which locale they hand to a helper whose
`resolve_admin` gate is untouched and still runs first; no route, query
parameter or payload moved (197 routes, 0 added, 0 removed);
`crates/backend/src/i18n.rs` is untouched, so `Accept-Language` is parsed
by the same code in use since `0.99.0`; and the skip link's new `escape()`
is hygiene, not a fix — the value it replaced was a compile-time constant,
so nothing was injectable before or after.

### Gates

Host tests **1,728 / 0 / 4 across 12 `test result:` lines** — unchanged,
because the nine new keys are covered by the completeness walk that
already enumerates every key, and no new test function was needed.
Migration chain **39**. Route surface **197, 0 added, 0 removed**.
`drift-scan` clean, i18n ceiling **103 scanned / 65 hit / 69 entries**.
Catalog **272 → 281** arms.

**Bundle, CI to CI**, with the code and the version bump again in separate
commits:

| commit | `Cargo.toml` | gzip |
|---|---|---|
| `eee448b` (`0.104.0` tag) | `0.104.0` | 904,062 B |
| `43f9da0` (this cut's code) | `0.104.0` | 904,471 B |
| `1c242b7` (`0.105.0` tag) | `0.105.0` | **904,367 B** |

**Code delta at the pinned version: +409 B.** **Absolute at the tag:
904,367 B, +305 B** over `0.104.0`, 34% of the 2,621,440 B budget. **The
version string accounts for −104 B** — down again, as it was by −144 B at
`0.104.0` and −829 B at `0.101.0`.

**CI ran 16 check runs on this release commit, not the usual 15, and the
sixteenth is not a gate.** `deny.yml` carries a daily `schedule:` beside
its `push:` trigger, and that scheduled run fired while `main`'s tip was
the release commit — `event: schedule`, same head SHA, `success`, a second
check run named `deny`. The release-workflow count is still 14 (15 check
runs, since `worker-build.yml` emits two jobs); **a release's check-run
total is that plus any scheduled workflow that happens to fire on the same
tip**, which is why the condition to wait on is a *stable* count with
nothing pending rather than a literal 15.

---

## [0.104.0] - 2026-11-15

**Minor** — the tenancy console answers `Accept-Language`, and so does the
shell that serves eleven operator screens. RFC 185 §5.3 screen 3, one
report-and-stop copy gate and one implementation round, both reviewed.

### Added — three more screens negotiate, through one chokepoint

`/admin/tenancy`, `/admin/tenancy/tenants` and
`/admin/tenancy/tenants/:tid` resolve their locale per request and render
every word from the catalog: **20 new `MessageKey`s**, both locales, and
nine existing keys reused rather than duplicated.

**Screens 1 and 2 each owned their route; the remaining eleven share one
helper.** `operator_json_api::shell` hardcoded `Locale::Ja` and took a
hardcoded Japanese title string from each caller. It now takes a
`MessageKey` and a `Locale` and composes
`format!("{} — cesauth", lookup(title_key, locale))`, the pattern the audit
viewer's route already set. **The locale stays a parameter rather than
becoming a negotiation**, because RFC 185 amendment A5 forbids serving a
still-Japanese body inside `<html lang="en">`: eight callers pass
`Locale::Ja` explicitly and will keep doing so until their own bodies
convert. Five of the console's thirteen shell-rendering screens now
negotiate, up from two.

Driven over real HTTP rather than asserted: `wrangler dev --local`, nine
requests, three routes × {`en`, `ja`, no header}, all `200`. `en` gives
`<html lang="en">` and *"Tenant management — cesauth"*; `ja` and no header
both give the Japanese form.

### Changed

- **Four of the eleven titles engage an existing key instead of minting a
  new one.** `ConfigTitle` was already byte-identical to its route's title;
  `OperationsTitle`, `TokensTitle` and `OidcClientsTitle` have their
  Japanese repointed to the live route's wording. Minting instead would
  have failed `no_two_keys_share_text_within_a_locale` outright for one
  (`"Operations"` was already taken) and produced case-only English splits
  no test can see for the others. **No user-visible change**: both
  components that read those keys (`OperatorShell`, `TenantAdminShell`) have
  no caller anywhere in the tree. The mockup wording they discard
  (`運用`, `管理者トークン`) is rowed for RFC 131, which owns adopting the
  mockups and can move heading, title and sidebar together.
- **The operator console's landing title is renamed, deliberately.**
  `cesauth コンソール` → `コンソール — cesauth` / `Console — cesauth`: the
  one title among eleven that did not fit the shape, left irregular by
  nobody's decision. Recorded while deciding it: that page has **three
  names** today — `コンソール` in the back link, `cesauth コンソール` in the
  title, `cesauth オペレーターコンソール` in its own `<h1>`. This settles the
  title; the heading waits for the cut that converts `console.rs`.
- **Two links that both point at `/admin/tenancy/tenants/new` are now one
  key.** Keying `テナント作成` and `新規テナント作成` separately would have
  minted two English names for one destination and made the confusion
  permanent in a second language.
- **One fetch failure, one wording.** The tenancy screens carried three
  phrasings of "could not load" against the catalog's own `FetchFailed`;
  the two generic sites now reuse it, and the count-specific message is
  re-registered to match its register in both locales rather than keep the
  split in English too.

### Fixed

- A catalog value carried a **trailing space** — faithfully reproduced from
  the literal it replaced, and invisible to review and to the duplicate-text
  test, which sees `"X: "` and `"X:"` as simply different strings. The
  separator now lives in the markup as its own text node.

### Security answer

The diff touches `crates/backend/src/routes/admin/`, which the release
rubric's path list names, so the question fires. **No new
security-relevant surface**, and this is what was checked:
`operator_json_api::shell`'s signature changed, but `resolve_admin` still
runs first and unchanged, so all eleven routes keep their admin gate; no
route, query parameter or JSON payload was added or removed (197 routes, 0
added, 0 removed); the only new input any of this reads is
`Accept-Language`, and `crates/backend/src/i18n.rs` is **untouched** by this
cut — three more routes now call a parser in use and unit-tested since
`0.99.0`; and the locale-negotiation evidence log carries no credential
material.

### Gates

Host tests **1,728 / 0 / 4 across 12 `test result:` lines** (`0.103.0`:
1,717; +11, all of them the title byte-identity tests) from the five-crate
command in `contributing.md` §Running tests. Migration chain **39**,
unchanged. Route surface **197, 0 added, 0 removed**. `drift-scan` clean,
i18n ceiling **103 scanned / 65 hit / 69 entries** with
`pages/operator/tenancy.rs` moving 27 → 0.

**Bundle, four CI measurements of the same workflow**, because this cut
happened to land its code and its version bump in separate commits and the
chain is worth keeping:

| commit | `Cargo.toml` | gzip |
|---|---|---|
| `4be0296` (`0.103.0` tag) | `0.103.0` | 903,469 B |
| `a260baa` (this cut's code) | `0.103.0` | 904,109 B |
| `314e092` (+ the review's one-space fix) | `0.103.0` | 904,206 B |
| `eee448b` (`0.104.0` tag) | `0.104.0` | **904,062 B** |

**Code delta at the pinned version: +737 B** (rows 1 → 3, version string
held constant). **Absolute at the tag: 904,062 B, +593 B** over `0.103.0`'s
own tagged figure, 34% of the 2,621,440 B budget. **The version string
alone accounts for −144 B** — it moved the bundle *down*, as a version
string did by −829 B at `0.101.0`, which is why the two figures are
reported separately rather than one being called the other.

And a floor worth recording: row 2 → 3 is **+97 B** for a change that
compiles to one `" "` text node and two catalog strings one byte shorter.
Even with the version held constant, sub-100-byte attribution is noise.

---

## [0.103.0] - 2026-11-15

**Minor** — the audit log can say who acted. RFC 187 across four rounds: a
classification stop-gate, two implementation rounds, and a documentation
round, each reviewed and accepted.

### Added — `actor`, distinct from `subject`

Migration `0021_audit_actor.sql` adds a nullable `actor TEXT` with a partial
index. `subject` answers *who the event concerns*; `actor` answers *who
performed it*. They were one column until now, and on the most destructive
operation in the product — `DeletionExecuted` — the acting admin's id
survived only as free text inside `reason` (`"admin-triggered by:{id}"`).
**"Which admin deleted this user?" was not answerable from the audit UI**,
one release after a cut devoted entirely to audit-chain integrity: `0.98.0`
hardened *that the record is intact*, and this is *what the record says*.

`actor` rides in the **hashed payload**, not only the indexed column —
`payload_hash` covers the serialized `Event` — so the column has evidence
behind it instead of being the one audit field editable without a trace.
**No backfill, ever:** `NULL` means *unknown* for rows below the migration
point and *no principal acted* above it, told apart by `seq` and never by a
sentinel value.

The operator console gains an **Actor** filter and column, under its own
`performed_by=` parameter — the pre-existing `actor=` has always filtered by
*subject*, and reusing it would have made bookmarked URLs silently answer a
different question. The filter is carried into the export form too: a screen
filter missing from that form downloads silently ignoring it, which already
happened once on this screen, to the date range. CSV and JSONL exports gain
an **appended** `actor` column — appended rather than placed in the readable
order, because a positional change breaks a spreadsheet silently.

### Changed

- **The audit viewer's two filter labels now say what the query does.** Both
  read *"(部分一致)" / "(substring)"* over SQL that has always been
  `subject = ?N` — an exact match. Now *"(完全一致)" / "(exact match)"*, and
  the port fields are `subject_exact` / `actor_exact` rather than
  `*_contains`. Two `MessageKey`s whose names said `Actor` while `0.102.0`
  had repointed their values at `Subject` are renamed to match their
  meaning, freeing those names for the real thing.
- **`AuditExported`'s own audit row names every filter applied** — event,
  subject, actor, from, to — where it previously named only the event kind.
  An audited export that cannot say *what was disclosed* is weak evidence.
  This closes **F-1** of `docs/src/expert/security-review-2026-q4.md`.
- `DeletionCancelled` and `DeletionExecuted` stop repeating the actor's id
  in `reason`; the column carries it, and each path keeps a
  `self-request` / `admin-triggered` / `sweep` marker so the *kind* of
  trigger is still a word rather than an inference from two columns.

### Fixed — documentation that stated things the code does not do

- **`storage.md` and `audit.rs`'s module doc both claimed the log is
  tamper-evident because "modifying any past row invalidates every
  subsequent `chain_hash`".** It does not: the indexed duplicate columns
  (`subject`, `client_id`, `ip`, `user_agent`, `reason`, `actor`) are not
  inputs to the chain hash, so a tamper confined to one of them passes
  verification. Found by the test this RFC required as *proof* of the
  opposite, which refuted its own prediction. ADR-010 — correct but
  implicit — now says it outright, and the remedy is stated as detection
  (compare each column against the payload's copy, treating an absent key
  as no claim) rather than prevention. Rowed as its own RFC; the gap
  predates this cut and none of it is introduced by `actor`.
- **22 of the 28 `EventKind` doc comments that describe a payload were
  describing a format that stopped existing at `v0.32.0`**, when the payload
  became the serialized `Event`: `user_id` is `subject`, `scheduled_at` is
  text inside `reason`, and `request_id` collided with the payload's *actual*
  RFC 036 correlation field. One was a plain wrong key —
  `RefreshRateLimited` documented `count`, and the code has written
  `window_secs` since `v0.37.0`. Four were verified accurate; two are rowed
  with RFC 123's declared-but-unemitted gate.
- `crates/backend/src/audit.rs` pointed operators at
  `docs/src/deployment/day-2-runbook.md` for the `v0.50.3` audit-purge
  procedure. That file was renamed to `runbook.md`; the procedure is at
  `runbook.md:499`. Closed RFCs keep the old path as the record of what was
  true when they shipped.

### Security answer

**Yes — this release is security-relevant**, and the path list
(`crates/core/src/audit`, `migrations/`, `routes/{oidc,me,magic_link,admin}`)
is not what makes it so; it is a new field recorded in an append-only log
that operators will read as *who did this*.

- **An attacker could have had the log name anyone.** Three sites on the
  public, unauthenticated magic-link endpoint pass the caller's own email
  as `subject`; the new field's default (`actor = subject`) would have made
  that unverified string the recorded actor, so anyone able to POST a
  magic-link request could write rows claiming `victim@example.com`
  performed an action. Those three now pass `actor: None`, and so do eight
  more sites where identity was not proven when the row was written: failed
  WebAuthn assertions, a failed magic-link verification, idle and absolute
  session timeouts, and an MFA lockout. The rule is written at the call
  sites and in `write_owned`'s own doc: **`actor` is `None` for a
  system-initiated transition or an authentication that did not succeed.**
  Found by enumerating all **127** write sites with a parser, not a grep.
- **Auth logic is unchanged.** Nothing in this cut alters who may do what;
  every change is to what is recorded. The one new input, `performed_by`,
  is bound through a `?N` placeholder on an endpoint already behind the
  system-admin gate, and the route surface is unchanged at 197 routes.
- **The record got stronger where prose was removed.** The actor id left
  `reason`'s free text for a hash-covered field plus an indexed column, and
  the screen that displays it shipped in the same cut — no release exists
  where the information is recorded but unreadable.
- The chain-integrity scope finding above is recorded as **F-7** in
  `security-review-2026-q4.md`; **F-3** (this RFC's own trigger) is closed.

### Gates

Host tests **1,717 / 0 / 4 across 12 `test result:` lines** (`0.102.0`:
1,706) from the five-crate command in `contributing.md` §Running tests;
migration chain **39** (35). Route surface unchanged — 197 routes, all seven
coverage figures identical. `drift-scan` clean, i18n ceiling 103/66/69
unmoved.

Bundle, CI to CI throughout — the only comparison this project accepts, after
a local raw-byte figure was once diffed against a CI gzip one inside this very
cut. **Code delta at the pinned version**: `0.102.0`'s 901,475 B → **903,428 B**
measuring this release's code with `Cargo.toml` still at `0.102.0`, **+1,953 B**.
**Absolute at the tag**, after the bump: **903,469 B** (892,770 wasm + 10,699
shim.js), **+1,994 B** over `0.102.0`'s own tagged figure — so **41 B of that is
the version string**, reported separately because a version bump alone has moved
this bundle by as much as 829 B before. 34% of the 2,621,440 B budget.

All **15** CI check runs green on the release commit (14 workflows;
`worker-build.yml` emits two jobs).

---

## [0.102.0] - 2026-11-12

**Minor** — new catalog surface, and a second route begins negotiating its
locale. RFC 185 §5.3 screen 2, two rounds, both reviewed and accepted.

### Added — the chain-status screen negotiates, and its badges are views now

`GET /admin/console/audit/chain` calls `resolve_locale`, and **both** of its
`lang` attributes follow it — the shell's `<html lang>` and the screen's own
`<main lang>`, which would otherwise have overridden the document for its whole
subtree. Driven over real HTTP: `wrangler dev --local`, three `curl -v` requests
with the body captured, all `200 OK` — `en` gives `<html lang="en">` and
*"Audit chain — cesauth"*, `ja` and no header give `<html lang="ja">` and
*"監査チェーン — cesauth"*.

This is the screen that reports audit-log tampering, and its status badges —
*"⛔ seq={n} で改ざんを検出"*, *"✗ seq の現在行と不一致（書き換えの疑い）"* — are
the words that tell an operator their audit log may have been rewritten. They
existed in one language with no catalog entry.

**31 new keys, and 4 strings that needed none.** Three fetch states and the
`Status` row label already had keys — the `Fetch*` family created for exactly
this purpose one screen earlier, and a bare `Status` key whose Japanese matches
this screen's word character for character. Finding those before writing
anything is what a key-list review is for.

**Two raw-markup sinks removed.** The badges were built as HTML strings and
injected through `inner_html`; they now return a class and a text, which `view!`
pairs natively. **No exploitable path existed** — the only interpolation was
`{seq}`, an `i64` — so this is two sinks removed from a security surface while
every line of both functions was being rewritten anyway, and nothing more.

### Changed — one label stops asserting something false

The audit viewer's subject filter and column were headed **"Actor"**. Measured
across **125** audit write sites, that column holds *who the event concerns*: the
acting principal for most kinds, but **the affected user** where the actor is a
background job or an admin acting on someone else. `AnonymousExpired` is emitted
by the 04:00 cron and has no human actor at all.

So *"Actor"* asserted agency that is false for those kinds, and the label is now
**"Subject"** — matching the type and the export header, which were right all
along. A label that can mislead is worse than a neutral one.

**That is the smaller half of what the investigation found.** Where actor and
subject differ, the actor survives only in free text: `DeletionExecuted` records
the deleted user while the acting admin's id sits on the line above, reachable
only as `"admin-triggered by:…"` inside `reason`. **So "which admin deleted this
user?" cannot be answered from the audit UI.** That is RFC 187, accepted, and
not in this release.

### Removed — the dead template, and a stale ceiling entry

`crates/frontend/src/admin/audit_chain.rs`, 281 lines and 6 tests, with no
caller. Cleared by the standing rule: zero callers, a host-test delta equal to
the deleted file's own test count, and no route-surface movement.

Its deletion also made a **ceiling entry stale** — the dead template carried a
count of 27 from `0.101.0`'s rebaseline, which had scored its own English. The
gate's stale-entry check caught it on the next run, and the entry was removed
rather than zeroed. **That rule had never before fired on a real entry**, only in
the synthetic test run to prove it could.

### Gates

Host tests **1,706 / 0 / 4** across 12 `test result:` lines, and the arithmetic
rather than the number: **+1** on the converted screen (two split error-message
tests merged into one locale-parameterised test, plus a locale-following test for
each badge function) **− 6** for the deleted template **= −5** from 1,711.
`route-contracts-check.sh` exit 0, **197 routes**, every figure identical.
`drift-scan.sh` clean — **103 scanned, 66 hit, 69 entries**, with
`pages/operator/audit_chain.rs` at **0**. `cargo check` warnings unchanged.

**Bundle, with the version string controlled for.** `0.101.0` established that a
seven-character same-length version bump alone moves this artifact by hundreds of
bytes, so the figures are given both ways. **Code delta: +1,415 B** measured with
the version pinned at `0.101.0` — 31 keys in two locales, and that is the figure
to quote for this release's code.

**Absolute after the bump: 901,768 B** (891,069 wasm + 10,699 shim.js), sha256
`dfb3a4c660223dee` / `f4ab4606e9cd7ccc` — `899,904 → 901,768`, **+1,864 B**. The
**449 B** between that and the code delta is the version string, and `shim.js`
moved by a byte (10,700 → 10,699) for the same reason. Reported both ways
because the naive figure attributes 1,864 B to 31 catalog strings when 1,415 of
it is theirs.

---

