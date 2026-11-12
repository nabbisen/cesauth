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

**v0.92.x and earlier are in [`docs/changelog-archive/`](docs/changelog-archive/README.md)**,
split by minor range and never edited after creation. This file holds
**0.93 and later**, 45 KB of the ~80 KB budget RFC 028 set — the 0.92 split at
the 0.95.0 cut took it from 74,482 B to 30,034 B, split to a floor rather than to
just under the ceiling.

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

Direction for the rule itself is in RFC 028's 2026-11-07 note: delete the
derived "~5 minor versions" figure, and build the gate Step 5 already specified.
**That note's §4 also records that RFC 028's diagnosis of `ROADMAP.md` is
wrong** — `## Planned (0.x)` is 93.3% of that file while `## Shipped`, the
section Step 3 says to archive, is 3.3%.

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

## [0.101.0] - 2026-11-12

**Minor** — a new gate condition changes what a contributor must satisfy to
merge. RFC 185 §5.2 round 2, two rounds, both reviewed and accepted. **The i18n
gate's zero now means something, and widening it found Japanese that had been
rendering unconverted since 0.97.0.**

### Fixed — the gate was certifying files it could not see

`0.99.0` shipped a gate that counted hardcoded literals per file against a
ceiling. `0.100.0` then demonstrated its blind spot: `<th scope="col">"Seq"</th>`
sat on a screen the gate scored `cjk 0 + en 0`, because the old rule required a
literal to be the entire trimmed content of its line.

The matcher is now a **two-mode lexer** distinguishing a Leptos `view!` quoted
text child from a server-side raw-string HTML fragment, because those hold text
in structurally different ways and need different defences. The result is
**1,013 counted literals against the previous rule's 210** — and the
discrimination kills the obvious false positive *structurally* rather than by an
exclusion list: Rust generics like `-> Result<` are never wrapped in quotes, so
requiring quotes in the Rust-literal mode makes them unmatchable. Zero of the
1,013 hits contain a `<` at all.

**Three previously invisible shapes now count.** A quoted text node sharing its
line with its own tags (150 hits — the `"Seq"` class). A text node spanning
several source lines, which is the dominant shape of the confirmation prose in
the tenant and tenancy form templates. And **CJK inside a raw-string HTML
template**, which closes a claim this project made and had wrong.

### Fixed — the Japanese skip links, and nine badges nobody could see

**`0.99.0`'s CHANGELOG and its tag message both claimed the gate bounded the
Japanese debt *"exactly, in any string literal"*. It did not.**

Three server frames — `admin/frame.rs`, `tenancy_console/frame.rs`,
`tenant_admin/frame.rs` — each render
`<a href="#main" class="skip-link">メインコンテンツへスキップ</a>` inside a
raw-string HTML template, where the quotes in `href` and `class` break the
`"[^"]*CJK[^"]*"` match. A skip link is an accessibility affordance, so this was
not a cosmetic miss.

Widening it then found a site nobody predicted: **the chain-status screen holds
nine hardcoded Japanese strings in raw-string HTML** —
`r##"<span class="badge">検証未実行</span>"##` and eight more status badges, at
`pages/operator/audit_chain.rs`. That is a CSR screen, not a server template,
and **those badges have been rendering unconverted since `0.97.0` shipped.**

**Correction, 2026-11-12, to this entry and to this release's tag message.**
Both originally said the nine badges were *invisible* to clause (a) and that
nobody could see them. **Clause (a) saw all nine** — as *markup fragments*.
Each badge is its own short raw string ending just after `</span>`, so
`"[^"]*CJK[^"]*"` spans from the quote closing `class="badge"` to the raw
string's own terminator and matches, angle brackets included. The genuinely
invisible case is the other one, which stands: the **three frames'** skip links,
where clause (a) really does score 0, because those raw strings continue past
the text with further quoted attributes so no fragment match ever closes. Two
cases were conflated and the wrong one was written down. **What survives is the
substantive claim** — the badges were unconverted for four releases — and
"counted as a markup fragment" is a poor kind of seen.

**And the totals in this entry overcount.** Where both clauses reach the same
literal — CJK inside a short raw-string fragment, or a quoted node carrying both
scripts — it is counted twice. On the chain-status screen the ceiling reads 55
for **41** distinct literals. **The gate is unaffected as a gate**: adding a
literal raises its file's count, removing one lowers it, and converting a file
drives it to 0, so it stays monotonic and the ceilings keep their force. `1,013`
is a count of matches, not of distinct strings, and should be read as such.

**All of it is counted. None of it is converted** — that is the next screens'
work, and this release deliberately changes no rendered text.

### Changed — the ceiling table, rebaselined

**70 entries, 68 files hit.** Every file that moved, moved up: the measurement
changed, not the tree, and no literal was added or converted here. Three new
false-positive classes surfaced while implementing the cross-line join and were
fixed at the source — `<script>`, `<style>` and `<pre>` bodies are stripped,
since code and preformatted content are never prose by HTML's own semantics.
Inline `<code>` was deliberately **not** stripped, because doing so would have
silently reversed a decision review had just taken.

### Gates

Host tests **1,711 / 0 / 4** across 12 `test result:` lines — **unchanged**, as a
release touching one shell script must leave them.
`route-contracts-check.sh` exit 0, **197 routes**, every figure identical.
`drift-scan.sh` clean: **104 files scanned, 68 hit, 70 ceiling entries, 0
violations, 0 stale.** `cargo check` warnings unchanged at 8 (frontend) and 1
(core).

**What the gate still does not see, because the number reads stronger than it
is**: a tag's own attribute value, in either language — a CJK `aria-label=` would
escape exactly as an English one does, for the same mechanical reason that an
attribute lives inside a tag's angle brackets and is not a text node — and, in
Rust-literal mode, an all-lowercase unpunctuated sentence, indistinguishable
from a CSS class list by shape alone. **A ceiling of 0 is still not a synonym
for "converted".**

### Measurement note — a bundle delta is not what this project has been reporting

Worker bundle **899,904 B** gzip at default level (889,204 wasm + 10,700
shim.js), sha256 `4d1a50c22917c598` / `3054bf5b78fd04ea` — **900,733 → 899,904,
a decrease of 829 B on a release whose only compiled-input change is the version
string.**

That is not an anomaly to wave at, so it was run down. The build **is**
deterministic: two consecutive builds of this tree are byte-identical, and
`cf34d37`'s tree rebuilt in an isolated worktree reproduces `0.100.0`'s recorded
figure exactly, sha included. And `git diff cf34d37 -- crates/ Cargo.toml
Cargo.lock` shows **nothing under `crates/`** — only `0.100.0` → `0.101.0`.

The decisive test: `cf34d37`'s tree **with only the version string changed**
builds a wasm **byte-identical** to this release's, sha `4d1a50c22917c598`. So a
seven-character, same-length version string moves the gzipped artifact by
**829 B**, in this instance downward.

**The consequence for the record**: a bundle delta below roughly a kilobyte
cannot be attributed to a release's code without controlling for the version
string, and tag messages in this project have been attributing deltas of exactly
that size. The `0.96.0` entry put this effect at **+16 B**; it is two orders of
magnitude larger than that. The control is cheap and is now known — rebuild the
previous tag's tree with the new version string and diff against *that*, not
against the previous tag's published number.

---

## [0.100.0] - 2026-11-11

**Minor** — the audit viewer is **the first screen in this project whose language
follows the request**. RFC 185 §5.3 screen 1, two rounds, both reviewed and
accepted.

### Added — locale negotiation, reaching a screen for the first time

`GET /admin/console/audit` calls `resolve_locale` instead of passing a hardcoded
`Locale::Ja`, and `mounted_locale()` — written, tested, and uncalled since it was
added — **has its first caller**. An `Accept-Language: en` operator gets the
screen in English, a `ja` operator in Japanese, and a request with no header
falls through to the default.

**Driven over real HTTP**, not inferred from a compile: a `wrangler dev --local`
instance with migrations applied, three `curl -v` requests, all three `200 OK` —
`en` → `<html lang="en">` and `Audit log — cesauth`; `ja` and header-absent →
`<html lang="ja">` and `監査ログ — cesauth`.

**Both `lang` attributes move together.** The screen also carried
`<main lang="ja">`, and an element-level `lang` overrides the document for its
whole subtree — so flipping only `<html lang>` would have served a document
claiming English with every word still announced as Japanese, strictly worse
than the truthful literal 0.99.0 preserved. There is no build-time signal for
getting that wrong.

### Changed — 24 literals onto the catalog, and three labels corrected

All 24 of the screen's hardcoded Japanese literals now resolve through
`lookup(MessageKey, Locale)`. **Eighteen of them reuse keys that already
existed** — written in both locales for this exact screen, and still called by
the server template it replaced.

Three labels revert to that template's wording, each on its own evidence.
`時刻` becomes `時刻 (UTC)`: a timestamp column with no unit, against RFC 111's
own UTC presentation policy. `詳細` becomes `Reason` and `イベント` becomes
`Event`, because the export CSV the operator downloads **from that same screen**
writes `seq,timestamp,kind,subject,client,reason` — two columns had been renamed
away from the file's own headers, in one commit, with no record. A fourth,
`"Seq"` → `"seq"`, followed at review for the same reason.

Five new keys, three of them deliberately **screen-neutral** — `FetchLoading`,
`FetchFailed`, `FetchUnauthorized`. Those strings are already hardcoded in three
to five operator screens, and scoping them to this one would have forced each
later conversion to add the same sentence to the catalog's duplicate-text
exception list under a new name. That list exists for concepts legitimately
shared between surfaces, not to excuse duplication.

### Removed — the 545-line template, once parity was measured

`crates/frontend/src/admin/audit.rs` and its `pub use` are gone. The deletion was
**held back a round**: the first parity measurement came out **17 of 18**, because
one column header still bypassed the catalog. That bar was met rather than
relaxed, and the second measurement reads 18 of 18.

The deletion is evidenced, not asserted: host tests fall by exactly **12**, the
deleted module's own test count. Had anything outside that file depended on
`audit_page`, the build would have failed to compile rather than quietly passing.

### Gates

Host tests **1,711 / 0 / 4** across 12 `test result:` lines — **+1** for the new
locale test, **−12** for the deleted module, net −11 from 0.99.0's 1,722.
`route-contracts-check.sh` exit 0, **197 routes**, every figure unchanged: the
deleted template was never route-registered. Route surface **197 pairs, 0 added,
0 removed**. `drift-scan.sh` clean, 10 sections; the i18n ceiling scans **104**
files, **15** hit, and `pages/operator/audit.rs` is pinned at **0**.
`cargo check` warnings unchanged at 8 (frontend) and 1 (core).

**Known limit of that ceiling, stated because the number reads stronger than it
is**: the matcher sees Japanese in any literal, but English only where a literal
is a standalone `view!` text child. A `0` therefore means "no Japanese, and no
standalone English" — not "fully converted". This screen demonstrated it: the
`"Seq"` header shared its line with its own tags and the gate read the file as
clean while it was still there.

---

## [0.99.0] - 2026-11-11

**Minor** — it adds a new CI gate, which changes what a contributor must satisfy
to merge. **Nine documents and a code comment stated an "admin console is
Japanese-only" policy as settled law; none of them was a check, and the hardcoded
literal count rose in each of the last three releases with nothing watching it.**
RFC 185 §5.2, the true half of §5.1, and §5.4.

### Added — a literal gate, so the rule finally has a check

`scripts/drift-scan.sh` gained a tenth section. A natural-language literal in
`crates/frontend/src/{pages,components,admin,templates,tenancy_console,tenant_admin}`
is counted per file and compared against a **per-file ceiling that may only go
down** — 18 entries summing to 210, with **105 files scanned and 16 hit** on the
shipping tree.

Four conditions fail the build, and **all four were driven**: a file over its
ceiling (Japanese and English each shown separately); a file **below** its
ceiling, which must be lowered rather than left as slack; a ceiling naming a file
that no longer exists; and **a file the matcher hits with no ceiling entry at
all** — the case a baseline table usually waves through, and the reason a new
screen arriving with forty literals cannot pass unlisted.

A ceiling rather than an exemption list, because a 210-entry list of literals
would be edited by the very commits meant to police it. Test code is out of scope
by construction — 31 of the frontend's Japanese strings are catalog assertions,
and a gate that fires on those is a gate that gets deleted.

**What the gate does and does not see, stated plainly.** It bounds the **Japanese**
debt in any *quoted Rust* string literal, in all six directories. It bounds the
**English** debt only where a literal is a standalone `view!` text child — in
practice `pages/` and `components/`.

**Correction, 2026-11-12.** This paragraph originally claimed the gate bounds the
Japanese debt *"exactly, in any string literal"*. **It does not**, and the
counter-examples were found while widening the matcher for 0.101.0:
`admin/frame.rs:219`, `tenancy_console/frame.rs:171` and
`tenant_admin/frame.rs:213` each render
`<a href="#main" class="skip-link">メインコンテンツへスキップ</a>` inside a
raw-string HTML template, and clause (a) scores **0** on all three — the quotes
in `href="#main"` and `class="skip-link"` break the `"[^"]*CJK[^"]*"` match. Three
rendered Japanese strings, on three server frames, and a skip link is an
accessibility affordance. The 0.101.0 cut closes it. **English prose inside a `format!` HTML
template is invisible to it**, which is how the server-rendered directories are
written. Two further blind spots were found and disclosed rather than regexed
away: the class-name exclusion drops exactly four literals repo-wide, two of them
real CSS class names and two of them genuine English sentences in
`admin/safety.rs` — the whole class, enumerated, not sampled.

### Changed — the shell's locale is a type, not a string

`leptos_html_shell`'s `lang: &str` is now `lang: Locale`. A call site can no
longer emit a language tag that no catalog locale corresponds to, and the shell's
emission and `mounted_locale()`'s parse share one vocabulary by construction
rather than by both happening to spell `"ja"` the same way. Previously a typo in
any of the ten literals would have produced a silently wrong locale with no
compile error, no warning and no log line.

All ten call sites and both `shell()` wrappers pass **the locale their content is
actually written in — values unchanged**.

**`<html lang>` is still not negotiated from the request, and that reverses what
RFC 185 proposed.** `<html lang>` is a claim about what language the content is
in. Every CSR surface is monolingual today *and* its literal names that language
correctly, so negotiating it would make the attribute false for exactly the users
who stated a preference. The flip belongs to the per-screen conversion, in the
same commit that gives a screen more than one language to serve. **No screen's
rendered language changes in this release.**

### Fixed — the two literals that both render and lie

`templates/security_center.rs` hardcoded `aria-label="セッション {sid}"` and
`templates/totp.rs` hardcoded a save-confirmation legend, both inside functions
where `locale` is already a parameter and where every neighbouring string goes
through the catalog. Both are **server-rendered** surfaces, which negotiate: an
`Accept-Language: en` request received the whole screen in English and these two
elements in Japanese — announced by a screen reader, invisible on screen. The
second carried a comment excusing itself (*"end-user route is also fine with short
literal"*).

Verified as a build-time property: the literals are gone and the new keys resolve
non-empty in both locales. **Not** verified by rendering either page and listening
to a screen reader — `trunk` cannot be installed in this environment.

### Fixed — the record

ADR-013's i18n-3 deferral is **closed**. Its own trigger was *"if/when demand
surfaces"*, and the owner supplied it. It was never a decision that the console
stays Japanese-only; it was a deferral with an exit condition that stopped being
quoted somewhere around RFC 072, which calls it a *constitution* and derives a
permanent `<html lang="ja">` from it — now annotated with its own lineage.

`operator_shell.rs` attributed the locale policy to **RFC 034**, which is
*introspect handler wiring* and contains no mention of locale. Corrected in
**two** places, not the one the handoff named.

### Gates

Host tests **1,722 / 0 / 4** across 12 `test result:` lines (**+1**).
`route-contracts-check.sh` exit 0 with **every** figure unchanged from 0.98.0 —
197 routes, E3 47, GATE_42 24, NONCE 13, E4 219, E5 19, E6 95, E7 156 — as a
release that touches no route should leave them. Route surface **197 pairs, 0
added, 0 removed**. `drift-scan.sh` clean, now 10 sections. `cargo check`
warnings unchanged at 8 (frontend) and 1 (core).

---

## [0.98.0] - 2026-11-11

**Minor, earned** — it adds `POST /admin/console/audit/chain/acknowledge`, a new
route surface. **A `ReadOnly` admin could erase the audit log's tamper alarm with
one button press, and nothing recorded that they had.** RFC 184, in full.

### Security — the tamper alarm is no longer erasable

`POST /admin/console/audit/chain/verify` justified gating on
`AdminAction::ViewConsole` with its own comment: *"a full re-walk is a
non-destructive read operation … an attacker who triggers it gains nothing."*
**The reasoning about information was right; the claim about state was false.**

`verify_chain_full` called `write_last_result` **unconditionally** into a single
slot whose own port documentation says it exists *"so the admin UI surfaces the
alarm"*, then advanced the checkpoint whenever the fresh walk said `valid`. So:

1. The 04:00 cron detects tampering and stores `valid=false,
   first_mismatch_seq=N`. The console shows `⛔ seq=N で改ざんを検出`.
2. Anyone who can open the console presses **Verify chain now**.
3. If the chain has since been rewritten *consistently* — what a
   wholesale-rewrite attacker produces, and what the checkpoint cross-check
   exists to catch — the alarm is overwritten with `valid=true` and the recorded
   baseline `chain_hash` is replaced.

**And `role_allows` returns true on `ViewConsole` for every role, `ReadOnly`
included** — the role whose name promises it cannot change anything — while
`ManageAdminTokens` is `Super`-only.

**Reproduced before it was fixed**, over real HTTP against a freshly-migrated
local D1 and KV, with tokens minted at `role=read_only` and `role=security`
through the real route, the tamper applied **directly to the database** below the
application layer, and the real `__scheduled` cron entry point. The finding
reproduced exactly.

Now:

- **A detected mismatch is sticky.** An unacknowledged `valid=false` survives any
  later run. A hash-chain mismatch means rows were altered — it is not a
  transient condition a retry can clear, so "press until green" is no longer a
  move. A later run that is **also** invalid still overwrites with fresher
  numbers, so the cron can always report a *new* mismatch.
- **No re-baselining over a standing alarm.** The checkpoint does not advance
  while an unacknowledged alarm is stored, however clean the new walk looks.
- **Acknowledgement is a separate, tiered, audited act.**
  `POST /admin/console/audit/chain/acknowledge`, gated on the new
  `AdminAction::AcknowledgeTamperAlarm` — `Security | Operations | Super`, the
  same row as `VerifyBucketSafety`, and **not** `ReadOnly`. CSRF required.
- **Both routes now write audit events.** Previously neither did, while merely
  *viewing* a console page wrote one.

### Security — a refused clean walk is itself evidence, and it is now recorded

Stopping the erase was not sufficient. **A standing alarm at seq N plus a fresh
full walk that verifies clean is the signature of a wholesale rewrite**, and the
first implementation computed that second half and threw it away: the refusal
returned the stored alarm, so the audit row reported the previous *incremental*
run's numbers — `rows_walked=1` for a full re-walk of a six-row chain — and
"the walk found the tamper again" became byte-identical to "the walk found it
clean and the write was refused".

Both paths now record it. The operator's audit detail carries
`refused_clean_walk=true` with the fresh walk's own verdict beside the standing
alarm's. And because the nightly cron has no principal to carry an audit write,
the refusal is also stamped durably onto the stored record as
`clean_walk_refused_at`, with an error-level log line for anyone watching live.
Without that, a rewrite would make every subsequent nightly run compute
`valid=true` forever and leave no trace at all.

### Fixed — the route's documentation, and a contract claim that was never true

The module comment no longer teaches the next reader that a full re-walk is a
non-destructive read. And `route-contracts.md` claimed this route emitted audit
kind `audit_chain_verified`, **an `EventKind` that has never existed**; it now
names `admin_audit_chain_verified`, which is emitted, with a new row for the
acknowledge route. That claim was one of **15 of 42** audit kinds in that column
naming a string the code does not produce — the other 14 are tracked.

### Gates

Host tests **1,721 / 0 / 4** across 12 `test result:` lines (**+11**).
`route-contracts-check.sh` exit 0, **all 197 routes documented**, E4
**219 = 195 (184+11) + 24 + 0**, E6 **95 = 86 (66+0+20) + 9 + 0**, E3/GATE_42/
NONCE/E5/E7 unchanged. Route-surface census **197 pairs — 1 added, 0 removed**,
the pre-stated delta met exactly. `migration_chain` **35**. mdbook **82 pages**.

### Upgrade note

`AuditVerificationResult` gained two fields, both `#[serde(default)]`. A
`chain:last_result` blob written by an earlier release has neither, and reads as
*not acknowledged* with *no refusal recorded* — the only safe reading of silence.
No migration, no manual step.

---

## [0.97.0] - 2026-11-11

**Minor, earned** — it adds `GET /admin/console/audit/chain.json`, a new route
surface. **An operator can see whether the audit log's hash chain verifies, and
trigger a re-verification, from the console.** And the audit export now gives
them what they asked for: **it had been dropping the date range they set, and
returning 50 rows out of 276 while recording that nothing was dropped.**

### Added — chain status (RFC 131 §0 slice 2, the second of six)

`GET /admin/console/audit/chain` served the Leptos shell and nothing else, with
a CSR stub that said so honestly. Behind it, `read_status` — 30 lines of
finished data assembly — had **no caller at all**, and `cargo check` had printed
`function read_status is never used` on every build since `580eeba`.

- **`GET /admin/console/audit/chain.json`** — the new route, calling that
  function. `AuditChainStatus` already derived `Serialize`.
- **A CSR component** replacing the stub: verification status, checkpoint, the
  growth hint, and the verify-now form. All **five** status badges and all
  **three** checkpoint-consistency states are pure functions, individually
  host-tested — four of the five badges are how an operator learns the audit log
  was tampered with.
- **`POST /admin/console/audit/chain/verify` has a caller for the first time.**
  The route has been live, CSRF-verified and role-checked for releases, and
  **nothing in the workspace posted to it.** Exercised now against a genuinely
  empty D1 (checkpoint created from nothing) and against a 268-row chain
  (checkpoint moved 211 → 268, full re-walk inside the Worker's budget).
- **RFC 161 §6.3's two controls restored** on the page handler, as slice 1 did:
  the `ViewConsole` role check and the `AdminConsoleViewed` audit write.

### Fixed — the audit export silently returned 50 rows and recorded that it had not

Found by reading the implementation report's own evidence table, which called 50
*"the export's own default row cap"*. **That cap is 10,000.**

The chain: the handler read `limit` from the form; no export form has ever sent
one; `AuditQuery`'s derived `Default` left it `None`; and
`CloudflareAuditQuerySource::search` then applied its own `DEFAULT_LIMIT = 50`
— a constant documented as *"default page size for the admin overview"*. Then
`export_audit` computed `truncated = rows.len() > max_rows`, i.e. `50 > 10_000`,
and so **set no truncation header and wrote `truncated=false` into the audit
record**.

**An operator exporting a 276-row log received 50 rows, in a file that looked
complete, with an audit record asserting nothing was dropped.** True since
v0.71.0 and unreachable until 0.95.0 rendered the first working export form.

Fixed in the handler, so the ceiling lives in one place. The default is
`max_rows + 1`, **not** `max_rows`: `export_audit` detects truncation by seeing
one row past the ceiling, so capping the query at exactly the ceiling would have
left `truncated` permanently false — the same lie one layer down. Now: 276 rows
with `truncated=false`, and `AUDIT_EXPORT_MAX_ROWS=5` gives 5 rows with the
header set and the record agreeing. **That truncation path had never run.**

`limit=0` no longer resolves to an empty export, and the ceiling's `as u32` cast
saturates instead of wrapping.

### Fixed — the export dropped the date range the operator set

The CSR export form sent `csrf`, `subject` and `event`; the handler reads
`since` and `until`. So narrowing to a period, seeing that table and clicking
**Export CSV** downloaded everything, with nothing on screen saying the period
had been dropped — and the export's own audit record built its `filter=` string
from the event alone, so the record did not show it either.

Both fields are now sent, converted through the same `parse_rfc3339_to_unix`
the `.json` query already uses, so the screen and the export compute identical
bounds from identical input.

**RFC 131 slice 1's parity table claimed this form carried "the same four hidden
fields plus `csrf`".** It did not, and the claim was accepted at review.

### Fixed — "cold start" was shown on a chain that was not cold

After a verify-now, the checkpoint badge read *"cold start — no cross-check"* on
a store with 268 rows and a fresh checkpoint. `checkpoint_consistent: None` has
two causes — no checkpoint has ever existed, or one exists and the last run was
a full re-walk, which `core::audit::verifier` skips the cross-check on **by
design**. The verifier was right; the label conflated them. It now distinguishes
them using `checkpoint_seq`, which was in the same payload all along.

The server-rendered template has the identical bug and is not touched; this is a
deliberate improvement over the specification, as slice 1's `csrf` field was.

### Fixed — the chain-status screen was Japanese at the edges and English in the middle

Surfaced by the implementer after the fact: **8 Japanese literals against 44
multi-word English ones.** Japanese covered only the chrome — title, back-link,
loading, errors — while every badge, table header, section heading and the
verify-now copy was English, carried over from the server-rendered template. The
screen is now in the same register as every other console page (**47** Japanese
literals; no operator-facing English prose), with `chain_hash` and `seq` left in
English as data identifiers.

### Gates

Host tests **1,710 / 0 / 4** across 12 `test result:` lines (**+23**).
`route-contracts-check.sh` exit 0, **all 196 routes documented**, E4
**218 = 194 (183+11) + 24 + 0**, E5 **19**, E3/GATE_42/NONCE/E6/E7 unchanged.
Route-surface census **196 pairs — 1 added, 0 removed**, the pre-stated delta
met exactly. `migration_chain` **35**. mdbook **82 pages**. **Backend dead-code
warnings 8 → 7**: `read_status` has a caller at last.

---

## [0.96.0] - 2026-11-10

**Minor by default, not earned** (RFC 181) — nothing newly possible, no route,
type, knob or caller obligation moved. A patch argument was available for both
halves and deliberately not made. **This release ships an assurance experiment
whose verdict is "do not adopt", and a security advisory cleared the day it
appeared.**

### Added — RFC 183's Verus pilot, and its rejection

**A machine-checked proof of RFC 4226's dynamic truncation, over all 2^160
HMAC-SHA1 outputs** — `verification/totp_truncation.rs`, verified with
[Verus](https://github.com/verus-lang/verus) `0.2026.07.27.31579f0`:

- **`offset + 3 < 20`** — no index in `compute_code` can panic. It sits on the
  live MFA path (`routes/me/totp/verify.rs:343`), once per skew step, so a panic
  there would 500 every TOTP verification.
- **`bin_code < 2^31`** — the invariant `& 0x7f` exists to establish, stated
  nowhere in the code until now.

Neither follows from the masks alone; both needed an explicit
`by (bit_vector)` lemma. **No production code changed** — `crates/core/src/totp.rs`
has zero bytes of diff since `0.95.0`. The three RFC 6238 vector tests that
previously covered this could only ever sample the space.

**`scripts/drift-scan.sh` gained one check**, because the proof is about a
*copy*: Verus needs its own `verus!{}` toolchain and cannot see through
`hmac`/`sha1`. A copy that drifts verifies fiction, and this project already
paid for that class once (RFC 171 Q1's dead match arm with a green suite). The
check byte-compares the copy's marked region against `totp.rs:253-257` and fails
loud both ways: **exit 1** on divergence, printing both blocks; **exit 2** if
production's anchor line moves at all, rather than skipping silently.

**The verdict is reject, and a clean rejection was always a legitimate outcome
of this pilot** — RFC 183 §5 said so before it ran. Verus worked, in 0.42
seconds. What it costs is a permanent out-of-workspace copy plus 85 lines of
gate that can police only the *text*, with the re-verification left to a human
because Verus is deliberately **not** in CI. The assurance decays the moment
someone edits the copy and does not re-run it, and nothing can notice.

**Two things recorded so nobody cites this pilot wrongly:**

- **`3 verified, 0 errors` does not witness the second obligation.** Delete the
  `ensures` and it still prints `3 verified, 0 errors`, because the count is
  *(number of `by (bit_vector)` blocks) + 1 for the function body*. What
  witnesses both obligations is weakening the masks: `& 0x7f` → `& 0xff` fails
  the postcondition, `& 0x0f` → `& 0x1f` fails a bounds precondition.
- **"Prefer Kani" is a hypothesis, not a finding.** `kani-verifier`'s install
  was refused outright by the implementer's sandbox policy, so nothing
  comparative was measured. The trial is scheduled, and either outcome deletes
  `verification/` and this check.

### Security — RUSTSEC-2026-0459 cleared the day it reddened CI

`rusqlite 0.32 → 0.41.1`, lifting `libsqlite3-sys 0.30.1 → 0.39.1` past the
advisory's `>= 0.39.0` requirement — C SQLite **CVE-2026-119375**.

**No cut caused it**: the advisory database updated `2026-11-09 17:13 UTC`,
which is why `0.94.0` was 14/14 green and `0.95.0`'s `audit` and `Cargo deny`
jobs went red against identical dependency code.

**Not exploitable here, for two independent reasons, each verified rather than
assumed** — and fixed properly anyway rather than exempted:

1. `cargo tree -i libsqlite3-sys` reaches it **only** through `rusqlite` under
   `cesauth-migrate-test`'s **dev-dependencies**. It is in no Worker build and
   no shipped artifact; the Worker uses D1, not a linked SQLite.
2. The advisory's own precondition is *"a process that opens a database file,
   with its `-wal`, that a less trusted party could have written"*, and
   `migrate-test` runs the migration chain against an **in-memory** database.
   No file, no WAL.

`cargo update -p libsqlite3-sys` alone could not reach the fixed version (0.32
pins 0.30.x) and `rusqlite 0.37` only reached 0.35.0, so the bump had to go to
0.41.1.

**The artifact does move, by 67 B** (893,600 → 893,667), because
`thiserror 2.0.18 → 2.0.21` rides along as a workspace dependency. Disclosed
rather than described as artifact-neutral.

### Gates

Host tests **1,687 / 0 / 4** across 12 `test result:` lines, unchanged.
`migration_chain` **35**. `route-contracts-check.sh` exit 0, **all 195 routes
documented**, every sub-figure identical to `0.95.0`. Route-surface census
**195 pairs — 0 added, 0 removed**, which is the independent confirmation that
`verification/` reaches no build: it carries no `Cargo.toml`, so unlike `fuzz/`
it is not a package at all and needs no workspace `exclude`. mdbook **82 pages**.

---

## [0.95.0] - 2026-11-10

**Minor, earned** — it adds `GET /admin/console/audit.json`, a new route surface.
**An operator can browse and export the audit log again.** Both halves of that
feature had existed and been tested for releases; only the call between them was
missing, and it had been missing since `580eeba`.

### Added — the audit browser (RFC 131 §0 slice 1, the first of six)

`GET /admin/console/audit` served the Leptos shell and nothing else — a module of
**704 bytes** whose own doc comment admitted a prior spec *"describ[ed] a search
feature that was never built."* `cesauth_core::admin::service::search_audit` had
**no production caller**. The 545-line `audit_page` view had none either.

- **`GET /admin/console/audit.json`** — the new route, calling `search_audit`.
- **A CSR component**, `ConsoleAudit`, routed at the existing
  `/admin/console/audit` path. Filter form (actor / event / period), results
  table, pager, and the export form.
- **Pagination and filtering exercised end to end** against a live server with
  local D1: two cursor pages (100 + 100 entries, `seq` descending), and an
  event filter returning 39 of 265 rows.

**`audit_page` is deliberately not deleted.** RFC 131 R4 says each slice deletes
its template and that is right — but deleting a 545-line specification on the
strength of its own replacement author's parity judgement is backwards. Parity
is recorded per section (nav, filter form, export form, schema note, results
table, pager) and the deletion is a reviewed decision, not a side effect.

### Fixed — the reference implementation's export form could not have worked

`render_export_form` renders **no `csrf` field**, and the entire 545-line file
mentions `csrf` once — in a comment claiming *"the export POST handler validates
separately."* It does (`audit_export.rs:32-34` reads `get("csrf")` and calls
`csrf::verify`), **and the form supplied nothing to validate.**

So **RFC 161's own claim that *"the only form that posts to it"* carries *"the
`csrf` field it requires"* was false.** Proven both ways against a live server:
**400** reproducing the reference form, **200 with 39 real rows** from the new
one, which binds the token the `.json` endpoint returns.

**Worth recording because it vindicates a decision**: RFC 131 §0 declined
re-pointing the handlers at the existing server views. Had this slice taken that
path, **the export button would have been broken on arrival.**

### Fixed — console page views are audited again, and the record that said otherwise was wrong

`EventKind::AdminConsoleViewed` is emitted again, from the page handler. Before
this release the variant carried a dated comment reading:

> **RFC 154.** Intentionally unemitted: a decision not to audit, not a gap.

**That comment was wrong, and git says so.** Immediately before `580eeba` the
event was emitted from **eight or more sites** across the console —
`console/alerts.rs`, `console/audit.rs`, `console/config.rs` twice, and others.
`580eeba` ("old string templates removed") deleted every one of them along with
the handler bodies it replaced with a bare shell. **RFC 154's back-fill came
afterwards, found an unemitted variant, and recorded a regression as a
decision.** The comment now names both RFCs and the reversal.

**The five other variants carrying the same claim were checked and are
accurate** — `AuthSucceeded`, `SessionCreated`, `SessionExpired`,
`WebauthnFailed`, `SessionStarted`: `git log -S` finds **no commit that ever
emitted any of them**. `AdminConsoleViewed` was the only mislabelled one,
precisely because it alone had once been emitted.

**Written on the page view, not on every `.json` fetch.** A filter submit or a
pager click is continued use of an already-recorded view; writing on both would
log a row per pagination click, which is the one part of RFC 154's objection that
was right. Verified: the count stays at **1** across three subsequent `.json`
requests.

### Added — the `ViewConsole` authorization check, and what it is actually worth

`ensure_role_allows(AdminAction::ViewConsole)` now gates both the page and the
new JSON route, via `require_system_admin!`. RFC 161 §6.3 listed this as a
dropped control alongside the audit write.

**Stated precisely, because it would be easy to overstate**:
`every_role_may_view_console` asserts `role_allows(r, ViewConsole)` for **all
four roles**, so **this check denies nobody today.** The console was already
authenticated — `operator_json_api::shell` resolves an admin principal or
rejects. This is defence in depth and an explicit gate for a future, more
restricted role; **it closed no live authorization hole.**

`operator_json_api::shell`'s contract was **not** widened. It discards the
resolved principal, and changing it would hand the role check and the audit
write to five not-yet-built consoles unreviewed.

### Known gaps

- **This screen ships unstyled**, and that was scoped rather than discovered.
  The CSR app's only stylesheet is `base.css` with one `.sr-only` rule
  (RFC 179); its §8 import owns the rest. The census rose **136 → 139**
  (`secondary`, `note`, `num` — three new literal class names, zero new computed
  sites), reported rather than suppressed, with `DECLARED_STYLED` untouched.
- **The component has never been mounted in a browser.** `trunk` cannot be
  installed on the development machine (`libdeflate-sys` against GCC 16.2.1), so
  its rendering, reactivity and UI interactions are **`unknown`** — not
  `observed`. Everything it depends on *is* exercised: the endpoint, both cursor
  pages, the filter, the audit write and the export round-trip, all over real
  HTTP. Only CI's `Trunk release build` touches the browser path.
- **The results table shows raw Unix timestamps**, reproducing the reference
  view rather than improving on it. Not this slice's job.
- **Twenty `api_v1` routes still claim `N/A (bearer)` while resolving through a
  cookie-accepting path** — RFC 152 half C, dated and staleness-checked.
- **`ROADMAP.md` is ~190 KB against RFC 028's 40,960 B budget**, with
  `## Planned (0.x)` at 93% of the file.
- **Eleven of the book's eighty pages remain absent from `SUMMARY.md`.**

### Bundle

Measured after the version bump, gzip **at its default level** (not `-9`):

| file | raw B | gzip B | sha256 (first 16) |
|---|---|---|---|
| `…-index_bg.wasm` | 2,445,081 | 882,900 | `cfc32f9f73138d98` |
| `shim.js` | 61,887 | 10,700 | `d4809d0a6a5638b2` |
| **Worker total** | | **893,600** | |

**+3,418 B from `0.94.0`'s 890,182** — the new route handler, the audit-write
call and the rewritten doc comment, all compiled into the Worker regardless of
the `csr` feature. The CSR component itself does **not** reach this bundle
(`components`/`pages` are `#[cfg(feature = "csr")]`, which the Worker never
enables). `wrangler deploy --dry-run` requires `crates/frontend/dist` to exist;
an **empty** one was created to measure, sound only because `LEPTOS_JS` and
`LEPTOS_WASM` are hardcoded consts (`leptos_shell.rs:85-86`).

---

## [0.94.0] - 2026-11-09

**Minor** — RFC 181's default. **The last unbuilt check of RFC 168 now exists**,
and building it found **two live API routes that no gate could see**. No wire
format, schema, cookie or permission slug changed; two routes gained
documentation they should always have had.

### Added — the level backstop, and a route-surface census on every run (RFC 168 §3.2)

`scripts/drift-scan.sh` gained the last of RFC 168's checks, accepted
2026-10-31 and unbuilt for eight releases. **Correcting this project's own
earlier record: it was one unbuilt check, not three** — §3's item 1
(reconciliation) shipped with RFC 164 in 0.91.2, and item 3 is a requirement on
the other two rather than a check of its own.

**RFC 181 changed what it is for.** Minor is now the default, so a patch is an
*argued exception*, and the backstop is the mechanical half of validating that
claim — the claim that was wrong six times in seven across `0.92.x`. Four
shapes, derived from `[workspace.package] version` against the highest existing
tag rather than asserted:

| | |
|---|---|
| **minor** | prints, passes — nothing to validate |
| **patch claim** | asserts, versus the previous tag, that the registered route set, the migration count and `rust-version` are **unchanged** |
| **not a release commit** | version equals the latest tag; prints, passes |
| **anything else** | a major bump or a version below the latest tag: **reports and fails**, rather than guessing |

**§3.2's own text says a patch must not "add" a route. It must be add *or*
remove**: `0.92.3` was cut as a patch and **removed** two live URLs, which no
addition-only test sees — the single concrete miss that prompted RFC 181. The
regression is part of the check's evidence: pointed at `0.92.2` → `0.92.3` it
reports `2 removed` and fails.

**It computes and reports on every run and fails only on a contradicted patch
claim.** That is deliberate: patch claims are now rare, and a check that only
executes on an exception rots between exceptions — this project's single most
repeated defect.

**And a census, every run, at every level**:

```
ℹ️   route surface vs 0.93.0: 194 pairs -- 0 added, 0 removed
```

Keyed on **method+path** (194 pairs), not path (150) — otherwise a removed
method on a surviving path is invisible. No gate had ever told a cut what it did
to the route surface.

### Fixed — two live routes that no gate could see (nine sites, not six)

Building the census surfaced a **192 vs 194** disagreement between the two
scripts. It was not two definitions. **`route-contracts-check.sh` matched
`(get|post|put|delete)_async` and never `patch`**, while
`crates/backend/src/lib.rs` registers:

```
101 .get_async   87 .post_async   7 .delete_async   2 .patch_async   1 .put_async
```

So **`PATCH /api/v1/tenants/:tid` and
`PATCH /api/v1/tenants/:tid/organizations/:oid` were live, registered and
undocumented** — and the gate whose entire job is *"every registered route is
documented"* could not match them. Its `✅ All 192 routes are documented` was
true only of the 192 it could see.

**Not a race like RFC 182 — a matcher-vocabulary gap**, and it existed in
**nine** places, not the six the dispatching handoff named. The three the
architect's own search missed:

- the **documented**-route extraction and two census filters, written
  `(GET|POST|PUT|DELETE)` **uppercase** against the markdown table — the search
  looked only for the lowercase `_async` shape;
- E6's mutating-row filter, written
  **`method != "POST" && method != "PUT" && method != "DELETE"`** — a `!=`
  chain, which **no regex-pattern search can find.**

All nine now read one shared `ROUTE_METHODS` constant and its two derived forms,
so the next method this project adds is one edit.

**Two consequences were inferred from the code and then refuted by
measurement**, rather than left as plausible: the E4 chunk builder really did
fold `.patch_async` lines onto the preceding route's chunk, and an `awk`
terminator really did over-run past them — but **all 194 registered pairs run
through the old and new resolver diff to zero differences**, and E4's census is
byte-identical, because its figures come from scanning `pub async fn`
definitions rather than lib.rs, and both affected rows are `Rendering: n/a`.

### Changed — `E6_BEARER_LEGACY_EXEMPT` grows from 18 to 20, and the finding it tracks grows with it

With `patch` in the vocabulary, E6 immediately reported both new routes as not
backing their `N/A (bearer)` claim, and the gate failed. **It was left failing
and reported rather than quieted.**

This is **not a new defect.** Both handlers open with
`require(AdminAction::ManageTenancy, …)`, and `api_v1::auth::require` resolves
through `admin_auth::resolve_or_respond` — header **or** the
`__Host-cesauth_admin` cookie — which is character-for-character the condition
the 18 existing entries are listed for. Their documentation rows claim
`N/A (bearer)` exactly as their `POST` and `DELETE` siblings do, and only two
distinct CSRF cell values exist across all 31 `api_v1` rows, so **no more
accurate cell was available**: the rows are right and the control is wrong.

They were **invisible, not newly broken**, so both join the list, dated, with
that reasoning at the call site. **The finding is not retired** — RFC 152 half C
owns the fix, which now covers **twenty** routes rather than eighteen, and the
list's staleness check still fails on any entry that stops matching.

`E6` now reads **`94 = 85 claims (65 resolved, 0 unresolved, 20 exempted) + 9
declared + 0 unclassified`**, and **both scripts now agree on 194**.

### Known gaps

- **Twenty `api_v1` routes claim `N/A (bearer)` and resolve through a
  cookie-accepting path.** RFC 152 half C's finding, now complete rather than
  eighteen-twentieths visible. Not exploitable on its own — the claim is about
  which resolver backs the row, not about a missing control — and it is tracked,
  dated and staleness-checked.
- **The route-surface census reads `lib.rs` only.** A route registered anywhere
  else would be invisible to it, exactly as `PATCH` was to the other script.
- **`trunk` cannot be installed on this machine**, so the frontend static asset
  and the browser suite remain unverifiable locally; only CI's
  `Trunk release build` exercises them, and the `317,718 B` asset figure has
  still never been independently confirmed.
- **`ROADMAP.md` is ~187 KB against RFC 028's 40,960 B budget**, with
  `## Planned (0.x)` at 93% of the file while `## Shipped` — the section RFC 028
  Step 3 says to archive — is 3%.
- **Eleven of the book's eighty pages remain absent from `SUMMARY.md`.** Carried
  from 0.89.5.

### Bundle

Measured after the version bump, gzip **at its default level** (not `-9`):

| file | raw B | gzip B | sha256 (first 16) |
|---|---|---|---|
| `…-index_bg.wasm` | 2,436,797 | 879,482 | `72ddadcbcaef5919` |
| `shim.js` | 61,887 | 10,700 | `486dad37486fd16c` |
| **Worker total** | | **890,182** | |

**−144 B from `0.93.0`'s 890,326.** Nothing this cycle changed reaches the
Worker — the release touched a shell script, a markdown table and
`route-contracts.md` — so the delta is the version string's own compression
effect, and **no further attribution is claimed for it.** `wrangler deploy
--dry-run` requires `crates/frontend/dist` to exist; an **empty** one was
created to measure, sound here only because `LEPTOS_JS` and `LEPTOS_WASM` are
hardcoded consts (`leptos_shell.rs:85-86`).

---

## [0.93.0] - 2026-11-08

**Minor.** Three things: **RFC 181 inverts how release levels are decided**,
**RFC 180 finishes RFC 131 R2b** — a programme slice that had been recorded as
blocked for six weeks against a question answered on 2026-09-24. No route, wire
format, schema, cookie or permission slug changed; the ten imported components
are **dormant** and reach no browser.

and **a `pipefail`/SIGPIPE defect in both release gates was found while running
this very cut's evidence — it held the tag until fixed.**

**This is the first release cut under RFC 181's default**, and it is a minor
because that is now the default, not because a trigger was found.

### Changed — minor is the default release level; patch must argue for itself (RFC 181)

The owner asked why `0.92.7` was not `0.93.0`. Audited against
`docs/src/expert/contributing.md` §Choosing the version level — which already
stated the deciding test *and* already carried a worked example of this exact
error (0.81.2, *"added CI gates — new capability throughout … should have been
0.82.0"*) — **six of the seven `0.92.x` releases were misleveled**:

| release | what it carried | correct |
|---|---|---|
| `0.92.1` | `POST /webauthn/register/start` began requiring a session **and** a `Content-Type` where it required neither | minor |
| `0.92.2` | added `credentialed-flows.yml`; workflows **14 → 15** | minor |
| `0.92.3` | **removed two live URLs**; `route-contracts.md` rows **194 → 192** | minor |
| `0.92.4` | a fix, nothing added | **patch** ✓ |
| `0.92.5` | the E7 gate; its own defects exempted, so no fix shipped | minor |
| `0.92.6` · `0.92.7` | a fix **and** new gates — a mix takes the higher level | minor |

**And it was the second such run**: `scripts/drift-scan.sh:730` already recorded
`0.79.1`–`0.79.6` adding **seventeen registered routes** across five patches.

So the rule was written, correct, and illustrated with this precise mistake, and
it **still failed six times in seven.** Wording was not the variable — **which
way the rule fails on a skipped step** was. Deciding a level used to mean
scanning seven triggers and concluding "none, therefore patch"; skip that and
you got the harmful answer. Under-leveling ships a caller-breaking change under
a number promising compatibility: silent, reaching integrators, and
uncorrectable because tags are immutable. Over-leveling spends a digit that
SemVer does not govern at `0.y.z` at all (§4, scoped `x > 0`).

- **The next release is a minor at scheduling time**, no argument required.
- **A patch is a claim argued in writing in the dispatch handoff**, covering
  both halves: nothing newly possible — *a new CI gate or workflow included* —
  **and** no caller must change anything. **Silence means minor.**
- **Major is unchanged** and stays the owner's.
- **Scoped to `0.y.z`; the inversion expires at `1.0`**, where the asymmetry
  reverses. Written down rather than left to be discovered.

Applied to `ROADMAP.md` §Versioning policy (its trigger list demoted from *what
earns a minor* to *what cannot be a patch*), `contributing.md` (with the
`0.92.x` audit added as its second worked example), and
`rfcs/handoffs/TEMPLATE.md`. **RFC 168 §4.2 is superseded in part** — its
requirement that a handoff state the level stands, and now lives in the
**template**, because that ruling was skipped by a handoff written four days
after it was accepted. A rule in a template reaches every dispatch; a rule in an
RFC reaches whoever re-reads that RFC.

**No retagging.** `0.92.1`–`0.92.7` are shipped, signed, immutable artifacts,
and §Versioning policy already settles this class as historical debt.

**One consequence, recorded in RFC 181 §7**: planned scope can no longer be
pinned to a predicted version number, because minors now advance every cut. Four
ROADMAP rows keyed to `0.93.0`/`0.94.0` are re-keyed to sequence.

### Added — RFC 131 R2b is finished (RFC 180)

Ten mockup component files — four shells, `topbar`, three domain components, and
the two primitives R2a excluded (`permission_denied`, `suspended_notice`) — at
pin `df3d9d0`, under `crates/frontend/src/components/{shells,nav,domain}/`.
**Dormant: nothing routes them, and `components` is `#[cfg(feature = "csr")]`,
which the Worker never enables**, so none of it reaches the deployed bundle.

**R2b was not blocked, and had not been for six weeks.** RFC 131 recorded it as
*"deferred with q1"*; **RFC 132 §13 q1 was answered 2026-09-24** and states *"R3
is no longer blocked."* RFC 131 was never updated. Measured, the slice was also
**five times smaller than RFC 131 described**: the ten files use **47** distinct
catalog keys, not the mockup's 263, and **exact-name overlap with core's catalog
is 0**.

- **The mockup's i18n mechanism was deleted, not imported** — no second
  `Locale`, no `Msg`, no reactive `LocaleContext`/`use_locale()`. That second
  catalog is what **ADR-013 declined**. Every file resolves through
  `cesauth_core::i18n::lookup`.
- **The locale was already in the DOM.** `leptos_html_shell` emits
  `<html lang="…">`, so `app.rs` reads it once at mount and holds plain state.
  No reactive context, because nothing in these files changes locale after
  mount.
- **`47 = 6 mapped + 41 added + 0 unresolved`**, each decided by comparing
  **rendered strings in both locales**, not names. `MessageKey` **171 → 212**.
- **The trap that a name-based pass would have shipped**: core's
  `AdminScopeTenant` renders `"Tenant: {slug}"`, parameterised — so the mockup's
  `ScopeTenant` was **added**, not mapped. Mapping it would have rendered a
  literal `{slug}` to an operator.
- **`auth_shell.rs`'s four footer strings are asserted as rendered output in
  both locales**, not as enum variants that exist.
- **No mock data carried forward**: `"alice@example.com"` and
  `"platform-op@example.test"` defaults are gone; those props are now required.

**RFC 131's own figures were stale and are corrected**: core had **171** keys,
not the "175" the R2 split recorded.

### Fixed — both release gates turned a match into a miss, and two checks could pass while a violation existed

**Found while running this release's own gates, and it held the tag.**
`drift-scan.sh` returned **one clean run in five** on an unchanged tree, with two
*different* false failures — `deployment/production.md` reported as a broken link
though it exists and is listed in `SUMMARY.md:88`, and tag `0.33.0` reported as
undocumented though it is at `CHANGELOG-0.31-to-0.40.md:1682`.
`route-contracts-check.sh` exited **141 — SIGPIPE — three times of three**,
stopping right after its E6 line, **so E7's census had not actually run since the
machine's load rose.**

**The mechanism.** Both scripts open `set -euo pipefail`. In

```bash
if printf '%s
' "$list" | grep -Fxq "$needle"; then
```

`grep -q` exits **0 on its first match**, the writer is killed by SIGPIPE, and
`pipefail` gives the *pipeline* that status — 141 — so the `if` takes the false
branch. **A real match is reported as a miss.** A 200,000-line list with the
needle first reports "not found" **40 times out of 40**; at 148 entries the list
fits the 64 KiB pipe buffer and usually works, which is why these gates had been
green for a week and flapped only at load average **134**. The same shape applies
to `| head` and — **a form the dispatching handoff failed to include** — an
`awk` script with its own `exit`, which was 4 further sites.

**Two of the affected checks could report clean while a violation existed**, both
found by the implementer auditing consumer logic rather than pipeline shape, and
**neither in the architect's own sample**:

- **`drift-scan.sh`'s link-integrity per-file gate** read
  `printf … | grep -Fxq "$rel" || continue`. On a match→miss it skipped that
  file's entire link scan, **with no counter recording the skip** — a broken link
  in that file would simply not be reported. `docs_link_scanned -eq 0` only
  catches every file being skipped, not one.
- **`route-contracts-check.sh`'s E7 caller-attribution chain**, four sites. A
  match→miss that shrinks what a *caller* demonstrably handles means the dropped
  variant is **never evaluated** against the producer — and in the worst case a
  method with a real, unexempted DEFECT is reclassified into the non-failing
  `no_caller` bucket. Producer-side misses are the opposite and only ever add
  false DEFECTs.

**The fix is plumbing, not logic**: every vulnerable pipe becomes a `<<<`
here-string, which has no writer process to kill; where the writer is a real
command and a pipe is unavoidable, `|| true` on the whole assignment keeps the
already-captured value. `grep -q <<< "$var"` and `grep -qE … "$file"` forms were
already safe and were left alone. **No check's matching logic and no exemption
list changed, and no reported figure moved** — E7 still reads
`156 = 8 + 31 + 117`, identical to the figure independently reproduced before the
fix.

**Verified**: `drift-scan.sh` **20/20 exit 0** (12 idle, 8 under deliberate
load); `route-contracts-check.sh` exit 0 with **byte-identical output across
runs**, all seven `ℹ️` lines and the closing `✅` restored. **Not claimed**:
whether either false-pass site ever hid a real violation in a past run. By
construction those runs left no record, and that retrospective question is its
own cycle.

### Known gaps

- **Six sidebar destinations in the new shells have no registered route** —
  `/admin/console/investigate`, `/admin/tenancy/users`,
  `/admin/t/:slug/{roles,groups,oidc-clients,audit}`. Harmless while the
  components are dormant; **six links will 404 the moment R3 mounts them**, and
  it is recorded for R3's dispatch rather than only in code comments. Three
  further links were wrong and were corrected against the real registrations.
- **No gate caught any of those nine.** `drift-scan.sh`'s RFC 108 check
  excludes `pages/`, `app.rs` and now `components/` — correctly, on the same CSR
  reasoning — so the shared-route-constants RFC that exclusion has promised
  since RFC 108 now has measurement behind it: 27 live path literals, three
  wrong, six pointing nowhere, zero caught.
- **`for_each_key`'s exhaustiveness pin and its iterated array are not checked
  against each other**, so a future key could be pinned, uniterated, and
  silently uncovered by the two completeness tests. 41 keys were added to both
  by hand correctly this cycle; nothing made them.
- **The RFC 179 census rose `96 → 136`** (`122` literal names + `14` that only
  appear once the computed sites resolve), **`1 declared-and-matching + 135
  not-yet-styled + 0 unclassified`** — reported, not suppressed. R2b touches no
  CSS.
- **`trunk` still cannot be installed here**, so the frontend asset and the live
  browser half of the census are unverifiable locally by anyone; only CI's
  `Trunk release build` exercises them.
- **`ROADMAP.md` is ~185 KB against RFC 028's 40,960 B budget**, and its
  diagnosis in RFC 028 is wrong: `## Planned (0.x)` is **93.3%** of the file
  while `## Shipped` — the section Step 3 says to archive — is **3.3%**.
- **Eleven of the book's eighty pages remain absent from `SUMMARY.md`.** Carried
  from 0.89.5.

### Bundle

Measured after the version bump, gzip **at its default level** (not `-9`):

| file | raw B | gzip B | sha256 (first 16) |
|---|---|---|---|
| `…-index_bg.wasm` | 2,436,446 | 879,627 | `697673587e7f3494` |
| `shim.js` | 61,887 | 10,699 | `b0f866ac62a016df` |
| **Worker total** | | **890,326** | |

**+1,254 B from `0.92.7`'s 889,072**, attributable to `cesauth-core`'s 41 new
`MessageKey` variants and their lookup arms — `cesauth-core` links into the
Worker unconditionally, while the ten CSR components do not reach it at all.
`wrangler deploy --dry-run` requires `crates/frontend/dist` to exist; an
**empty** one was created to measure, sound here only because `LEPTOS_JS` and
`LEPTOS_WASM` are hardcoded consts (`leptos_shell.rs:85-86`) rather than read
from it. The frontend asset is **not** reported — see *Known gaps*.

