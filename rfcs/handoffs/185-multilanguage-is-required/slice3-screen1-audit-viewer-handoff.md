# Developer Handoff — RFC 185 §5.3, screen 1: the audit viewer

**Governing RFC.** `rfcs/accepted/185-multilanguage-is-required-and-the-csr-app-has-no-locale-at-all.md`
— read **§8** (seven amendments) before §1–§7. Where the body and §8 disagree, §8 wins.
**Prior review.** `.git-exclude/reviewed/185-gate-type-and-record-review.md` — its
**F-A** and **F-C** are load-bearing here and are quoted where they apply.
**Target release.** **Minor.** This screen becomes the **first surface in the
project that negotiates its locale per request**, and `mounted_locale()` gets
its first caller. A patch argument is not available: something is newly
possible that was not before.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. RFC 185 §5.5 (how many locales) is open and the
owner's, and does not block: `Locale` is a closed enum, so adding a variant
later is a compile error until every key is filled, which is the designed
behaviour and exactly why it does not gate this work.

---

## 1. Purpose

`GET /admin/console/audit` — the operator audit viewer — becomes the first
screen whose language follows the request. After this lands, an
`Accept-Language: en` operator gets that screen in English, a `ja` operator
gets it in Japanese, `<html lang>` and `<main lang>` both say which, and the
screen's 24 hardcoded Japanese literals are gone.

It is also the screen that **lost** `En` when RFC 131 slice 1 converted it:
18 catalog lookups became 26 hardcoded literals. So this is a restoration, not
a new capability — and the keys to restore it with **already exist**.

## 2. Why this matters

The owner, 2026-11-11: *"Multilanguage support is required."* Four slices of
RFC 131 remain, and until one screen actually negotiates, nothing in the
product does — `0.99.0` built the gate and typed the plumbing, and deliberately
changed no rendered language. This is the first cut where a user sees a
difference.

Second, and found while scoping this one: **the CSR rewrite silently changed
the Japanese wording of three operator-facing labels** and nobody recorded it
(§4 F3). One of them dropped the unit from a timestamp column.

## 3. Resolved decisions — do not re-open

**D1. Reuse the existing `AuditViewer*` keys. Do not invent a parallel set.**
There are **19** of them in `crates/core/src/i18n/mod.rs`, written in both
locales for *this exact screen*, and the server template `admin/audit.rs` still
calls 18 of them. **10 of this screen's 24 literals are byte-identical to an
existing key's `Locale::Ja` value** (§4 F2). A second set of keys for the same
strings would make `no_two_keys_share_text_within_a_locale` fail, which is the
catalog telling you the same thing.

**D2. Three wordings revert to the template's, because the template's is the
better-evidenced one.** These are design calls, mine, with the evidence in each:

| CSR says | revert to | key | why |
|---|---|---|---|
| `"時刻"` | `"時刻 (UTC)"` | `AuditViewerColTime` | RFC 111 set a UTC ISO-8601 presentation policy. A timestamp column with no unit is the defect that policy exists to prevent, and the export file's header is `timestamp` |
| `"詳細"` | `"Reason"` | `AuditViewerColReason` | The column is bound to `e.reason`, and the **export CSV's own header row is `seq,timestamp,kind,subject,client,reason`** (`crates/core/src/admin/service/audit_export.rs:95`). The screen and the file the operator downloads from it must not name the same column differently |
| `"イベント"` | `"Event"` | `AuditViewerColEvent` | Same reason: the CSV header is `kind`, the template said `Event`, and `詳細`/`イベント` were a two-column rename in one commit with no record |

**D3. Do NOT resolve the actor/subject vocabulary. It is its own decision.**
Scoping found **four names for one field**: `AuditQuery::subject_contains` and
`subject` in the core type (`crates/core/src/admin/types.rs:522`), `subject` in
the export CSV header, **`actor`** in the URL/form parameter and the input id
`audit-actor`, `Actor (部分一致)` / `Actor` in the old template, and `実行者`
in the CSR screen. There is **no `actor` field anywhere in `AuditQuery`**.
Renaming any of it touches a route contract and a downloaded file format, which
is out of this cut by a mile. **For this cut: wrap the existing displayed
wording in a key and change no vocabulary** — use `AuditViewerActorLabel` for
the filter label and `AuditViewerColActor` for the column, i.e. the template's
own wording, and say in the report that you did so under D3 rather than as a
choice. `ROADMAP.md` carries the row.

**D4. This screen flips to negotiated locale, and that is TWO `lang` edits, not
one.** Review finding F-C. The route must pass `crate::i18n::resolve_locale(req)`
to `leptos_html_shell` *for this route only*, and
`crates/frontend/src/pages/operator/audit.rs:190`'s **`<main lang="ja">`** must
follow the same value. **Leaving `<main lang="ja">` in place would defeat the
whole cut**: an element-level `lang` wins over `<html lang>` for its entire
subtree, so the document would claim English and every word of content would
still be announced as Japanese. That is strictly worse than the truthful
literal `0.99.0` preserved.

**D5. `mounted_locale()` gets its first caller here**, and it is the only way
the CSR component can know the locale: the component is mounted client-side and
has no request. `crates/frontend/src/app.rs:64`. It reads
`document.documentElement.lang` through `Locale::from_primary_subtag` and
`unwrap_or_default()`s to `Ja` — so **the shell's `<html lang>` is the channel**,
which is why `0.99.0` typed it.

**D6. The route's `<title>` is converted too.** `routes/admin/console/audit.rs:67`
passes `"監査ログ — cesauth"`. A negotiated screen with a hardcoded Japanese tab
title is the same half-and-half defect one layer up. `AuditViewerPageTitle`
already holds `"監査ログ"` / `"Audit log"`; compose the ` — cesauth` suffix at
the call site. **This is the only one of the 27 title literals in scope** — the
other 26 belong to their own screens' conversions (`ROADMAP.md`).

**D7. The ceiling goes 24 → 0 in the same commit.** `scripts/drift-scan.sh`'s
`I18N_CEILINGS`. D5 of the previous handoff makes a stale ceiling a hard
failure, so the gate will fail until you lower it — that is the mechanism
working, not a problem to route around. **Never raise a ceiling.**

## 4. Facts already measured — do not re-derive

**If any of this fails to reproduce on your run, that is a finding — report it
rather than working around it.**

**F1 — the screen's 24 literals**, non-test, non-comment:

```sh
awk '/^#\[cfg\(test\)\]/{exit} {print NR"\t"$0}' crates/frontend/src/pages/operator/audit.rs \
 | grep -vP '\t\s*//' | grep -P '"[^"]*[\x{3040}-\x{30ff}\x{4e00}-\x{9fff}][^"]*"'
```

**F2 — the mapping. 10 exact, 6 divergent, the rest new.** Exact matches to an
existing key's `Locale::Ja` value: `監査ログ` (`AuditViewerPageTitle`, used at
`:190`'s `aria-label` and `:191`'s `<h1>`), `絞り込み` (`AuditViewerSectionTitle`,
`:205` and `:206`), `イベント種別` (`AuditViewerEventLabel`), `(すべて)`
(`AuditViewerEventAny`), `期間 (UTC)` (`AuditViewerPeriodLabel`), `開始`
(`AuditViewerFromLabel`), `終了` (`AuditViewerToLabel`), `絞り込む`
(`AuditViewerSubmitButton`), the `tenant_id 単位での…` note
(`AuditViewerNoteSchemaTenant`), `条件に合致するイベントはありません。`
(`AuditViewerEmptyState`), `より古い →` (`AuditViewerOlderLink`).

Divergent, handled by D2 and D3: `時刻`, `詳細`, `イベント`, `実行者` (twice —
filter label and column), `← 新しい` vs `AuditViewerNewerLink`'s `← より新しい`.

**Needing new keys** (no catalog entry, in either locale): the two error
strings at `:80` and `:82`, `← コンソール` (`:195`), `チェーン検証状況 →`
(`:197`), `読み込み中…` (`:278`). **Count them yourself and report the number**
— mine is a scoping estimate, not a measurement you should inherit.

**F3 — what the CSR rewrite changed, recorded so it is not re-litigated.** The
screen's five column headers are `時刻 / 実行者 / イベント / 詳細 / Seq`
(`:289-293`); the template's were `時刻 (UTC) / Actor / Event / Reason / seq`.
**The `Seq` column was NOT dropped** — I believed it had been, from a listing
that showed only the *Japanese* literals, and `"Seq"` is ASCII. That is review
finding **F-A** happening to me an hour after I wrote it: *enumerating the
Japanese and reasoning about completeness from it is the error the gate's own
blind spot is made of.* Stated here because it is the single easiest mistake to
repeat on this file.

**F4 — baseline gates at `0.99.0` (`f70339f`).** Host **1,722 / 0 / 4** across
**12** `test result:` lines. `route-contracts-check.sh` exit 0, **197 routes**,
E3 47 · GATE_42 24 · NONCE 13 · E4 219 · E5 19 · E6 95 · E7 156.
`drift-scan.sh` clean, **10** sections, i18n ceiling **105 files scanned, 16
hit, 18 entries, 0 violations, 0 stale**. `cargo check` warnings **8** frontend,
**1** core. Bundle **899,809 B**.

## 5. Report-and-stop gates

**G1 — the new-key list, before you write it.** Report the literals with no
existing key, with your proposed `MessageKey` name and **both** locale strings,
**before** adding them. A `Locale::En` string invented for an operator screen is
operator-facing copy; I want to read it before it is a commit. Do the exact
matches (F2) first and independently — they need no approval.

**G2 — `audit_page`'s 545 lines, after conversion, not before.** RFC 131 R4
says each slice deletes its template, and `ROADMAP.md` records that the
deletion was blocked on *"18 catalog lookups replaced by 26 hardcoded Japanese
literals, so that one screen lost `Locale::En` coverage the template had"*. This
cut removes that blocker. **So: convert, then measure parity and report it —
every `MessageKey` the template uses must be reachable from the CSR screen, and
every column and filter the template offers must exist on it.** If parity
holds, delete in this same cut (`crates/frontend/src/admin/audit.rs`, its
`pub use` at `admin.rs`, and re-point the four doc-comment references at a git
revision rather than a deleted path). **If it does not hold, report the gap and
stop** — do not delete, and do not "fix" the gap by adding scope.

**G3 — the negotiated screen, observed.** You cannot render this here (`trunk`
will not install, no browser connection). Report what you *did* establish and
in which terms: that `resolve_locale` is called on this route, that the shell
emits `lang="en"` for an `Accept-Language: en` request, that
`from_primary_subtag` round-trips it, and that the component's strings come
from `lookup(_, mounted_locale())`. **State plainly that nobody saw the screen
in English.** `observed`/`reviewed`, never `exercised`.

## 6. Change scope

| # | Task | Files |
|---|---|---|
| **T1** | Re-point the 10 exact matches (F2) at their existing keys. No new keys, no wording change | `crates/frontend/src/pages/operator/audit.rs` |
| **T2** | D2's three reversions and D3's two actor labels, at the template's wording | same |
| **T3** | G1's new keys, in both locales, added to the `match` pin **and** the hand-written `all` array in `crates/core/src/i18n/tests/lookup_completeness.rs` — the two mechanisms do not check each other | `crates/core/src/i18n/mod.rs`, `.../tests/lookup_completeness.rs` |
| **T4** | The locale flip: route passes `resolve_locale(req)`; component takes `mounted_locale()`; **`<main lang>` at `:190` follows it** (D4) | `crates/backend/src/routes/admin/console/audit.rs`, `crates/frontend/src/pages/operator/audit.rs` |
| **T5** | D6's title | `crates/backend/src/routes/admin/console/audit.rs` |
| **T6** | Lower `I18N_CEILINGS`' `pages/operator/audit.rs` entry to **0** (D7) | `scripts/drift-scan.sh` |
| **T7** | G2: parity report, then the deletion **only if** parity holds | `crates/frontend/src/admin/audit.rs`, `crates/frontend/src/admin.rs` |

Order: T1–T3 before T4, so the screen can honour a locale before it is given
one. T6 last among the code tasks — it will fail until the literals are gone,
which is how you know T1–T3 are complete.

## 7. Explicit non-change scope

- **One screen.** `clients.rs` (52), `console.rs` (33), `tenancy.rs` (27) and
  `audit_chain.rs` (41) are later screens. Their ceilings stay as they are.
- **No vocabulary decisions** beyond D2's three. D3 especially.
- **No route-string, URL-parameter or CSV-header changes.** The `actor`
  parameter stays `actor` even though the field is `subject`.
- **Do not widen the i18n matcher** (review finding F-A). It stays as shipped.
- **Do not touch the other 26 `<title>` literals** or the other 14 `lang`
  attributes (F-C's list). This screen's two only.
- **Do not localise `components/`** — still dormant, still RFC 131 R3's.
- Standing rules: **no `cargo fmt`**; no `#[allow]` to quiet a warning.

## 8. Task detail worth stating explicitly

**T4 — the silent-failure risk is the whole task.** If `<main lang="ja">`
survives, every gate still passes, `cargo check` is clean, the shell emits
`lang="en"`, and a screen reader still reads the page in Japanese. **There is no
build-time signal for this.** Assert it mechanically (§9) and say in the report
that you did.

**T4 — `mounted_locale()` is read once, at mount.** It is plain state, not a
reactive context: RFC 180 §5 bars building a reactive locale context, fixed or
not, and that still holds. Read it once and pass it down; do not introduce a
signal, a context, or a switcher.

**T1 — two of the exact matches are attribute values, not text children**
(`:190`'s `aria-label`, `:220`'s `placeholder`). They need the same treatment
and the i18n gate's clause (b) would not have caught them if they had been
English — F-A again.

**T3 — do not repeat `lookup_completeness`'s own defect.** The `match` arm pins
every variant (compile error if one is missed); a **separate** hand-written
array is what the tests iterate. A key in the pin but absent from the array
compiles and passes both tests while being uncovered by the two tests whose job
is completeness. Add to both and say so.

## 9. Assert machine-checkable things mechanically

```sh
# 1. No Japanese literal left on this screen. Expect: no output.
awk '/^#\[cfg\(test\)\]/{exit} {print}' crates/frontend/src/pages/operator/audit.rs \
  | grep -vP '^\s*//' | grep -P '[\x{3040}-\x{30ff}\x{4e00}-\x{9fff}]'

# 2. No hardcoded lang on this screen (D4). Expect: no output.
grep -n 'lang="' crates/frontend/src/pages/operator/audit.rs

# 3. The route negotiates (T4). Expect: a resolve_locale call.
grep -n "resolve_locale" crates/backend/src/routes/admin/console/audit.rs

# 4. mounted_locale now has exactly one real caller plus its definition.
grep -rn "mounted_locale(" --include="*.rs" crates/ | grep -vP '^\S+:\d+:\s*(//|///)'

# 5. No new key duplicates an existing string -- the catalog's own test, but
#    run it deliberately and name it in the report.
cargo test -p cesauth-core no_two_keys_share_text_within_a_locale

# 6. Non-test code changed only where §6 says -- assert on hunk headers,
#    not filenames.
git diff -U0 | grep '^@@'
```

**A count or a list in prose is a measurement.** Every figure in the report
carries the command that produced it, the new-key count included.

## 10. Required tests and evidence

```sh
cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend \
           -p cesauth-backend -p cesauth-adapter-cloudflare \
           --features cesauth-frontend/csr            > evidence/cargo-test.log 2>&1
cargo check -p cesauth-backend  --target wasm32-unknown-unknown  > evidence/wasm32-check.log 2>&1
cargo check -p cesauth-frontend --features csr --target wasm32-unknown-unknown > evidence/csr-check.log 2>&1
cargo clippy -p cesauth-core -p cesauth-adapter-test -p cesauth-migrate-test \
             -p cesauth-frontend --all-targets -- -D clippy::correctness > evidence/cargo-clippy.log 2>&1
cargo deny check   > evidence/cargo-deny.log 2>&1
cargo audit        > evidence/cargo-audit.log 2>&1
bash scripts/route-contracts-check.sh > evidence/route-contracts.log 2>&1
bash scripts/drift-scan.sh            > evidence/drift-scan.log 2>&1
```

Expected against F4: host tests **above 1,722** — report the delta and
reconcile it; the catalog's completeness tests consume new keys without adding
test functions, so a large jump wants explaining. `route-contracts-check.sh`
exit 0 with **route surface 197 pairs, 0 added, 0 removed** — **a non-zero
delta means the cut grew; stop.** `drift-scan.sh` exit 0 with the i18n ceiling
line showing **15 files hit** (one fewer) and the `pages/operator/audit.rs`
entry at **0**. `cargo check` warnings **8 / 1**, unchanged — and if T7's
deletion lands, the two `never used` frontend warnings may change; report the
new figure rather than asserting the old one.

**Sum test counts programmatically** — `awk`/`python` over the whole log, never
by hand; doc-tests count.

**A fires/does-not-fire pair is required for T6**, and it is free: the gate must
be red with the literals gone and the ceiling still at 24, green at 0.

**Evidence policy.** Every file under `evidence/` is redirected command output.
A hand-written summary line is rejected at review.

## 11. What must NOT be claimed

- **Do not claim anyone saw this screen in English.** G3. `trunk` will not
  install here and there is no browser connection, so the user-visible outcome
  of the entire cut is `observed`/`reviewed`, never `exercised`. The honest
  wording names what *was* established: the route negotiates, the shell emits
  the tag, the parse round-trips, the strings come from the catalog.
- **Do not claim the screen is at parity with the template** unless G2's
  measurement says so, column by column and filter by filter.
- **Do not claim RFC 131 slice 1's regression is fully repaired** if any of
  F2's divergences is left unresolved — name which.
- **Do not claim the project is multilingual.** One screen of eleven negotiates
  after this. `pages/` still holds 174 literals and `components/` 12.
- RFC 000 §22 terms throughout.

## 12. Prohibited shortcuts

- No second set of keys for strings the catalog already has (D1).
- **No raising a ceiling, ever.**
- No `#[allow(...)]`, `#[cfg(...)]` or feature gate to hide an error.
- No `continue-on-error: true`; no weakening a gate until it passes.
- No reactive locale context, no `LocaleToggle` (RFC 180 §5).
- No `cargo fmt`. No route-string, URL-param or CSV-header changes.
- No deleting `audit_page` on a parity claim you did not measure.

## 13. Acceptance criteria

RFC 185 §5.3 for this one screen, and §5.1's deferred flip (A5) for this one
route.

**Checked hardest:** (1) §9 assertion 2 — `<main lang>` gone — because there is
no build-time signal for getting it wrong and it would silently nullify the
cut; (2) G2's parity measurement, because a 545-line deletion rests on it and a
parity claim was already accepted once on this screen and was false; (3) G1's
English strings, as operator-facing copy.

**Expected unreachable, stated in advance:** the rendered English screen (§11).

## 14. Known risks

- **A parity claim about this exact screen was accepted once and was false.**
  `0.95.0`'s slice 1 claimed the export form carried the same four hidden
  fields plus `csrf`; it did not, and I signed a tag on it. G2 exists because
  of that, and *"I checked and it matches"* is not a measurement.
- **`<main lang>` is the trap** (§8). Fifteen such attributes exist; this
  screen has one; fourteen are out of scope and must stay.
- **The new `Locale::En` strings are user-visible copy on a security surface.**
  G1 is a stop, not a formality.
- **T7 deletes 545 lines**, which is the largest deletion in the programme so
  far and is conditional. A conditional deletion done unconditionally is the
  failure mode; report G2 first.
- **If the work turns out materially larger than scoped, stop and report.**
  Re-scoping is the architect's call, not the implementer's.

## 15. Review request

Write the package to `.git-exclude/review-request/`. It must include:

implementation summary · changed files · any deviation from §6 · every log from
§10 · the §9 assertion output · T6's fires/does-not-fire pair · **G1's new-key
list with both locales** · **G2's parity measurement, column by column** ·
G3's honest terms · gate results against F4 · what remains unverified (§11) ·
unresolved issues · requested review focus.

**Report the path only.** The architect reads it there.
