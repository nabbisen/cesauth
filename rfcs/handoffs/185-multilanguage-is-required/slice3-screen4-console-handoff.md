# Developer Handoff — RFC 185 §5.3, screen 4: the operator console's seven, and the last three skip links

**RFC.** `rfcs/accepted/185-multilanguage-is-required-and-the-csr-app-has-no-locale-at-all.md` §5.3
**Previous slices.** screen 1 (`0.100.0`, 5 new keys) · screen 2 (`0.102.0`,
31) · screen 3 (`0.104.0`, 20 new + 9 reused, and the shared shell)
**Baseline.** `da7785d` / tag `0.104.0`
**Level.** Minor — seven more screens answer `Accept-Language`.

---

## 1. Purpose

Convert `crates/frontend/src/pages/operator/console.rs` — **seven**
components, `ConsoleOverview` / `ConsoleOperations` / `ConsoleTokens` /
`ConsoleSafety` / `ConsoleCost` / `ConsoleAlerts` / `ConsoleConfig` — and
flip the **seven** routes that serve them from `Locale::Ja` to
`resolve_locale`. Then close the last three Japanese literals that live
outside `pages/operator/`.

## 2. Why this slice is far cheaper than its ceiling row suggests

The ceiling says **44** for this file. It was 17 new keys when I scoped
`0.104.0`; it is **12** now, because screen 3 minted the title keys this
screen's headings and nav links need. Measured against the post-`0.104.0`
catalog:

```
pages/operator/console.rs: 33 occurrences, 21 distinct, 9 already keyed, 12 new
```

The nine already keyed are `TenancyOverviewPageTitle`, `OperationsTitle`,
`AuditViewerPageTitle`, `ConsoleCostPageTitle`, `TokensTitle`,
`ConsoleAlertsPageTitle`, `ConfigTitle`, `FetchLoading`, and
`OperatorConsoleBackLink` — the last of which alone covers **six**
occurrences of `← コンソール`. **Reuse them.** A parallel key with the same
Japanese fails `no_two_keys_share_text_within_a_locale`.

**And the twelve become ten**, by §4's two rulings: the four
`…は未実装です(RFC 161)。` sentences collapse into one shared key, and one
new key is the skip link from §6. So: **10 new keys, 9 reused.**

## 3. Facts already measured — do not re-derive

- **Seven `<main lang="ja">` attributes**, at `console.rs:22, 53, 85, 111,
  121, 131, 141` — one per component. Screen 1's F-C applies to each: a
  `<main lang>` overrides `<html lang>` for its subtree, and **no
  build-time signal exists** for getting it wrong. Seven is the most of any
  slice so far.
- **Seven routes to flip**, each a one-line change now that the shell takes
  a locale: `console/{overview,operations_route,tokens,safety,cost,alerts,config}.rs`
  (`grep -rn "Locale::Ja" crates/backend/src/routes/admin/console/*.rs`).
  **`console/clients.rs` is the eighth and stays pinned** — its body is
  `0.106.0`'s work.
- **`crates/core/src/i18n/tests/screen3_titles.rs` must stay green,
  untouched.** All seven of these routes' Japanese titles are already
  pinned byte-identical there. Flipping the locale argument does not change
  what `Locale::Ja` resolves to, so those eleven tests are this slice's
  free regression guard. If one fails, you changed a title.
- **Four of the seven components are RFC 161 placeholder screens**
  (`ConsoleSafety`, `ConsoleCost`, `ConsoleAlerts`, `ConsoleConfig`), whose
  whole body is a heading, a back link and one `…は未実装です(RFC 161)。`
  sentence. RFC 161 §9(b)/(c) — owner-approved 2026-10-30 — restores them
  as RFC 131 slices.
- **The three skip links are the last live Japanese outside
  `pages/operator/`.** A parse of every non-test file under
  `crates/frontend/src` outside `pages/operator/` finds exactly three:
  `admin/frame.rs:219`, `tenancy_console/frame.rs:171`,
  `tenant_admin/frame.rs:213`, all `メインコンテンツへスキップ`. **This
  corrects a claim I signed into the `0.99.0` tag** — that the gate bounded
  the Japanese debt exactly. It did not; these three were outside it.
- **Baseline gates**, each with its command.
  `cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend -p cesauth-backend -p cesauth-adapter-cloudflare --features cesauth-frontend/csr`
  → **1,728 / 0 / 4 across 12 `test result:` lines**.
  `cargo test -p cesauth-migrate-test --test migration_chain` → **39**.
  `bash scripts/route-contracts-check.sh` → **197 routes**, seven coverage
  figures. `bash scripts/drift-scan.sh` → clean, **103 / 65 / 69**. Bundle:
  CI's `bundle-size.yml` is the authority — **904,062 B gzip at `0.104.0`**;
  a local figure is comparable only to another local figure, and a raw-byte
  count is not comparable to a gzip one at all.

## 4. Rulings already made — apply, do not reopen

**R1. The four placeholder sentences become one key.** Each of those four
screens already names itself in its own `<h1>`; the body only has to say
the status. Four bespoke sentences would be four translations written to be
deleted when RFC 131 restores the screens. One key, four call sites. **Its
wording is a G1 item** (§5), not the structure.

**R2. A title may be shorter than its heading, when the heading contains
it.** Two headings differ from their route's title: `安全性チェック` against
`ConsoleSafetyPageTitle`'s `安全性`, and `cesauth オペレーターコンソール`
against `ConsoleOverviewPageTitle`'s `コンソール`. Both headings are
**supersets** of their title. That is legitimate and common — a tab label
is short, a page heading can be full — so both stay, each as its own key,
and the rule is now written down: **the title is the screen's short name,
the heading may be the fuller one, and the heading must contain the
title's words.** Do not "fix" either by making them identical; do not
change either route's title (`screen3_titles.rs` pins them).

**R3. `エラーが発生しました。` gets one shared key, now.** It appears at
`console.rs:99` and again at `clients.rs:126`, which is `0.106.0`'s file.
Name it for what it is — a generic action failure, distinct from
`FetchFailed`'s load failure — so that `0.106.0` reuses it instead of
minting the second variant. This is the fourth time this programme has met
a near-duplicate failure message; the cheap moment to stop it is before the
second one exists.

## 5. Report-and-stop gate: G1

**10 new keys, two locales, before any of them is written.** Report the
table (key · `Ja` · `En` · where used) and stop. Three copy questions it
must answer rather than settle silently:

1. **R1's one sentence, in both locales.** It will be read on four screens
   and it says the product does not do something yet. Propose the wording.
2. **The status pair** — `✓ システム正常` and `⚠ 状態を確認できませんでした`
   (`console.rs:38`, `:40`). The second is a *status check* failure, not a
   load failure, so I expect its own key rather than `FetchFailed` — but
   its English must not invent a third register beside *"Failed to load.
   Please reload."* and *"Failed to load the tenant count."*
3. **R2's four values** — the two headings' English, against their titles'
   `Console` and `Safety`.

**Before you submit it, run the collision check in both locales against the
whole catalog.** Screen 3's G1 table would have panicked the build on an
English-side duplicate it had only checked in Japanese. The catalog is now
261 keys.

## 6. Change scope

| # | Task | Files |
|---|---|---|
| **T1** | 10 new `MessageKey`s, both locales, in the enum, the `lookup` match and **both** `lookup_completeness.rs` lists | `crates/core/src/i18n/{mod.rs,tests/lookup_completeness.rs}` |
| **T2** | The seven components take a `Locale` via `mounted_locale()`, every literal through `lookup`, all **seven** `<main lang="ja">` → `locale.bcp47()` | `crates/frontend/src/pages/operator/console.rs` |
| **T3** | Seven routes: `Locale::Ja` → `crate::i18n::resolve_locale(&req)`. **`clients.rs` untouched** | `routes/admin/console/{overview,operations_route,tokens,safety,cost,alerts,config}.rs` |
| **T4** | The skip link reads from the catalog in all three frames. Each already has a `*_for(..., locale, ...)` variant with `locale` in scope and the markup is already a `format!`-style string with `{...}` interpolation, so this is a placeholder, not a restructure | `crates/frontend/src/{admin,tenancy_console,tenant_admin}/frame.rs` |
| **T5** | Ceiling rows: `pages/operator/console.rs` → **0**, and the three `frame.rs` rows (**4** each today) to whatever the matcher now produces | `scripts/drift-scan.sh` |
| **T6** | The Japanese **doc comments** in both converted screens become English: **9** lines in `console.rs`, **4** in `tenancy.rs` (rowed at screen 3) | `crates/frontend/src/pages/operator/{console,tenancy}.rs` |

**T5 carries a measurement trap.** Do not assume each frame row drops by
one. The matcher double-counts a literal that is both a CJK string and an
HTML text node, so the drop may be two. The ceiling is **value-based** — a
row must equal the matcher's actual count — so run the gate, read the real
number, and set the row to it.

**T6 is here because my own §8 assertion was wrong twice.** I wrote "expect
no output" for screen 3 and `tenancy.rs` returned five doc-comment lines;
checking before writing this handoff, `console.rs` has **nine**
(`grep -cP '^\s*(//!|///).*[CJK]'`). The two screens already converted,
`audit.rs` and `audit_chain.rs`, have **zero** — they were authored in
English. So the inconsistency is in these two files, this slice has both of
them open, and thirteen comment lines is a cheaper fix than a third round
of explaining why the assertion does not mean what it says. **No ceiling
impact**: the matcher skips any line starting with `//`, so these lines
were never counted.

**T4's blast radius is zero today, and say so rather than implying more:**
the `*_for` variants have **no production caller** (only
`crates/frontend/tests/acceptance_harness.rs`); every live page goes
through the `Locale::default()` wrapper, and `Locale::default()` is `Ja`.
So this closes the debt and changes nothing an operator sees until those
frames' routes negotiate.

## 7. Explicit non-change scope

- **Translating any other file's Japanese doc comments.** T6 covers the two
  screens this slice has open. `clients.rs`'s are `0.106.0`'s, with its body.
- **`pages/operator/clients.rs`** — `0.106.0`. Measured now so the next
  scope does not start cold: **53 occurrences, 47 distinct, 8 already
  keyed, 39 new** — and three things that make it its own cut. It carries
  the **secret-reveal copy** (*"このシークレットは今だけ表示されます。"*,
  *"後から再度表示することはできません"*), the highest-stakes operator copy
  in this programme. It has a **composed sentence with an interpolated
  verb** (`クライアント「{}」の{}` with `revealed.verb`), which does not
  survive translation as a frame and needs one key per case. And several of
  its sentences are **split across source lines** (`:291-293`), so the 47
  distinct count overstates the sentence count — joining them is part of
  the work, not a detail.
- **The English-literal surfaces** — `admin/`, `tenancy_console/`,
  `tenant_admin/`, roughly 790 of the ceiling's 1,084. A different problem,
  no slice plan yet, and not this cut's.
- **No new route, no new query parameter, no `.json` payload change.**
  `route-contracts-check.sh` must still read **197 routes, 0 added, 0
  removed**.
- **No `<h1>` or title re-wording** beyond keying what is already there
  (R2).

## 8. Assert machine-checkable things mechanically

```sh
# 1. No Japanese anywhere in console.rs OR tenancy.rs -- code or doc
#    comment, since T6 translates the comments too. Expect: no output.
grep -nP '[\x{3040}-\x{30ff}\x{4e00}-\x{9fff}]' crates/frontend/src/pages/operator/console.rs \
                                                   crates/frontend/src/pages/operator/tenancy.rs
# 2. No hardcoded lang left on the seven components. Expect: no output.
grep -n 'lang="ja"' crates/frontend/src/pages/operator/console.rs
# 3. Exactly one console route still pins Japanese (clients.rs).
grep -rn "Locale::Ja" crates/backend/src/routes/admin/console/*.rs
# 4. Exactly seven console routes negotiate.
grep -rln "resolve_locale" crates/backend/src/routes/admin/console/ | wc -l
# 5. The skip link is gone from all three frames. Expect: no output.
grep -rn "メインコンテンツへスキップ" crates/frontend/src/
# 6. The screen-3 title pins still pass, untouched.
cargo test -p cesauth-core screen3_titles
# 7. Non-test code changed only where §6 says -- hunk headers, not filenames.
git diff -U0 da7785d -- crates/ scripts/ | grep '^@@' | wc -l
```

## 9. What must NOT be claimed

- **Not that the operator console is bilingual.** After this slice,
  **twelve of thirteen** shell-rendering screens negotiate; `clients.rs` is
  the thirteenth. Give the number with the command.
- **Not that the frontend holds no Japanese.** After this slice and
  `0.106.0`, the parse finds none outside test fixtures — say *outside test
  fixtures*, and name the parse.
- **Not that the ceiling going to 0 proves the file holds no English
  literal.** It means this matcher finds nothing, which is a floor.
- **Not that a local bundle figure is comparable to CI's.**

## 10. Acceptance criteria

G1 cleared before code. T1–T5 landed. Seven routes verified over real HTTP
— `wrangler dev --local`, `{en, ja, absent}`, bearer redacted; **seven
routes × three is twenty-one requests**, and that is the cost of a
seven-component slice, so budget it or say which subset you drove and why.
`screen3_titles.rs` green untouched. Ceiling rows at the matcher's real
values with the gate clean. 197 routes. Host tests ≥ 1,728 with 12 lines
and 0 failed. Every figure carrying the command that produced it.

## 11. Known risks

1. **Seven `<main lang>` sites.** Nothing in the build catches a miss.
2. **Six `← コンソール` occurrences** must all route to the one existing
   key; minting a second is a build failure, and keying five of six is a
   silent inconsistency.
3. **The four placeholder screens are the ones nobody looks at**, which is
   exactly where a `lookup` left unconverted survives review.
4. **The ceiling is value-based** in both directions: a row that does not
   equal the matcher's count fails, whether too high or too low.

## 12. Review request

Write to `.git-exclude/review-request/`. Include: the G1 table as its own
redirected file, with the both-locale collision check's output; the
implementation summary; deviations from §6; the HTTP evidence; §8's output
verbatim; every gate from §3 re-run with its own command named; and the
bundle handled per §9 or declared not measured, with the reason.
