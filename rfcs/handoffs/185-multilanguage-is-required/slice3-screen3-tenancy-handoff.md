# Developer Handoff — RFC 185 §5.3, screen 3: the tenancy console, and the shared shell

**RFC.** `rfcs/accepted/185-multilanguage-is-required-and-the-csr-app-has-no-locale-at-all.md` §5.3
**Previous slices.** `slice3-screen1-audit-viewer-handoff.md` (24 literals, 5
new keys), `slice3-screen2-chain-status-handoff.md` (31 new keys). Both
shipped — `0.100.0` and `0.102.0`.
**Baseline.** `1be6103` / tag `0.103.0`.
**Level.** Minor (RFC 181 default; a screen becomes bilingual, which is new
capability).

---

## 1. Purpose

Convert `crates/frontend/src/pages/operator/tenancy.rs` — **three**
components, `TenancyOverview` / `TenancyTenants` / `TenancyTenantDetail` — to
the catalog, and make the **three** routes that serve them negotiate their
locale. Along the way, parameterise the shared operator shell that **eleven**
routes call, because the three in this slice cannot negotiate while it
hardcodes `Locale::Ja`.

## 2. Why this matters

This is the operator's tenant-management surface: the tenant list, a tenant's
detail page, and the status/plan/membership actions on it. Today every word is
Japanese, inside a document that declares `lang="ja"` — truthful, and useless
to an operator who asked for English. The owner's requirement stands:
multilanguage support is required.

## 3. The shared shell is the reason this slice is shaped this way

Screens 1 and 2 each owned their route, and each route called
`leptos_shell::leptos_html_shell` directly. **The remaining eleven operator
routes do not.** They all call one helper:

```rust
// crates/backend/src/routes/admin/operator_json_api.rs:29-39
pub async fn shell<D>(req: &Request, ctx: &RouteContext<D>, title: &str) -> Result<Response> {
    let _admin = match resolve_admin(req, ctx).await? { Ok(a) => a, Err(r) => return Ok(r) };
    leptos_html_shell(req, &ctx.env, title, cesauth_core::i18n::Locale::Ja).await
}
```

`Locale::Ja` is hardcoded, and each caller passes a **hardcoded Japanese
title string**. Measured, with the command:

```sh
grep -rn "operator_json_api::shell(" crates/backend/src/   # 11 call sites
```

7 of the 11 serve `pages/operator/console.rs`'s seven components, 3 serve
this slice's `tenancy.rs`, 1 serves `clients.rs`.

**Do not make `shell()` negotiate for all eleven.** RFC 185 amendment **A5**
forbids exactly that: a route whose body is still Japanese must not be served
inside `<html lang="en">`, because that replaces a true claim with a false one
for precisely the users who expressed a preference. The shell takes the locale
as a **parameter** instead, and only this slice's three routes pass a
negotiated one. This is the same move RFC 185 §5.2 already made for
`leptos_html_shell` (`lang: &str → Locale`, shipped `0.99.0`).

## 4. Facts already measured — do not re-derive

Counts, each with the command that produced it. Re-run them if you doubt
them; do not restate them from memory.

- **The gate's own count for this file is 27.** `bash scripts/drift-scan.sh`
  → `i18n literal ceiling: scanned 103 file(s) … 66 hit … 69 ceiling
  entr(y|ies)`, and the row is `"pages/operator/tenancy.rs	27"` in
  `scripts/drift-scan.sh`'s `I18N_CEILINGS`.
- **A second, independent parse agrees on 27** and resolves it further: **27
  occurrences, 22 distinct, 4 already in the catalog, so 18 new keys.** The
  four that exist are `OperatorConsoleBackLink` (`← コンソール`),
  `FetchLoading` (`読み込み中…`), `Status` (`ステータス`) and
  `TenantDeletionColActions` (`操作`). **Reuse them.** Minting a parallel key
  with the same Japanese value fails
  `no_two_keys_share_text_within_a_locale` (`crates/core/src/i18n/tests/lookup_completeness.rs:302`).
- **Three `<main lang="ja">` attributes**, at `tenancy.rs:31`, `:71`, `:141` —
  one per component. Screen 1's finding F-C applies to each: a `<main lang>`
  overrides `<html lang>` for its whole subtree, so a document would announce
  English while every word was still read as Japanese. **No build-time signal
  exists for getting this wrong.**
- **The eleven titles.** Each caller passes the full string, e.g.
  `"テナント一覧 — cesauth"`. The established pattern composes instead
  (`routes/admin/console/audit.rs:73-75`): the key holds the screen name and
  the route appends `" — cesauth"`.
- **Baseline gates**, each with its command:
  `cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend -p cesauth-backend -p cesauth-adapter-cloudflare --features cesauth-frontend/csr`
  → **1,717 / 0 / 4 across 12 `test result:` lines**;
  `cargo test -p cesauth-migrate-test --test migration_chain` → **39**;
  `bash scripts/route-contracts-check.sh` → **197 routes**, seven coverage
  figures; `bash scripts/drift-scan.sh` → clean, **103 / 66 / 69**. Bundle:
  CI's `bundle-size.yml` is the authority — **903,469 B gzip at `0.103.0`**.
  A local figure is comparable only to another local figure taken the same
  way; a raw-byte count is not comparable to a gzip one at all.

## 5. Report-and-stop gates

**G1 — the key list, before any of it is written.** 18 body keys + 11 title
keys = **29 strings in two locales**, on an operator surface. Report the
table (key · `Ja` · `En` · where it is used) and stop. This gate has caught
something in every slice: screen 1's refused Japanese expansion, screen 2's
four already-existing keys, RFC 187's `(substring)` label over an exact-match
query.

**Three copy questions G1 must answer rather than decide silently:**

1. **Three phrasings of one failure.** `tenancy.rs` has
   `データを取得できませんでした。` (`:107`, `:195`) and
   `テナント数を取得できませんでした。` (`:45`), while the catalog's
   `FetchFailed` says `読み込みに失敗しました。再読み込みしてください。`
   **My preference, to argue with:** reuse `FetchFailed` for the two generic
   ones — which changes visible wording and therefore needs stating, not
   assuming — and keep one specific key where the message names what failed
   (the tenant count). Three phrasings of one condition on one screen family
   is the confusion the owner's philosophy names.
2. **`"cesauth コンソール"` does not fit the composed shape.** Ten titles read
   `X — cesauth`; `console/overview.rs`'s reads `cesauth コンソール`.
   Composition turns it into `コンソール — cesauth`. That is a visible change
   to the operator console's landing title: say so, with the before and
   after, rather than letting a refactor rename a page.
3. **Four of the eleven titles disagree with their own screen's `<h1>`** —
   e.g. title `安全性 — cesauth` against heading `安全性チェック`. Those four
   screens are **out of this slice** (§7), so do not touch the headings; but
   name the disagreement in the report so it is on the record before someone
   keys both and makes it permanent.

**G2 — evidence, before the cut is called done.** Over real HTTP, not a unit
test: `wrangler dev --local`, then for **each of the three routes** a request
with `Accept-Language: en`, one with `ja`, and one with no header. `en` must
give `<html lang="en">` and the English title; the other two the Japanese
form. Redact the bearer token. Screen 1's round 1 claimed parity it did not
have; this gate is why round 2 found it.

## 6. Change scope

| # | Task | Files |
|---|---|---|
| **T1** | 18 new `MessageKey`s + 11 title keys, both locales, added to the enum, the `lookup` match, and **both** lists in `lookup_completeness.rs` | `crates/core/src/i18n/mod.rs`, `crates/core/src/i18n/tests/lookup_completeness.rs` |
| **T2** | `shell()` takes `title_key: MessageKey` and `locale: Locale`, composes `format!("{} — cesauth", lookup(title_key, locale))` | `routes/admin/operator_json_api.rs` |
| **T3** | All **11** callers updated. **8 pass `Locale::Ja` explicitly**; the 3 tenancy routes pass `crate::i18n::resolve_locale(&req)` | the 11 files from §3's grep |
| **T4** | `tenancy.rs`'s three components take a `Locale` and resolve every literal through `lookup`; the three `<main lang="ja">` follow the negotiated locale | `crates/frontend/src/pages/operator/tenancy.rs` |
| **T5** | The ceiling row `pages/operator/tenancy.rs` goes **27 → 0** | `scripts/drift-scan.sh` |
| **T6** | Host tests for the eleven titles: each key's `Locale::Ja` value, composed, is **byte-identical** to the literal its route passes today | `crates/core/src/i18n/tests/` |

**T6 is the one that protects the eight screens this slice does not convert.**
A key rename that quietly changes eight operator titles has no other witness.
Capture each old literal from `git show 1be6103:<file>` and assert against it.

## 7. Explicit non-change scope

- **`pages/operator/console.rs` (7 components, 44 by the gate).** Out, and
  not for size: **four of its seven are RFC 161 placeholder screens** whose
  body is `"…は未実装です(RFC 161)。"`, and RFC 161 §9(b)/(c) — owner-approved,
  2026-10-30 — restores them as RFC 131 §0 slices. Writing English copy for a
  screen that is scheduled to be rewritten is work done to be deleted. When
  console.rs is converted, those four want **one shared not-implemented key**,
  not four bespoke sentences. Their routes keep passing `Locale::Ja`.
- **`pages/operator/clients.rs` (60 by the gate, 47 distinct, 40 new keys,
  565 lines).** Out — it is the largest copy review left in the programme and
  deserves its own cut. It also carries `aria-label="OIDC クライアント管理"`
  (`:252`), a Japanese string a screen reader speaks and an eye never sees.
- **The server-rendered admin surfaces** (`admin/`, `tenancy_console/`,
  `tenant_admin/` — about 790 of the ceiling's 1,084). Out, and they are a
  different problem: their literals are mostly **English**, so they need keys
  to become bilingual rather than to stop being monolingual Japanese.
- **No new route, no new query parameter, no change to any `.json` payload.**
  `route-contracts-check.sh` must still read **197 routes, 0 added, 0
  removed**.

## 8. Assert machine-checkable things mechanically

```sh
# 1. No Japanese left in the converted file, either shape.  Expect: no output.
grep -nP '[\x{3040}-\x{30ff}\x{4e00}-\x{9fff}]' crates/frontend/src/pages/operator/tenancy.rs
# 2. No hardcoded lang on the three components.             Expect: no output.
grep -n 'lang="ja"' crates/frontend/src/pages/operator/tenancy.rs
# 3. Exactly 8 callers still pin Japanese, exactly 3 negotiate.
grep -rc "Locale::Ja" crates/backend/src/routes/admin/console/ crates/backend/src/routes/admin/tenancy_console/
grep -rn "resolve_locale" crates/backend/src/routes/admin/tenancy_console/
# 4. The ceiling row is 0 and the gate agrees.              Expect: clean.
bash scripts/drift-scan.sh | grep "i18n literal ceiling"
# 5. Non-test code changed only where §6 says — hunk headers, not filenames.
git diff -U0 1be6103 -- crates/ scripts/ | grep '^@@' | wc -l
```

## 9. What must NOT be claimed

- **Not that the operator console is bilingual.** **Five of its thirteen
  shell-rendering screens** will be: `audit`, `audit/chain` and this slice's
  three. **Eight still pin `Locale::Ja` by design**, and both numbers are
  grep-able — the thirteen is
  `grep -rn "leptos_html_shell(\|operator_json_api::shell(" routes/admin/{console,tenancy_console}/`
  minus the helper's own definition. Say *five of thirteen*, with the
  command.
- **Not that the eleven titles are unchanged** if any `Ja` value differs by a
  byte from the literal it replaces. T6 decides that, not a reading.
- **Not that a local bundle figure is comparable to CI's.** This programme
  has already lost a round to a raw-byte number diffed against a gzip one.
- **Not that the ceiling going to 0 means the screen holds no English
  literal.** The ceiling counts both scripts; a `0` means this matcher finds
  nothing, which is a floor, not a proof.

## 10. Acceptance criteria

G1 cleared before code; T1–T6 landed; the three routes verified over real
HTTP in both locales plus no-header; ceiling row 27 → 0 with the gate clean;
197 routes unchanged; host tests ≥ 1,717 with 12 `test result:` lines and 0
failed; every figure in the report carrying the command that produced it.

## 11. Known risks

1. **The `<main lang>` trap, three times.** Nothing in the build catches it.
2. **The eight unconverted titles.** The only thing standing between a
   mechanical refactor and eight silently renamed operator pages is T6.
3. **`no_two_keys_share_text_within_a_locale`** fails on a parallel key for
   an existing value. Four values already exist (§4).
4. **The ceiling is value-based**: a file's real count must *equal* its row.
   Converting without editing the row fails the gate, and so does editing the
   row to a number the matcher does not produce.

## 12. Review request

Write to `.git-exclude/review-request/`. Include: the G1 table as its own
redirected file; the implementation summary; deviations from §6; G2's HTTP
evidence with the bearer redacted; §8's output verbatim; every gate from §4
re-run **with its own command named**; and the bundle handled per §9's rule
or declared not measured, with the reason.
