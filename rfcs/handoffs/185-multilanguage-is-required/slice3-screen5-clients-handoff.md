# Developer Handoff — RFC 185 §5.3, screen 5: the OIDC client manager, and the gate that locks the console

**RFC.** `rfcs/accepted/185-multilanguage-is-required-and-the-csr-app-has-no-locale-at-all.md` §5.3
**Previous slices.** screen 1 `0.100.0` (5 keys) · screen 2 `0.102.0` (31) ·
screen 3 `0.104.0` (20 + the shared shell) · screen 4 `0.105.0` (9 + the
three skip links)
**Baseline.** `5483791` / tag `0.105.0`
**Level.** Minor — the thirteenth and last shell-rendering operator screen
negotiates, and a new gate keeps all thirteen that way.

---

## 1. Purpose

Convert `crates/frontend/src/pages/operator/clients.rs` — the OIDC client
manager, 565 lines, one component — and flip
`routes/admin/console/clients.rs`, the last route pinning `Locale::Ja`.
Then add the gate that fails if any of the thirteen stops negotiating.

## 2. This is the heaviest copy slice in the programme, and the only one
## whose code shape has to change

Measured against the 281-arm catalog at `5483791`:

```
pages/operator/clients.rs: 53 occurrences, 47 distinct, 9 keyed, 38 new
```

**The 38 become roughly 32 keys**, because six of them are fragments of
three sentences and one is a parser artifact. §3 names each merge; your G1
confirms or corrects the arithmetic. Either way this is the largest key
table since screen 2's 31 — and unlike screen 2, **three of these strings
cannot be keyed as they stand.**

`GenericErrorOccurred`, minted last cut for exactly this file, already
covers `clients.rs:126`. That ruling has now paid for itself; do not mint a
second.

## 3. The three structural problems, with the shape each must take

**S1. A sentence wrapped around interpolated markup.** Two of them:

```rust
// :275
<p>"クライアント "<strong>{label}</strong>" を削除します。この操作は元に戻せません。"</p>
// :289
<p>"クライアント "<strong>{label}</strong>" のシークレットを再発行します。"</p>
```

Keyed as prefix + suffix, this cannot be translated: the two halves are
only a sentence in Japanese word order. **One key per sentence, with a
`{name}` placeholder**, substituted the way this catalog already does it
(`audit_chain.rs:127` → `lookup(key, locale).replace("{seq}", …)`, and the
catalog's own doc comments at `mod.rs:284` and `:480` document the
convention). To keep the client name bold, split the looked-up value on the
placeholder and interleave the markup:

```rust
let v = lookup(MessageKey::ClientsDeleteConfirmBody, locale);
let (pre, post) = v.split_once("{name}").expect("…");   // not unwrap_or
view! { <p>{pre}<strong>{label}</strong>{post}</p> }
```

**`expect`, not `unwrap_or((v, ""))`.** A fallback that silently renders
the sentence without the client name, on a delete confirmation, is worse
than a panic in a CSR component — and T6 makes the panic unreachable.

**Beware the prefix that looks keyed.** `"クライアント "` normalises to
`クライアント`, which **matches the existing `SessionsLabelClient`**. Reusing
a field-label key as a sentence prefix is exactly the trap S1 exists to
close. After this slice, `SessionsLabelClient` is **not** used by this
file.

**S2. A noun-slot frame with an interpolated verb.** `:435`:

```rust
<h2>{format!("クライアント「{}」の{}", revealed.client_label, revealed.verb)}</h2>
```

where `SecretReveal.verb: &'static str` is `"再発行"` (`:237`) or `"作成"`
(`:325`). English has no frame that takes those two nouns in that slot —
*"Client X's re-issue"* is not a sentence anyone writes. **Two keys, two
whole sentences, each with `{name}`**, and the struct field becomes the key
rather than the word:

```rust
struct SecretReveal { …, heading: MessageKey }   // was: verb: &'static str
```

Both call sites already know which case they are. This is the one place in
this slice where the diff is a code shape, not a lookup.

**S3. Adjacent string literals that are one sentence.** `:291-293` (three
fragments of one warning), `:437-438` (a bold sentence plus its
continuation), `:530-532` (three fragments in the create form). The view
macro concatenates them; a translation cannot be assembled from the pieces.
Each group becomes **one key per sentence** — `:437-438` stays two keys
because the emphasis is on the first sentence and that emphasis is
meaningful on a one-time secret display; `:291-293` and `:530-532` each
collapse to one.

## 4. Facts already measured — do not re-derive

- **9 keys already cover 9 of the 53 occurrences**: `FetchUnauthorized`,
  `FetchFailed`, `GenericErrorOccurred`, `OidcClientsTitle`,
  `OperatorConsoleBackLink`, `FetchLoading`, `TenantDeletionCancelButton`,
  `TenantDeletionColActions`, and `SessionsLabelClient` — **which §3's S1
  retires from this file.** Reuse the other eight; minting a parallel key
  for any of their values fails
  `no_two_keys_share_text_within_a_locale`, which compares exact strings
  in **both** locales (281 arms today; screen 3's table failed this in
  English, screen 4's passed it).
- **One `<main lang="ja">`**, at `:252`, and its `aria-label` is Japanese
  too (`aria-label="OIDC クライアント管理"`) — a string a screen reader
  speaks and an eye never sees. So is `:274`'s and `:288`'s
  `role="alertdialog" aria-label=…`. All three are copy, not markup.
- **Four Japanese doc-comment lines** in this file
  (`grep -cP '^\s*(//!|///).*[CJK]'` → 4). Screens 3 and 4 translated
  theirs; `audit.rs` and `audit_chain.rs` were authored in English. T4
  closes the last of them.
- **`routes/admin/console/clients.rs:96` is the last `Locale::Ja` in
  code** under `routes/admin/{console,tenancy_console}`. The only other
  two matches in those trees are comments, in `audit.rs:69` and
  `audit_chain.rs:102`.
- **Thirteen routes render an operator shell**, twelve of them already
  negotiating. Enumerated, with the command, in §6 T7.
- **Baseline gates**, each with its command:
  `cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend -p cesauth-backend -p cesauth-adapter-cloudflare --features cesauth-frontend/csr`
  → **1,728 / 0 / 4 across 12 `test result:` lines**;
  `cargo test -p cesauth-migrate-test --test migration_chain` → **39**;
  `bash scripts/route-contracts-check.sh` → **197 routes**;
  `bash scripts/drift-scan.sh` → clean, **103 / 65 / 69**. Bundle: CI is
  the authority — **904,367 B gzip at `0.105.0`**.

## 5. Report-and-stop gate: G1

**The whole key table, both locales, before any of it is written** — and
this time the table has to carry the most dangerous copy in the programme.
Run the both-locale collision check against all 281 arms **before**
submitting, as screen 4 did.

Four copy questions it must answer rather than settle:

1. **The one-time-secret warnings** (`:437-438`, `:530-532`). These tell an
   operator that a credential will never be shown again. If the English
   understates it, someone loses a secret and re-issues in production. Give
   both locales and say what each sentence is for.
2. **Three words for re-issue** — `再発行` (`:237`, the verb slot S2
   removes), `シークレット再発行` (`:400`, the table action) and
   `再発行する` (`:297`, the confirm button) — and **two for delete**,
   `削除` (`:406`) and `削除する` (`:278`). The duplicate-text test forbids
   two keys sharing one English value, so you cannot render both as
   *"Delete"*: decide what the table action and the confirm button each
   say, in both locales, and keep the pair distinguishable by more than
   politeness.
3. **`応答の解析に失敗しました。`** (`:241`, `:490`) is a fourth failure
   phrasing beside `FetchFailed`, `GenericErrorOccurred` and screen 4's
   status-check key. It is genuinely a different condition (the response
   arrived and did not parse), so I expect its own key — but its English
   must sit in the same *"Failed to …"* family that `0.104.0` and `0.105.0`
   put the others in.
4. **S2's two headings**, which replace the verb frame. Propose both
   sentences; they are the first thing an operator reads on a screen that
   is showing a secret.

## 6. Change scope

| # | Task | Files |
|---|---|---|
| **T1** | ~32 new `MessageKey`s, both locales, in the enum, the `lookup` match and **both** `lookup_completeness.rs` lists | `crates/core/src/i18n/{mod.rs,tests/lookup_completeness.rs}` |
| **T2** | The component takes `mounted_locale()`, every literal and every `aria-label` through `lookup`, `<main lang="ja">` → `locale.bcp47()`, and §3's S1/S2/S3 shapes applied | `crates/frontend/src/pages/operator/clients.rs` |
| **T3** | `Locale::Ja` → `crate::i18n::resolve_locale(&req)` | `routes/admin/console/clients.rs` |
| **T4** | The four Japanese doc comments become English | `crates/frontend/src/pages/operator/clients.rs` |
| **T5** | The ceiling row for the file, set to **whatever the matcher now produces** — it will not be 0, because the file also holds English literals, and a row must equal the real count | `scripts/drift-scan.sh` |
| **T6** | A test per placeholder-bearing key: its value contains `{name}` **exactly once** in **both** locales | `crates/core/src/i18n/tests/` |
| **T7** | **The negotiation gate** — see below | `scripts/drift-scan.sh` |

**T6 is the assertion nothing else makes.** `split_once` on a value whose
placeholder was dropped by a translator, or doubled, silently changes a
delete confirmation. One `matches("{name}").count() == 1` per key per
locale closes it.

**T7, designed here so the gate is not invented mid-cut.** Enumerate every
file under `crates/backend/src/routes/admin/{console,tenancy_console}/`
that calls `operator_json_api::shell(` or `leptos_shell::leptos_html_shell(`
— excluding the helper's own definition — and require each to contain
`crate::i18n::resolve_locale`. **Pin the expected count at 13** and fail if
the set changes in either direction: a route that stops negotiating, and a
new operator screen that never started. Report the figure on its own
`drift-scan` line, in the shape the other coverage lines use. Today the
enumeration gives:

```sh
for d in console tenancy_console; do for f in crates/backend/src/routes/admin/$d/*.rs; do
  grep -q "operator_json_api::shell(\|leptos_html_shell(" "$f" && \
    printf "%-44s %s\n" "$f" "$(grep -q resolve_locale "$f" && echo ok || echo PINNED)"
done; done
# 13 files; 12 ok; console/clients.rs PINNED — and that is T3.
```

**If the copy review in §5 runs long, T7 ships separately and says so.**
Twelve routes' worth of conversion is the thing with a deadline risk; the
gate is thirty lines and can be its own cut. What must not happen is T7
quietly disappearing.

## 7. Explicit non-change scope

- **The three `frame.rs` files' hardcoded `<html lang="ja">`** and the
  acceptance harness's `admin_fixtures_render_in_ja_only_per_adr_013`
  inversion. That pin is now correctly annotated; inverting it belongs to
  the cut that converts the server-rendered admin family.
- **The ~790 English literals** under `admin/`, `tenancy_console/`,
  `tenant_admin/`. A different problem, no slice plan yet.
- **No new route, parameter or payload.** `route-contracts-check.sh` must
  still read **197 routes, 0 added, 0 removed**.
- **No change to what a secret is, how it is generated, or how long it is
  shown.** This slice translates the warnings; it does not touch the
  reveal mechanism.

## 8. Assert machine-checkable things mechanically

Each expectation below is what the command returns **today**, so a
difference is a signal and not a surprise.

```sh
# 1. No Japanese left anywhere in the file, code or doc comment (T2 + T4).
#    Today: 57 lines. After: no output.
grep -cP '[\x{3040}-\x{30ff}\x{4e00}-\x{9fff}]' crates/frontend/src/pages/operator/clients.rs
# 2. The hardcoded lang is gone. Today: 1. After: 0.
grep -c 'lang="ja"' crates/frontend/src/pages/operator/clients.rs
# 3. No Locale::Ja left in code under either tree. After: exactly two
#    hits, both comments -- console/audit.rs:69 and audit_chain.rs:102.
grep -rn "Locale::Ja" crates/backend/src/routes/admin/console/ crates/backend/src/routes/admin/tenancy_console/
# 4. S1's trap, as a NEGATIVE invariant: this file must still not reference
#    SessionsLabelClient. Today 0, after 0 -- a nonzero here means the
#    field-label key was reused as a sentence prefix.
grep -c "SessionsLabelClient" crates/frontend/src/pages/operator/clients.rs
# 5. The verb field is gone (S2). Word-anchored, because `verbatim` in a
#    test name matches a bare "verb". Today: 5 lines. After: no output.
grep -n "\bverb\b" crates/frontend/src/pages/operator/clients.rs
# 6. The new gate reports 13 of 13.
bash scripts/drift-scan.sh | grep -i "negotiat"
# 7. Non-test code changed only where §6 says -- hunk headers, not filenames.
git diff -U0 5483791 -- crates/ scripts/ | grep '^@@' | wc -l
```

## 9. What must NOT be claimed

- **Not that RFC 185 is finished.** This completes **§5.3's thirteen
  operator screens**. The ~790 English literals and the three
  server-rendered frames are still outstanding, and the ADR-013 harness pin
  still inverts one day.
- **Not that the frontend holds no Japanese** — say *no Japanese under
  `pages/operator/` outside test fixtures*, and name the parse.
- **Not that the ceiling row reaching its new value means no English
  literal remains.** The row is the matcher's count, which is a floor.
- **Not that a local bundle figure is comparable to CI's.**

## 10. Acceptance criteria

G1 cleared before code, with the collision check's output attached. T1–T7
landed, or T7 explicitly deferred with a reason. The route verified over
real HTTP — `wrangler dev --local`, `{en, ja, absent}`, bearer redacted;
**one route, three requests**, which is the cheapest HTTP evidence in the
programme and therefore has no excuse. `screen3_titles.rs` green and
untouched. Ceiling row at the matcher's real value. **197 routes.** Host
tests ≥ 1,728 with 12 lines and 0 failed. Every figure with its command.

## 11. Known risks

1. **The copy is the risk, not the code.** A secret-reveal warning that
   reads weaker in English than in Japanese is a production incident with a
   paper trail pointing at this cut.
2. **S1's `split_once`** is the one place a translation error becomes a
   missing client name in a destructive confirmation. T6 or nothing.
3. **`SessionsLabelClient` looks like a legitimate reuse** and is not, at
   `:275` and `:289`.
4. **The ceiling is value-based**: the row must equal the matcher's count,
   and this file will not reach 0.
5. **T7 pins 13.** If a new operator screen lands between dispatch and
   return, the count moves and the gate's number moves with it —
   deliberately, in the same commit, with the new route negotiating.

## 12. Review request

Write to `.git-exclude/review-request/`. Include: the G1 table as its own
redirected file with the both-locale collision output; the implementation
summary; deviations from §6; the HTTP evidence; §8's output verbatim; every
gate from §4 re-run with its own command named; the new gate's line; and
the bundle handled per §9 or declared not measured, with the reason.
