# Developer Handoff — RFC 185, cut 1: the gate, the type, and the record

**Governing RFC.** `rfcs/accepted/185-multilanguage-is-required-and-the-csr-app-has-no-locale-at-all.md`

**Read §8 of that RFC first.** It lists **seven amendments** made after the owner
accepted it, while this handoff was being scoped. Four of the RFC's measurements
were wrong, its title is wrong, and **§5.1's central proposal was unsafe**. The
amendments are marked inline at the point where each wrong claim sits, with the
original kept visible. Where the RFC body and §8 disagree, **§8 wins**, and this
handoff is built on §8.

**Target release.** **Minor.** A patch argument exists and is refused:

- (a) is not satisfied. This cut adds **a new CI gate**, which
  `rfcs/handoffs/TEMPLATE.md` names as disqualifying in those words — it changes
  what a contributor must satisfy to merge.
- (b) is satisfied in the narrow sense (no URL, no request field, no header; every
  crate is `publish = false`), and that is not enough on its own.
- Separately, §5.4 reverses a rule that nine documents state as settled law. A
  release that changes what the project's documented policy *is* is not a patch.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. RFC 185 §5.5 (how many locales) is open and the owner's,
and **does not block this cut** — every item below is locale-count-agnostic.

---

## 1. Purpose

After this lands:

1. **A new natural-language literal anywhere in `crates/frontend/src` fails the
   build.** Japanese *and* English. Today nothing checks it, and the count has
   risen in each of the last three releases.
2. `leptos_html_shell` takes a **`Locale`**, not a `&str`. A call site can no
   longer emit a language tag that no catalog locale corresponds to, and the
   value the shell emits and the value `mounted_locale()` parses are the same
   vocabulary **by construction** rather than by both happening to spell `"ja"`
   the same way.
3. The **two** natural-language literals in the frontend that both render today
   and are wrong are gone.
4. The record says what the owner decided. ADR-013's i18n-3 deferral is closed,
   `operator_shell.rs:9` stops attributing a locale policy to an RFC about
   introspect handler wiring, and RFC 072's "constitution" is annotated as the
   scope exclusion it was.

**What does not change: any screen's rendered language, and any `<html lang>`
value.** See §3, D1. The report must say this in those words.

## 2. Why this matters

**The gate.** This project's dominant failure mode is a documented rule with no
gate. RFC 185 §2 found **nine** documents stating a Japanese-only policy, a code
comment citing the wrong RFC for it, and a handoff of mine calling it a resolved
decision — and in the same tree, `components/shells/operator_shell.rs:108` renders
`"Safety"`, one English word, between ten `lookup(…, LOCALE)` siblings, inside the
shell whose own module doc declares the console Japanese-only. Nine documents and
no check produced both the rule and its violation.

**The type.** `routes/leptos_shell.rs:92` takes `lang: &str` and gets a hardcoded
literal at all ten call sites. `crates/frontend/src/app.rs:64`'s `mounted_locale()`
reads `document.documentElement.lang` back through `Locale::from_primary_subtag`,
which returns `Option` and is `unwrap_or_default()`-ed to `Ja`. **A typo in any of
those ten literals would therefore produce a silently wrong locale and no error
anywhere** — not a compile error, not a warning, not a log line. Nothing today
asserts the two ends agree.

**The two live literals.** `crates/frontend/src/templates/security_center.rs:307`
emits `aria-label="セッション {sid}"` hardcoded, inside a function where `locale`
is already a parameter and where 63 sibling strings in that directory go through
`lookup(…, locale)`. The Security Center is **server-rendered**, so it *does*
negotiate: an `Accept-Language: en` user gets the whole screen in English and this
one `aria-label` in Japanese — announced by a screen reader, invisible on screen.
`templates/totp.rs:191` is the same shape (`gate_legend = "保存確認"`) and carries a
comment excusing itself: *"admin-side is JA; end-user route is also fine with
short literal"*.

**Honest severity for the rest.** The other 210 literals are **latent**, not live:
`pages/`'s 198 are each in the language its surface's `<html lang>` already claims,
and `components/`'s 12 are in files with **zero mount sites** (§4, F4). This cut
is a gate and a type. It fixes two user-visible strings. That is the whole
user-visible payload and the report should not inflate it.

## 3. Resolved decisions — do not re-open

**D1. `<html lang>` is NOT negotiated in this cut, and that reverses RFC 185 §5.1.**
Amendment A5. `<html lang>` is a claim about what language the content is in.
All ten shell surfaces are monolingual today **and their literals are truthful**:
the three `"ja"` sites serve the operator screens (177 Japanese literals, 0 catalog
calls), the seven `"en"` sites serve `pages/login.rs`, `pages/sessions.rs`,
`pages/security_center.rs`, `pages/totp.rs` and `pages/tenant_admin/*` (0 Japanese
literals, 0 catalog calls — i.e. hardcoded English). Resolving `lang` from
`Accept-Language` today would make it **false for exactly the users who stated a
preference**. The flip moves into §5.3, per screen, in the same commit that
converts that screen. **Do not call `resolve_locale` from `leptos_shell.rs` in
this cut.** If you think this is wrong, say so in the report — but do not build it.

**D2. `mounted_locale()` stays uncalled.** It is correct and it has no caller
(amendment A3). There is nothing for it to feed until a screen consults the
catalog. Wiring it now would be a caller that reads a value and discards it.

**D3. `components/`'s 12 English literals are baselined, not localised.** All five
affected files have zero mount sites (§4, F4), both shells included. Converting
code that renders nowhere is RFC 131 R3's work and would be done blind — you could
not look at the result. The ceiling stops it growing; R3 pays it down when it
mounts them.

**D4. The baseline is a per-file descending ceiling, not an exemption list.**
A 212-entry literal list would be edited by the very commits meant to police it,
and §5.3 would edit it on every screen. Eighteen per-file numbers that may only go
**down** forbid new debt, need no edit when a literal is deleted, and fail loudly
when one is added.

**D5. Ceiling slack is a hard failure.** A file whose real count has dropped
*below* its ceiling fails until the ceiling is lowered. Without this the ceiling
accumulates headroom and silently stops being a gate — which is exactly what
`E6_BEARER_LEGACY_EXEMPT`'s own staleness rule exists to prevent.
`scripts/route-contracts-check.sh:1961-1979` is the implementation to copy.

**D6. The matcher must catch English as well as Japanese.** Amendment A7: RFC 185
§3 counted Japanese literals only, so by construction it could not see the 33
English ones, and it reported `components/` clean while 12 sat in it. A
Japanese-only gate would ship that same blindness permanently.

**D7. Test code is out of scope by construction, not by list.** 31 of the
frontend's Japanese strings are catalog assertions (`auth_shell.rs`'s
`footer_strings` tests, `admin/audit.rs`'s 9, `templates/tests/*`'s 25). A gate
that fires on those is a gate that gets deleted. Exclude by path (`tests/`,
`*tests.rs`) **and** by truncating each file at its first `#[cfg(test)]` line.

**D8. The gate lives in `scripts/drift-scan.sh`**, as one more section beside the
existing nine, not in a new script. It is already wired to CI
(`.github/workflows/drift-scan.yml`), already has the section idiom, and
`drift-scan.sh` runs in ~1.0 s — a few greps over ~105 files keeps it there.

**D9. `role_impact.rs` needs no special exemption.** Its ceiling of 3 is the
exemption. Its actual problem — a sentence composed from `"Grant "` `{role}`
`" to "` `{subject}` `" for "` `{scope}` `"."`, which **no assignment of
translations renders correctly in Japanese** because the verb goes last — is
recorded in `ROADMAP.md` and is not yours.

## 4. Facts already measured — do not re-derive

Treat as measured ground. **If any of this fails to reproduce on your run, that is
a finding — report it rather than working around it.**

**F1 — the matcher and the baseline.** This probe produced every figure below.
It is a probe, not the gate; the gate is yours to write (§6 T1), and it must
reproduce these numbers.

```sh
# Matcher N, candidate. Non-test code only.
#   (a) any string literal containing kana or CJK
#   (b) any standalone view! text child containing two consecutive ASCII
#       letters, excluding all-lowercase-hyphenated words (CSS class names)
for d in pages components admin templates tenancy_console tenant_admin; do
  for f in $(find "crates/frontend/src/$d" -name '*.rs' \
                  -not -path '*/tests/*' -not -name 'tests.rs' | sort); do
    body=$(awk '/^#\[cfg\(test\)\]/{exit} {print}' "$f" | grep -vP '^\s*//')
    a=$(printf '%s\n' "$body" \
        | grep -oP '"[^"]*[\x{3040}-\x{30ff}\x{4e00}-\x{9fff}][^"]*"' | wc -l || true)
    b=$(printf '%s\n' "$body" | grep -oP '^\s*"[^"]*"\s*$' \
        | sed -E 's/^\s*//; s/\s*$//' | grep -P '[A-Za-z]{2}' \
        | grep -vP '^"[a-z][a-z-]*( [a-z][a-z-]*)*"$' \
        | grep -vP '[\x{3040}-\x{30ff}\x{4e00}-\x{9fff}]' | wc -l || true)
    [ "$((a+b))" -gt 0 ] && printf '%s %s (cjk %s + en %s)\n' "$f" "$((a+b))" "$a" "$b"
  done
done
```

| file | ceiling | cjk | en |
|---|---|---|---|
| `pages/operator/clients.rs` | **52** | 52 | 0 |
| `pages/operator/audit_chain.rs` | **41** | 41 | 0 |
| `pages/operator/console.rs` | **33** | 33 | 0 |
| `pages/operator/tenancy.rs` | **27** | 27 | 0 |
| `pages/operator/audit.rs` | **24** | 24 | 0 |
| `pages/security_center.rs` | **9** | 0 | 9 |
| `pages/login.rs` | **3** | 0 | 3 |
| `pages/sessions.rs` | **3** | 0 | 3 |
| `pages/totp.rs` | **3** | 0 | 3 |
| `pages/tenant_admin/overview.rs` | **2** | 0 | 2 |
| `pages/tenant_admin/invitations.rs` | **1** | 0 | 1 |
| `components/primitives/confirm_dialog.rs` | **4** | 0 | 4 |
| `components/domain/role_impact.rs` | **3** | 0 | 3 |
| `components/primitives/density_toggle.rs` | **2** | 0 | 2 |
| `components/shells/tenant_admin_shell.rs` | **2** | 0 | 2 |
| `components/shells/operator_shell.rs` | **1** | 0 | 1 |
| `templates/security_center.rs` | 1 → **0** after T3 | 1 | 0 |
| `templates/totp.rs` | 1 → **0** after T3 | 1 | 0 |

Subtotals: `pages/` **198** across 11 of 18 files · `components/` **12** across 5
of 31 · `admin/` **0** · `templates/` **2 → 0** · `tenancy_console/` **0** ·
`tenant_admin/` **0**. **Frontend total 212, and 210 after T3.**

**F2 — matcher vocabulary, both directions.** Stated so you do not rediscover it
as a surprise, and so the report can be honest about what the gate does not see.

- **Known false positives, accepted**: `components/domain/role_impact.rs`'s
  `" to "` and `" for "` are single lowercase words and are therefore exempted by
  the class-name rule, so its ceiling is 3 where a human would count 4. Harmless —
  the ceiling only needs to be a number that cannot rise.
- **Known false negatives, accepted and named**: a natural-language literal that
  is *not* a standalone `view!` text child and contains no kana/CJK is invisible
  to clause (b) — an English `attr:title="…"`, an English `aria-label="…"`, an
  English string returned from a helper function. Clause (a) catches none of these
  either, because they are not Japanese. **The gate therefore bounds the Japanese
  debt exactly and the English debt partially.** Say so in the report. Do not
  widen the matcher to close this in this cut (§7).
- **Deliberately not matched**: CSS class names, `" · "`, `" — "`, `"."`, `" "`,
  `""`, `"✕"`.

**F3 — `mounted_locale` exists and is uncalled.** `crates/frontend/src/app.rs:64`.
`grep -rn "mounted_locale" --include="*.rs" crates/` returns the definition and
nothing else. It is `pub`, which is why `cargo check` says nothing about it.

**F4 — the whole of `components/` is dormant.**
`grep -rn "<AuthShell\|<OperatorShell\|<TenantAdminShell\|<ConfirmDialog\|<DensityToggle\|<RoleImpact" --include="*.rs" crates/frontend/src`
finds **zero** mount sites outside `components/` itself. RFC 179 recorded this for
the 17 imported primitives; it holds for **both shells** too, so RFC 180's 54
catalog calls have never executed.

**F5 — the ten shell call sites**, with the locale each one's content is actually
written in. `grep -rn "leptos_html_shell" --include="*.rs" crates/`:

| file:line | current `lang` | content language |
|---|---|---|
| `routes/ui.rs:25` | `"en"` | En |
| `routes/me/sessions.rs:58` | `"en"` | En |
| `routes/me/security.rs:69` | `"en"` | En |
| `routes/me/totp/enroll.rs:164` | `"en"` | En |
| `routes/me/totp/disable.rs:154` | `"en"` | En |
| `routes/invitations.rs:386` | `"en"` | En |
| `routes/admin/tenant_admin/json_api.rs:48` | `"en"` | En |
| `routes/admin/operator_json_api.rs:38` | `"ja"` | Ja |
| `routes/admin/console/audit.rs:67` | `"ja"` | Ja |
| `routes/admin/console/audit_chain.rs:101` | `"ja"` | Ja |

**F6 — `crate::i18n::locale_str(Locale) -> &'static str` already exists**
(`crates/backend/src/i18n.rs:92`) and returns exactly `"ja"`/`"en"`. Use it; do not
write a second mapping.

**F7 — baseline gates on `884f92c` (tag `0.98.0`).** Host tests **1,721 passed /
0 failed / 4 ignored** across **12** `test result:` lines. `route-contracts-check.sh`
exit 0, **197 routes**, E3 47 · GATE_42 24 · NONCE 13 · E4 219 · E5 19 · E6 95 ·
E7 156. `drift-scan.sh` clean. `cargo check -p cesauth-frontend --features csr`
emits **8** warnings, `cesauth-core` **1** — both pre-existing; this cut must not
raise either.

## 5. Report-and-stop gates

**G1 — the matcher's full hit list, before it is wired into CI.** Run your
implementation of matcher N over `crates/frontend/src` and report **every hit**,
file:line and literal, with your classification of each as (i) real
natural-language debt, (ii) false positive, or (iii) uncertain. Report before
committing the ceiling table. The reason is §4 F2: this matcher was designed
against a 71-line sample, and the exemption rule for CSS class names is a
heuristic. **An exemption list built from a guess is the failure this gate exists
to prevent.** If your list disagrees with F1's eighteen rows, that disagreement is
the finding — report it, do not reconcile by adjusting the matcher until the
numbers match.

**G2 — the ceiling's staleness rule, before T3.** T3 deletes two literals, which
takes `templates/` from 2 to 0 and is therefore the **first real exercise of D5**.
Report whether your staleness check fires on the intermediate state (literal
removed, ceiling not yet lowered) *before* you lower the ceilings. A staleness
rule that cannot be shown to fire on a real transition is not a rule. This is the
fires/does-not-fire pair for D5 and it is free — do not simulate it.

## 6. Change scope

Order matters: the gate (T1) is **written** first but **wired into CI last**, so it
lands green rather than merged red.

| # | Task | Files |
|---|---|---|
| **T1** | Implement matcher N and the per-file ceiling table as a new `drift-scan.sh` section. Report G1 before fixing the table. Hard failure on: a file over its ceiling; a file **under** its ceiling (D5); a ceiling naming a file that does not exist; a file hit by the matcher with **no** ceiling entry at all (the "new file" case — this is the one a ceiling table gets wrong, and a new screen with 40 literals must fail, not pass unlisted) | `scripts/drift-scan.sh` |
| **T2** | `leptos_html_shell`'s `lang: &str` → `lang: Locale`; `<html lang="{lang}">` becomes `locale_str(lang)` (F6). Update all ten call sites (F5) and the two `shell()` wrappers that forward it, passing the locale from F5's right-hand column — **values unchanged** | `crates/backend/src/routes/leptos_shell.rs`, the ten files in F5, `routes/admin/operator_json_api.rs`, `routes/admin/tenant_admin/json_api.rs` |
| **T3** | Delete the two live literals. Add one `MessageKey` each in **both** locales; `locale` is already a parameter in both functions. Then lower both ceilings to 0 — **after** reporting G2 | `crates/frontend/src/templates/security_center.rs:307`, `crates/frontend/src/templates/totp.rs:191`, `crates/core/src/i18n/mod.rs` (+ its completeness lists — see §8) |
| **T4** | The round-trip test: for **every** `Locale` variant, `Locale::from_primary_subtag(locale_str(v)) == Some(v)`. Exhaustive over the enum, not two hardcoded cases — see §8 | `crates/backend/src/i18n.rs` (test module) |
| **T5** | §5.4, the record. (a) `docs/src/expert/adr/013-i18n.md`: amend the **Out of scope** list to state the owner's 2026-11-11 decision (*"Multilanguage support is required"*) and that the i18n-3 deferral is **closed** — its own trigger was *"if/when demand surfaces"* and the demand has surfaced. (b) `crates/frontend/src/components/shells/operator_shell.rs:9`: the comment attributes the locale policy to **RFC 034**, which is `034-introspect-handler-wiring.md` and contains no mention of locale — correct it to cite ADR-013 and RFC 185. (c) `rfcs/done/072-html-lang-locale.md`: a dated note that the "constitution" at `:88` and the derived permanent `<html lang="ja">` at `:96` rest on a **scope exclusion**, not a decision, and that RFC 185 closed it | `docs/src/expert/adr/013-i18n.md`, `crates/frontend/src/components/shells/operator_shell.rs`, `rfcs/done/072-html-lang-locale.md` |
| **T6** | Wire T1's section into the `drift-scan.sh` run and confirm green. **Last.** | — |

## 7. Explicit non-change scope

- **Do not negotiate `<html lang>`.** D1. Do not call `resolve_locale` from
  `leptos_shell.rs`.
- **Do not call `mounted_locale()`.** D2.
- **Do not localise `pages/`.** That is §5.3, per screen, and it is 198 literals.
- **Do not localise `components/`.** D3 — dormant, RFC 131 R3's.
- **Do not widen matcher N** to catch English attribute values or helper returns
  (F2's named false negatives). A wider matcher needs its own measured hit list;
  this cut ships the one that has one.
- **Do not touch the 27 `<title>` literals** at the shell and wrapper call sites.
  They are in `crates/backend`, outside the gate's scope, and they belong with
  §5.3's per-screen conversion — `ROADMAP.md` has the row.
- **Do not fix `role_impact.rs`'s composed sentence.** D9.
- **Do not change `Locale`'s closed-enum design.** RFC 185 §6, and §5.5 is open.
- **Do not fix the 8 pre-existing `cesauth-frontend` warnings or the 1 in
  `cesauth-core`.** `ROADMAP.md` owns them. Do not let them grow either (F7).
- Standing rules: **no `cargo fmt`**; **no route-string changes**.

## 8. Task detail worth stating explicitly

**T1 — the pipefail/SIGPIPE class applies here, and the polarity is the dangerous
one.** RFC 182. In this gate, "no match" is the **pass** condition for most greps,
so a match→miss error is a **false pass**: a literal becomes invisible and the
ceiling check passes on a count that is too low. Note also that the probe in §4 F1
needs `|| true` on every `| wc -l`, because `grep` exits 1 on no match and
`drift-scan.sh` opens `set -euo pipefail` — the first version of that probe died
on exactly that. Prefer here-strings over pipes into `grep -q`/`head`, and state
per site whether a miss would produce a false failure or a false pass.

**T1 — the "new file" case is the one ceiling tables get wrong.** A file the
matcher hits with no entry in the table must be a **hard failure**, not an implicit
zero and not an implicit pass. A new screen arriving with 40 literals is precisely
what this gate is for, and an unlisted-means-fine table would wave it through.

**T2 — silent-failure risk, and it is the reason for the whole task.** `lang` is
interpolated straight into `<html lang="…">`. A wrong value compiles, serves, and
renders; nothing logs. Once T2 lands, the type makes a *typo* impossible, but it
does not make a *wrong variant* impossible — `Locale::En` on a Japanese screen
still compiles. F5's right-hand column is the authority for all ten; take it from
there rather than re-deriving per file.

**T3 — the catalog has two completeness mechanisms and they do not check each
other.** `crates/core/src/i18n/tests/lookup_completeness.rs` pins every variant in
a `match` arm, and a **separate hand-written** `let all = […]` array is what the
completeness and dedup tests actually iterate. A key added to the pin but omitted
from the array compiles and passes both tests while being uncovered by the two
tests whose entire job is completeness. `ROADMAP.md` has the row; **for now, add
your two keys to both**, and state in the report that you did.

**T4 — do not repeat the mistake above.** A test that hardcodes `Ja` and `En` is
exactly the hand-written list that rots when §5.5 adds a locale. Drive it from an
exhaustive `match` (the compiler then fails on a new variant) or from an array the
test asserts agrees with such a `match`. Say which you chose.

**T5(b) — check before you cite.** Read `rfcs/done/034-*.md` and confirm for
yourself that it says nothing about locale before replacing the citation. The
whole point of this task is that nobody checked.

## 9. Assert machine-checkable things mechanically

```sh
# 1. No negotiation leaked into the shell (D1). Expect: no output.
grep -n "resolve_locale" crates/backend/src/routes/leptos_shell.rs

# 2. mounted_locale still has no caller (D2). Expect: exactly 1 line, the definition.
grep -rn "mounted_locale" --include="*.rs" crates/ | tee /dev/stderr | wc -l

# 3. No raw language-tag literals left at the shell boundary (T2).
#    Expect: no output.
grep -rn 'leptos_html_shell(' -A3 --include="*.rs" crates/backend/src/routes \
  | grep -E '"(ja|en)"'

# 4. The two live literals are gone (T3). Expect: no output.
grep -n 'セッション' crates/frontend/src/templates/security_center.rs
grep -n '保存確認'  crates/frontend/src/templates/totp.rs

# 5. RFC 034 is no longer cited for locale policy (T5b). Expect: no output.
grep -n "RFC 034" crates/frontend/src/components/shells/operator_shell.rs

# 6. Non-test code changed only where §6 says. Assert on git's hunk headers,
#    not on filenames -- grep -v tests.rs misses inline #[cfg(test)] modules.
git diff -U0 | grep '^@@'
```

**Figures in prose are measurements.** Every count in the report carries the
command that produced it. The ceiling table is a list claiming completeness; a
presence check cannot validate it, only the command can.

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

Expected: **host tests above 1,721 / 0 / 4 across 12 `test result:` lines** (T4
adds at least one, T3's keys add to the catalog tests — report the delta and
reconcile it against this baseline, which is the one the canonical csr-inclusive
command produces). `route-contracts-check.sh` exit 0 with **every figure in F7
unchanged** — this cut touches no route, so **a non-zero route-surface delta means
the cut grew and you should stop**. `drift-scan.sh` exit 0 including the new
section. `cargo check` warnings **8 frontend / 1 core, unchanged**.

**Sum the counts programmatically** — `awk`/`python` over the whole log, never by
hand-adding `test result:` lines, and doc-tests count.

**New gate → fires/does-not-fire pair, required.** Three pairs, not one:
1. **Over ceiling**: add one Japanese literal to a `pages/` file, capture red;
   remove, capture green.
2. **Over ceiling, English**: add one standalone English text child, capture red;
   remove, capture green. Clause (b) is the new half and must be shown to work.
3. **Under ceiling (D5)**: this is G2 — T3's own transition. Capture red with the
   literal removed and the ceiling still at 1, green after lowering it to 0.

**Evidence policy.** Every file under `evidence/` is redirected command output. A
hand-written summary line is not evidence and is rejected at review.

## 11. What must NOT be claimed

- **Do not claim any user-visible language changed, beyond the two strings in T3.**
  Nothing else does. The honest wording: *"no screen's rendered language and no
  `<html lang>` value changes in this cut; the two `templates/` literals are the
  only user-visible difference."*
- **Do not claim the gate forbids all hardcoded natural language.** It bounds the
  Japanese debt **exactly** and the English debt **partially** (F2). The honest
  wording names the uncovered class: English attribute values and English strings
  returned from helpers.
- **Do not claim `components/`'s register is fixed.** It is baselined. And do not
  claim its defects are user-visible: those files mount nowhere (F4).
- **Browser-side anything is `observed` or `unknown`, never `exercised`.** `trunk`
  cannot be installed on this machine and there is no Chrome connection. If you
  cannot render the Security Center and hear the `aria-label`, say so — T3 is
  verified by the string being gone and the key resolving, which is a build-time
  property, not a screen-reader one.
- RFC 000 §22 terms throughout: `exercised` / `observed` / `reviewed` / `unknown`.

## 12. Prohibited shortcuts

- No `#[allow(...)]`, `#[cfg(...)]` or feature gate to hide an error.
- No `continue-on-error: true`; no weakening a gate command until it passes.
- No merging the new section red "to be fixed next release."
- **No raising a ceiling.** Ever, in this cut. A ceiling that needs raising means
  a literal was added, which is the thing being forbidden.
- No `cargo fmt`. No route-string changes.
- No deleting a `lookup` call to make a count move.

## 13. Acceptance criteria

RFC 185 §5.2 in full, and the amended §5.1 (A5) — its typed half only. §5.4 in
full.

**Checked hardest, in order:** (1) the three fires/does-not-fire pairs in §10,
because a gate that cannot be shown to fail is not a gate, and clause (b) and D5
have never run; (2) G1's hit list against F1's eighteen rows, because an
exemption list built from a guess is the failure this gate exists to prevent;
(3) §9 assertion 3 — that no `"ja"`/`"en"` literal survives at the shell boundary.

**Expected unreachable, stated in advance:** the screen-reader behaviour T3 fixes
cannot be verified here (§11). Report it `reviewed`.

## 14. Known risks

- **D1 is a reversal of the accepted RFC, decided by the architect after the owner
  accepted it.** If the reasoning in D1 does not hold up when you read the ten call
  sites, that is a finding worth more than the task — report it. A non-reproduction
  of my claim that all ten `lang` literals are currently truthful is the single
  most valuable thing this cut could produce.
- **Matcher N was designed against a 71-line sample.** G1 exists because of that.
  Expect its class-name heuristic to need adjustment, and report the adjustment
  rather than folding it in silently.
- **The ceiling table is 18 hand-written numbers**, which is the same shape as the
  `lookup_completeness` array that rots (§8, T3). D5's staleness rule is what keeps
  it honest; if your implementation cannot make D5 fire (G2), stop and report —
  without it this gate is a comment.
- **T2 touches 12 files for a type change with no behaviour change**, which is the
  shape that invites an unrelated tidy-up. §7.
- **If the work turns out materially larger than scoped, stop and report.**
  Re-scoping is the architect's call, not the implementer's.

## 15. Review request

Write the package to `.git-exclude/review-request/`. It must include:

implementation summary · changed files · any deviation from §6 · every log from
§10 · the §9 assertion output · **all three** fires/does-not-fire pairs · G1's
full hit list with classifications · G2's result · gate results against F7 ·
what remains unverified (§11) · unresolved issues · requested review focus.

**Report the path only.** The architect reads it there.
