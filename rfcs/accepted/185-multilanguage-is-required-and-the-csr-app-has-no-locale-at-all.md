# RFC 185 — Multilanguage is required, and the CSR app has no locale input at all

**Status**: **Accepted** by the owner, 2026-11-11. **Amended 2026-11-11** while scoping the
dispatch — four measurements in this RFC were wrong and §5.1's proposal was partly unsafe.
Each amendment is marked inline where the wrong claim sits and listed in **§8**; the original
wording is kept, struck through or quoted, so the correction is visible rather than silent.
**Trigger**: the owner, 2026-11-11 — *"Multilanguage support is required. Excuse
me but I did not know of the 'Japanese-only written down as policy'."*

---

## 1. First, my own error in how I posed the question

I asked the owner to choose between adopting the catalog and *"Japanese-only
becomes written policy."* **That second option was never theirs to be offered**,
and I should have read the governing document before framing a choice around it.

ADR-013's `## v0.36.0 migration scope` → **Out of scope** list contains, as an
amendment dated 2026-09-09:

> ~~Admin console (operator-facing, English by design; i18n there is i18n-3
> territory if/when demand surfaces).~~ **Amended 2026-09-09.** The console is
> **Japanese**, and i18n there **remains i18n-3 territory**. … The owner ruled
> on the drift rather than against it — 29 files of deliberate JA is stronger
> evidence of intent than one line nobody applied, and **with no production
> deployment there is nothing to migrate either way**.

That is a **deferral with its trigger written into it** — "if/when demand
surfaces" — recorded in the *out of scope* list, decided because nothing was
deployed. It is not a decision that multilanguage is unwanted. **The owner has
now supplied the demand, which is the condition the ADR itself wrote.** Nothing
is being overridden.

## 2. How a deferral became a constitution

The deferral hardened by citation, across years of RFCs, into a rule stated as
settled law:

- `rfcs/done/072-html-lang-locale.md:75` — *"admin console は当面 JA-only"*,
  and `:88` calls it a **constitution** to be obeyed, deriving `:96` *"admin 系
  frame は常に `<html lang="ja">`"* — a permanent markup rule from a temporary
  scope exclusion.
- `077` embeds JA text directly in admin surfaces *because* of the policy;
  `078` calls it an *"i18n contract"* and treats English appearing in admin as a
  **violation**; `073`, `105`, `106`, `109`, `113` all cite it; `109` lists
  "ADR-013 (admin JA-only)" in its own Refs line.
- `crates/frontend/src/components/shells/operator_shell.rs:9` attributes it to
  **RFC 034** — which is `034-introspect-handler-wiring.md` and contains **no
  mention of locale, Japanese, or ADR-013**. Checked by grep over the file.
- And my own slice 2 handoff wrote it as a **"resolved decision — do not
  re-open."**

Nine documents, a code comment citing the wrong RFC, and a handoff of mine. Not
one of them is where the rule was decided, because it never was decided — it was
deferred, and "if/when demand surfaces" stopped being quoted somewhere around
RFC 072.

## 3. What is actually built, measured

| scope | files | files with JA literals | JA literals | `lookup()` calls |
|---|---|---|---|---|
| `frontend/src/pages/` — **the live CSR screens** | 18 | **5** | **177** | **0** |
| `frontend/src/components/` — RFC 180's import | 31 | 0 | **0** | 54 |
| `frontend/src/admin/` — server templates | 12 | 0 | **0** | 18 |
| `frontend/src/templates/` | 13 | **2** | **2** | 63 |

**Amended 2026-11-11 (A1) — the figures above are the corrected ones.** The first version of
this table said `pages/` **175**, `components/` **0 files / 0 literals**, `admin/` **0 / 0**,
and `templates/` **1 file / 4 literals**. It counted quoted Japanese without excluding test
code, which both overstates and understates: recounted per file, skipping everything from a
`#[cfg(test)]` line onward, skipping `tests/` paths, and skipping comment lines —

```sh
for f in $(find crates/frontend/src/<scope> -name '*.rs' | sort); do
  n=$(awk '/^#\[cfg\(test\)\]/{exit} {print}' "$f" \
        | grep -vP '^\s*//' \
        | grep -oP '"[^"]*[\x{3040}-\x{30ff}\x{4e00}-\x{9fff}][^"]*"' | wc -l)
  [ "$n" -gt 0 ] && printf '%s %s\n' "$f" "$n"
done
```

— `pages/` is **177** across 5 files: `operator/clients.rs` **52**,
`operator/audit_chain.rs` **41**, `operator/console.rs` **33**, `operator/tenancy.rs` **27**,
`operator/audit.rs` **24**. `components/` is **0**, and its four Japanese strings are
`auth_shell.rs`'s own `footer_strings` **test assertions** — the first table read test fixtures
as production literals, in both directions. `admin/` is **0** non-test (its 9 are
`admin/audit.rs` assertions). `templates/` is **2** in **two** files, not 4 in one:
`security_center.rs:307` and `totp.rs:191`. **Non-test total: 179.** Test code holds **31**
legitimately-Japanese strings — which is itself a §5.2 requirement: a gate that does not exempt
test paths fires on every catalog assertion the project has.

**Amended 2026-11-11 (A7) — the sentence below is false, and the error is in the measurement's
own design: §3 counted *Japanese* literals, so it could not see hardcoded **English** ones.**
Re-measured with a matcher that catches both — kana/CJK anywhere in a literal, **plus** any
standalone `view!` text child containing two consecutive ASCII letters, excluding
all-lowercase-hyphenated words (CSS class names) and test paths:

| scope | files hit | natural-language literals | of which CJK | of which English |
|---|---|---|---|---|
| `frontend/src/pages/` | **11** of 18 | **198** | 177 | **21** |
| `frontend/src/components/` | **5** of 31 | **12** | 0 | **12** |
| `frontend/src/admin/` | 0 | **0** | 0 | 0 |
| `frontend/src/templates/` | 2 | **2** | 2 | 0 |
| `frontend/src/tenancy_console/`, `tenant_admin/` | 0 | **0** | 0 | 0 |
| **total** | | **212** | 179 | 33 |

So `pages/` is **11** files, not 5, and `components/` — the scope this RFC held up as the one
doing it right — carries **12** hardcoded English strings beside its 54 catalog calls.
Three of them matter beyond the count:

- `components/shells/operator_shell.rs:108` — `"Safety"`, **one English word in the sidebar**,
  sitting between ten `lookup(…, LOCALE)` siblings in the shell whose own module doc declares
  the console Japanese-only. RFC 180 imported it and review accepted it.
- `components/shells/tenant_admin_shell.rs:126-130` — the auditor banner is **mixed-language by
  construction**: `<span>"Read-only"</span>` then `{lookup(MessageKey::AuditorRoleReadOnly,
  locale)}` then `" Only the Audit section is accessible."`, concatenated inside one
  `role="status"`. On a `ja` request that renders English, then Japanese, then English.
- `components/domain/role_impact.rs` composes a sentence from fragments — `"Grant "` `{role}`
  `" to "` `{subject}` `" for "` `{scope}` `"."`. **That shape cannot be localised at all**:
  Japanese word order puts the verb last, so there is no assignment of translations to those
  four fragments that produces correct Japanese. It needs one key with placeholders, which is
  a different change from a `lookup` substitution.

**But none of the twelve renders today.** `grep -rn "<ConfirmDialog\|<DensityToggle\|
<RoleImpact\|<OperatorShell\|<TenantAdminShell"` finds **zero mount sites outside
`components/` itself** — all five files are dormant, which extends RFC 179's finding (*"all 17
imported primitives have zero call sites"*) to **the two shells as well**. So these are latent,
not live: the register defect is real and the reader is nobody, yet. The two `templates/`
literals (A4) are the opposite — they render on every request.

~~**The catalog is used everywhere except the screens the project is actively
migrating to.**~~ `ADR-013`'s machinery is all present and exercised — closed
`Locale { Ja, En }`, `lookup(MessageKey, Locale)`, `parse_accept_language`,
`resolve_locale(&Request)` at ~~**18**~~ **8** server-side call sites, and a test that
every key resolves in every locale.

**Amended 2026-11-11 (A2).** The 18 was wrong by conflation: **18 is `frontend/src/admin`'s
`lookup(` count from the table above**, which I carried into the sentence about
`resolve_locale`. `grep -rn 'resolve_locale(' --include="*.rs" crates/ | grep -v 'pub fn '`
gives **8** call sites in **4** files — `magic_link/request.rs` ×2, `magic_link/verify.rs` ×2,
`me/totp/enroll.rs` ×2, `me/totp/verify.rs` ×2. §4's "18 other paths" is the same error.
A ninth site, `api_v1/anonymous.rs:288`, calls `resolve_locale_str("ja")` — **a function whose
name promises resolution and whose entire body returns its own argument**, which is honest only
because its doc comment says so. Not counted among the 8.

**But the CSR app has no locale input whatsoever:**

**Amended 2026-11-11 (A3) — this RFC's own title is wrong, and so is the sentence above.**
`crates/frontend/src/app.rs:64` already holds `mounted_locale()`, which reads
`document.documentElement.lang` and maps it through `Locale::from_primary_subtag`
(region/script subtags stripped, case-insensitive, `unwrap_or_default()` on anything
unrecognised). **The reader exists and is correct. It has no caller** — its own doc comment
says *"Not yet called anywhere"*, and `grep -rn "mounted_locale" --include="*.rs" crates/`
returns the definition and nothing else. So the input is not missing; **it is built, tested in
`core` (`from_primary_subtag_*`, three tests), and unwired** — which is the third time in three
releases: `read_status` was a finished reader with no caller since `580eeba` (0.97.0), the
export-truncation header is a signal with no reader (0.98.0 backlog), and this is a locale
reader with no caller. **It is invisible to the compiler because it is `pub`** — `cargo check
-p cesauth-frontend --features csr` reports 8 warnings and this is not one of them. That is a
second argument for §5.2: a gate, not a warning.


- `routes/leptos_shell.rs:92` — `leptos_html_shell(_req, _env, title, lang)`.
  **`_req` is unused**, and `lang` is a hardcoded literal at every call site:
  `"en"` at 7 (sign-in, sessions, security, TOTP enroll/disable, invitations) and
  `"ja"` at 3 (the two audit console routes and one title-parameterised site).
  `resolve_locale` is **never called** from this file.
- `components/` accept `#[prop(default = Locale::default())] locale: Locale`, and
  `operator_shell.rs:49` pins `const LOCALE: Locale = Locale::Ja`. The catalog
  calls are real; the locale reaching them is a constant.

So every RFC 131 slice converts a template that *does* consult the catalog into
a page that *cannot*. Slice 1 turned 18 `lookup` calls into 26 hardcoded
literals; slice 2 shipped 44 English strings, and fixing that produced 47
hardcoded Japanese ones. **Four slices remain**, and each one adds to the 175.

## 4. A defect that does not depend on the policy at all

`<html lang>` is served as a literal unrelated to the requesting user, on
surfaces where ADR-013 **requires** negotiation and where the server already
performs it on ~~18~~ **8** other paths (A2). `lang` drives screen-reader pronunciation, so a
wrong value is an accessibility defect, not a cosmetic one — and it bears
directly on the owner's stated concern about users who have changed their
browser defaults.

**Amended 2026-11-11 (A4) — there is now one named instance, and it is not on a CSR surface.**
`crates/frontend/src/templates/security_center.rs:307` emits
`aria-label="セッション {sid}"` **hardcoded**, inside a function where `locale` is already a
parameter and where every other string on the same screen goes through `lookup(…, locale)` —
63 of them in that directory. The Security Center is a **server-rendered** surface, so it
*does* negotiate: an `Accept-Language: en` user is served the whole screen in English and one
`aria-label` in Japanese, which is exactly the accessibility defect this section describes,
announced by the screen reader and invisible on screen. `templates/totp.rs:191` is the same
shape (`gate_legend = "保存確認"`), and carries a comment excusing itself:
*"admin-side is JA; end-user route is also fine with short literal"*. Both are in the 0.99.0
cut. **The CSR half of this section stands as written below**: no CSR surface has a mismatch
today, because each one is monolingual *and* its `lang` literal names that language — which is
the finding that reshapes §5.1 (A5).

**I have not driven this to a user-visible mismatch.** Which surfaces currently
disagree with their own content needs measuring per surface, and the implementing
cycle should do that rather than take my inference. **Evidence term:
`reviewed`.**

## 5. Proposed shape

**The ordering is the whole proposal**: plumbing and a gate *before* RFC 131
slice 3, then the 175-literal backlog. Doing it the other way round means four
more slices of debt and four more re-litigations of the same question.

**§5.1 — Plumbing (before slice 3).** ~~`leptos_html_shell` resolves the locale
from the request it already receives and ignores, emits it as `<html lang>`, and
exposes it to the CSR app in one place the app can read at mount. `pages/` and
`components/` take it from there instead of `Locale::default()`.~~

**Amended 2026-11-11 (A5) — the struck half of this is a regression, and I proposed it.**
`<html lang>` is a claim about **what language the content is in**. Today every one of the ten
shell surfaces is monolingual and its hardcoded literal names that language correctly: the
three `"ja"` sites serve the operator screens, whose `pages/` bodies hold 177 Japanese
literals and zero catalog calls; the seven `"en"` sites serve `pages/login.rs`,
`pages/sessions.rs`, `pages/security_center.rs`, `pages/totp.rs` and `pages/tenant_admin/*`,
all of which hold **0** Japanese literals and zero catalog calls, i.e. hardcoded English.
**So `lang` is currently truthful on all ten**, and resolving it from `Accept-Language` would
make it false for exactly the users who stated a preference — a `ja` reader sent to an English
screen labelled `lang="ja"`, and the reverse. Negotiating a value the content cannot honour is
worse than a literal that tells the truth, and it is the §4 defect this RFC opened with,
inflicted deliberately.

**The flip belongs to §5.3, per screen, in the same commit that converts that screen** — at
which point the surface can honour any locale and `lang` becomes negotiable without lying.
There is no ordering in which the flip can come first: by construction, no CSR surface can
honestly negotiate before its literals are in the catalog.

**What is true today and ships in the first cut instead** — the part of this section that was
right, narrowed to what can be done without lying:

- `leptos_html_shell`'s `lang: &str` becomes `lang: Locale`. A call site then cannot emit a
  tag no catalog locale corresponds to, and the shell's emission and `mounted_locale`'s parse
  (A3) share one vocabulary **by construction** rather than by both happening to spell `"ja"`
  the same way. Today a typo in that literal would reach `from_primary_subtag`, return `None`,
  and silently default to `Ja` with no error anywhere. A round-trip test pins it.
- Each call site passes the locale **its content is actually written in** — unchanged values,
  now type-checked. **No rendered language changes in that cut**, and the report must say so
  in those words rather than implying progress the user could see.
- `mounted_locale` stays uncalled until a screen can use it, and the §5.2 gate's
  per-file ceiling is what keeps `pages/` from growing in the meantime.

**§5.2 — A gate, in the same cycle.** A natural-language literal in `pages/` or
`components/` fails the build, with an explicit exemption list for data and API
identifiers (`chain_hash`, `seq`, `Export CSV`) in the shape
`E6_BEARER_LEGACY_EXEMPT` already uses.

**Amended 2026-11-11 (A6) — three requirements the first version did not state, each from a
measurement above.** (i) **Test paths are exempt by construction**, not by list: 31 of the 210
Japanese strings in `crates/frontend` are catalog assertions (A1), and a gate that fires on
them is a gate that gets deleted. (ii) **The baseline is a per-file descending ceiling, not an
exemption list.** A 177-entry literal list churns on every conversion and would be edited in
the same commits it is meant to police; five per-file numbers that may only go **down** forbid
new debt, need no edit when a literal is removed, and fail loudly when one is added.
(iii) **The ceiling needs E6's stale-entry rule, inverted**: a file whose real count has
dropped *below* its ceiling must fail until the ceiling is lowered. Without that the ceiling
rots upward-slack and stops being a gate — which is the exact failure mode
`E6_BEARER_LEGACY_EXEMPT`'s own staleness check exists to prevent, and which
`scripts/route-contracts-check.sh:1961-1979` already implements to copy from.
(iv) **The matcher must catch English, not only Japanese** — A7 is the reason, and without it
the gate would have reported `components/` clean while 12 English strings sat in it. (v) Only
the **two `templates/` literals are fixed** in the first cut, because those render on every
request; `components/`'s 12 are dormant (A7) and are **baselined by ceiling, not localised**,
since converting code that mounts nowhere is RFC 131 R3's work and would be done blind. **This is the part that makes it stick**
— the project's own dominant failure mode is a documented rule with no gate, and
this rule has had nine documents and no gate for years.

**§5.3 — The 175, converted.** Per screen, with `MessageKey`s added in both
locales, which `every_message_key_resolves_in_every_locale_to_nonempty` already
enforces. Sizeable but mechanical, and it can run per-slice once §5.2 forbids
new instances.

**§5.4 — Correct the record, which is cheap and prevents the next recurrence.**
Amend ADR-013 to state the owner's 2026-11-11 decision and that the i18n-3
deferral is now closed; fix `operator_shell.rs:9`'s citation of RFC 034; and
note in RFC 072's lineage that its "constitution" was a scope exclusion.

**§5.5 — Still open, and the owner's**: whether `En` is the second locale or
whether more are wanted. ADR-013's `Locale` is a **closed enum requiring a
recompile per locale**, which it argues for deliberately (compiler-enforced
completeness) and which is a real constraint if the answer is "several". And
ADR-013's own Q1 — a `/me/preferences` locale override outranking
`Accept-Language` — becomes live the moment users have more than one choice.

## 6. What I am not proposing

- **No `LocaleToggle`.** RFC 180 barred importing the mockup's live switcher and
  that still holds; negotiation is not a switcher.
- **No change to the server-rendered paths**, which already negotiate.
- **No change to `Locale`'s closed-enum design** unless §5.5 says more than two.
- **No bundling with RFC 131's remaining slices.** This is the precondition for
  them, not a part of them.

---

## 8. Amendments, 2026-11-11 (architect, while scoping the dispatch)

The owner accepted this RFC on the strength of §1–§4. Scoping the handoff meant
re-deriving every figure in it against the tree, and **four of them were wrong
and one proposal was unsafe**. All five are corrected inline above, at the point
where the wrong claim sits, with the original kept visible.

| # | Was | Is | Why it was wrong |
|---|---|---|---|
| **A1** | `pages/` **175** literals; `components/` 0 files; `templates/` 1 file / 4 | `pages/` **177**; `components/` **0** non-test; `admin/` **0** non-test; `templates/` **2** in **2** files; non-test total **179** | Counted quoted Japanese without excluding `#[cfg(test)]` bodies and `tests/` paths, so **test fixtures were read as production literals** — in both directions |
| **A2** | `resolve_locale` at **18** server-side call sites | **8**, in 4 files | **18 is `frontend/src/admin`'s `lookup(` count** from the table two paragraphs above; I carried it into the next sentence |
| **A3** | *"the CSR app has no locale input whatsoever"* — this RFC's **title** | `app.rs:64`'s `mounted_locale()` reads `document.documentElement.lang` correctly and **has no caller** | Did not grep the CSR crate for an existing reader before asserting none existed. The reader's own doc comment says it is uncalled |
| **A4** | §4: *"I have not driven this to a user-visible mismatch"*, evidence `reviewed` | One named instance: `templates/security_center.rs:307`'s Japanese `aria-label` on a **negotiating** surface; plus `totp.rs:191` | Looked for the mismatch on the CSR surfaces, where it does not exist, and not on the server-rendered ones, where it does |
| **A5** | §5.1: the shell **negotiates** `<html lang>` from the request, first, before slice 3 | The flip moves into §5.3 per screen; the first cut ships `lang: Locale` typing with **unchanged values** | Every CSR surface is monolingual **and** its `lang` literal is truthful today. Negotiating it first replaces a true claim with a false one for precisely the users who expressed a preference — the §4 defect, inflicted on purpose |
| **A6** | §5.2: an exemption list in the `E6_BEARER_LEGACY_EXEMPT` shape | Test paths exempt by construction; **per-file descending ceiling**; ceiling staleness is a hard failure; the matcher must catch **English too**; only `templates/`'s 2 are fixed in cut 1 | A 198-entry literal list would be edited by the same commits it polices, and slack above the real count rots silently |
| **A7** | §3: *"the catalog is used everywhere except the screens the project is actively migrating to"*; `pages/` 5 files | **False.** `components/` holds **12** hardcoded **English** strings; `pages/` is **11** files, 198 literals (177 CJK + **21 English**); frontend total **212**. All 12 are in files with **zero mount sites** — both shells included | §3 counted *Japanese* literals, so by construction it could not see English ones. The scope the RFC praised was never measured for the defect it was praised for |

**What survives unchanged, and is the whole value of the RFC**: §1 (the question
I posed to the owner contained an option that was never theirs), §2 (nine
documents state as settled law a deferral whose own trigger —
*"if/when demand surfaces"* — the owner has now pulled), §5.2's existence (the
dominant failure mode here is a documented rule with no gate, and this rule has
had nine documents and no gate for years), §5.3, §5.4, §5.5 and §6.

**§5.5 remains open and the owner's**: whether `En` is the second locale or more
are wanted. It does not block the first cut — `lang: Locale`, the gate and the
record corrections are all locale-count-agnostic — but it does shape §5.3, since
`Locale` is a closed enum requiring a recompile per locale and every `MessageKey`
must be written in every variant.
