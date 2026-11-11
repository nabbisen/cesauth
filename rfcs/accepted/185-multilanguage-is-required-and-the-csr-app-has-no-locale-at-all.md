# RFC 185 — Multilanguage is required, and the CSR app has no locale input at all

**Status**: Proposed, 2026-11-11. Needs the owner's authorization.
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
| `frontend/src/pages/` — **the live CSR screens** | 18 | **5** | **175** | **0** |
| `frontend/src/components/` — RFC 180's import | 31 | 0 | 0 | 54 |
| `frontend/src/admin/` — server templates | 12 | 0 | 0 | 18 |
| `frontend/src/templates/` | 13 | 1 | 4 | 63 |

**The catalog is used everywhere except the screens the project is actively
migrating to.** `ADR-013`'s machinery is all present and exercised — closed
`Locale { Ja, En }`, `lookup(MessageKey, Locale)`, `parse_accept_language`,
`resolve_locale(&Request)` at **18** server-side call sites, and a test that
every key resolves in every locale.

**But the CSR app has no locale input whatsoever:**

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
performs it on 18 other paths. `lang` drives screen-reader pronunciation, so a
wrong value is an accessibility defect, not a cosmetic one — and it bears
directly on the owner's stated concern about users who have changed their
browser defaults.

**I have not driven this to a user-visible mismatch.** Which surfaces currently
disagree with their own content needs measuring per surface, and the implementing
cycle should do that rather than take my inference. **Evidence term:
`reviewed`.**

## 5. Proposed shape

**The ordering is the whole proposal**: plumbing and a gate *before* RFC 131
slice 3, then the 175-literal backlog. Doing it the other way round means four
more slices of debt and four more re-litigations of the same question.

**§5.1 — Plumbing (before slice 3).** `leptos_html_shell` resolves the locale
from the request it already receives and ignores, emits it as `<html lang>`, and
exposes it to the CSR app in one place the app can read at mount. `pages/` and
`components/` take it from there instead of `Locale::default()`.

**§5.2 — A gate, in the same cycle.** A natural-language literal in `pages/` or
`components/` fails the build, with an explicit exemption list for data and API
identifiers (`chain_hash`, `seq`, `Export CSV`) in the shape
`E6_BEARER_LEGACY_EXEMPT` already uses. **This is the part that makes it stick**
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
