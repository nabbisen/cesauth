# RFC 180 — R2b is forty-seven keys, not a catalog merge, and it stopped being blocked on 2026-09-24

**Status.** **Accepted 2026-11-07** — the owner's reply was *"RFC 179 and 180
are accepted."* **Not yet dispatched**, and deliberately: it is a **minor**, and
letting its code reach `main` before RFC 179's patch is cut would force that cut
to the higher level. Its handoff goes out the day `0.92.7` is tagged. Proposed
2026-11-07 by the architect. This is the scoping
proposal RFC 131's R2b correction says is owed. **It replaces a question the
owner was told he had to answer with a recommendation he only has to accept** —
measuring R2b's actual surface found it is five times smaller than RFC 131
describes, and that the mechanism question it was waiting on was answered **six
weeks ago**, on 2026-09-24.
**Tier.** **P3.** Nothing is broken by R2b staying unbuilt; ten mockup files sit
outside the tree and two primitives are excluded from an otherwise-complete
import. This is a blocked-programme cleanup, not a defect.
**Size.** **Small.** 47 keys to triage, 4 of which are a server-rendered
footer, and one mechanism to **delete rather than import**.
**Touches.** `crates/core/src/i18n/` (additive variants + `ja`/`en` rows),
`crates/frontend/src/components/` (10 new files), `crates/frontend/src/app.rs`
(read `lang` once at mount).
**Depends on.** Nothing. **Explicitly not RFC 132 §13 q1**, which is answered —
§2.
**Target release.** **Minor** — it adds module surface, the same reason R2a was
a minor (0.82.0). Not bundled with RFC 179, which is a patch.

---

## 1. Summary

RFC 131 R2b has read as *"deferred with q1"* since 2026-09-09. Three
measurements change what it is:

1. **It is not blocked.** RFC 132 §13 q1 reads **ANSWERED 2026-09-24**, and
   that RFC states *"R3 is no longer blocked."* RFC 131 was never updated.
2. **Its scope is 47 keys, not 263.** The ten files R2b imports reference 47
   distinct catalog keys. The mockup's 263-variant enum was never the unit.
3. **The mechanism should be deleted, not merged.** The locale is **already in
   the DOM** — `leptos_html_shell` emits `<html lang="…">` — and
   `cesauth_core::i18n` already resolves it server-side. Neither the mockup's
   second `Locale`, nor its `Msg` enum, nor its reactive `LocaleContext` needs
   to come across at all.

So R2b's "design decision, not clerical" framing was right about the *shape*
and wrong about the *size*. There is a decision, and it is one page of triage.

## 2. The blocker, and why it stayed closed-but-recorded-open for six weeks

RFC 131 §5 said:

> So R2b cannot be settled without RFC 132 §13 q1, which the owner deferred on
> 2026-09-09.

Written 2026-09-09. The owner answered q1 on **2026-09-24**, taking the
architect's full recommendation, and RFC 132 §13 records it with *"**R3 is no
longer blocked.**"* Nobody propagated that back to RFC 131, and on 2026-11-07
the architect cited the stale line **to the owner, in conversation**, as live
evidence that R3 had an unanswered two-month-old dependency. Corrected in
RFC 131 the same day.

**q1's answer is also exactly the input R2b needed.** R2b's stated conflict was
that `components/shells/auth_shell.rs` is a **pre-authentication** shell calling
`t`, while RFC 132 classifies pre-auth `server`, where no Leptos reactive
context exists. q1's answer settles that directly: pre-auth is
**server-rendered**, email-first. So a reactive locale hook was never a
candidate for that file, and the conflict dissolves rather than needing a ruling.

## 3. The measured scope

Ten files use i18n, matching RFC 131's own coupling-map count
(`grep -rlE 'crate::i18n|use_locale|LocaleContext|Msg::' crates/ui/src/components/`
at `df3d9d0`):

| area | files |
|---|---|
| `shells` | `auth_shell`, `operator_shell`, `personal_shell`, `tenant_admin_shell` |
| `domain` | `role_impact`, `secret_reveal`, `sparkline` |
| `nav` | `topbar` |
| `primitives` | `permission_denied`, `suspended_notice` — the two R2a excluded |

**They reference 47 distinct keys, not 263.** And the catalogs are disjoint:

| | measured | command |
|---|---|---|
| core `MessageKey` variants | **171** | census over `i18n/mod.rs:162-410`; reconciles `171 + 36 doc + 19 blank + 21 section = 247` raw, **0 unaccounted** |
| mockup `Msg` variants | **263** | same shape; `263 + 49 + 51 = 363` raw, **0 unaccounted** |
| exact-name overlap, full sets | **4** | `TotpDisableSubmit`, `TotpEnrollTitle`, `TotpVerifyCodeLabel`, `TotpVerifyTitle` |
| exact-name overlap, **the 47** | **0** | `comm -12` |

**RFC 131's "175" is stale; it is 171 today.** Stated with its command above
because the previous figure was carried in prose and nothing recomputed it.

### 3.1 Where the 47 actually land

Core's catalog is rich exactly where the mockup's shells are not, and empty
exactly where they are:

| stem | core keys | the 47 need |
|---|---|---|
| `Sessions*` | **19** | 1 (`SessionsTitle`) |
| `Security*` | **28** | 1 (`SecurityCentreTitle`) |
| `Audit*` | **19** | 2 |
| `Config`, `Tokens`, `Operations`, `Scope*`, `Status*`, `Terms`, `Privacy`, `PoweredBy`, `Suspended*`, `PermissionDenied*`, `Sidebar*`, `TenantAdmin*`, `Environment*` | **0** | the rest |

So the triage is: **a handful of page-title keys resolve to core's existing
ones** (the mockup's `SessionsTitle` is core's `SessionsPageTitle`, its
`SecurityCentreTitle` is core's `SecurityTitle`, its `AuditTitle` is core's
`AuditViewerPageTitle`), and **the remainder is additive vocabulary core
genuinely lacks** — operator-console chrome, shell navigation, scope and
environment labels. That is a review over 47 rows, not a merge of two
catalogs.

### 3.2 `auth_shell.rs` — the file the whole deferral rested on — needs four strings

`PoweredBy`, `Privacy`, `Status`, `Terms`. Footer chrome. On a surface q1
settled as server-rendered, which is the path `cesauth_core::i18n::lookup`
already serves per request. **Four additive variants and three `ja`/`en` rows
close the only architectural objection R2b recorded.**

## 4. Direction — delete the mechanism, extend the one catalog

**1. Do not import the mockup's i18n.** Not its `Locale`, not `Msg`, not
`LocaleContext`/`use_locale()`. Importing it creates the second catalog
**ADR-013 declined** when it rejected a separate `cesauth-i18n` crate, and the
two-libraries drift RFC 131 §3 condemns. Rewrite the ten files' `t(Msg::X)`
call sites against `cesauth_core::i18n`.

**2. The locale is already in the DOM; read it, do not invent it.**
`leptos_html_shell(_req, _env, title, lang)` emits `<html lang="{lang}">` and
callers pass `"ja"` (operator) or `"en"` (tenant-admin, invitations) today. The
CSR app reads `document.documentElement.lang` **once at mount**, maps it with
`parse_accept_language`'s existing semantics, and holds it as plain state. No
reactive context, because nothing in these ten files changes locale after mount
— and `LocaleSwitchLabel` is a *label*, not a switch; if a live switcher is
ever wanted, that is its own RFC with its own reason.

**3. Extend `MessageKey` additively.** Zero name collisions among the 47, so no
renames and no breaking change to the 171. Resolve the handful of semantic
duplicates **to core's existing key**, and record each decision in the cycle's
report — those are the only judgement calls in the whole slice.

**4. Then R2b is done**, `permission_denied.rs` and `suspended_notice.rs` stop
being excluded, and RFC 131's R2 is complete for the first time since 0.82.0.

## 5. What this does not touch

- **No CSS.** The stylesheet half of R2a is **RFC 179**, a patch, independent of
  this.
- **No screen wiring.** That is R3.
- **No live locale switching**, no `Accept-Language` change, no new route, no
  wire-format, schema, cookie or permission change.
- **No ADR-013 amendment.** This RFC follows it rather than revisiting it.

## 6. The thing worth noticing while we are here

The CSR app has **no locale handling at all** today — `grep -rn "locale"` over
`crates/frontend/src/pages/` and `components/` returns nothing, and only the
server-rendered `templates/` call `lookup`. So the CSR pages hardcode their
strings, **in both languages at once**: `pages/operator/clients.rs:350` renders
`"操作"` while `pages/sessions.rs:96` renders `"Actions"`, in one tree, with no
mechanism choosing either. Doing R2b correctly gives those pages the first
locale path they have ever had. **Not in this slice's scope** — the existing
pages are R3's — but it is the reason this slice is worth more than finishing
an import.

## 7. Acceptance criteria

1. Ten files present under `crates/frontend/src/components/`, compiling under
   the `csr` feature, referencing **`cesauth_core::i18n` only** — a
   `grep -rn 'Msg::\|use_locale\|LocaleContext' crates/` returns **0**.
2. Every one of the 47 keys is **either** mapped to an existing `MessageKey`
   **or** added as a new variant with `ja` and `en` rows. The cycle's report
   carries the 47-row table and its arithmetic: `47 = mapped + added + 0
   unresolved`.
3. `permission_denied.rs` and `suspended_notice.rs` are no longer excluded, and
   RFC 131's R2a exclusion note is updated to say so.
4. `auth_shell.rs`'s four keys resolve through the **server-rendered** path, and
   a test asserts the rendered footer strings in both locales — not just that
   the variants exist. (Asserting the enum is not asserting the caller.)
5. Host tests rise by the new cases and the count is stated with its command.
   `route-contracts-check.sh`, `drift-scan.sh`, `migration_chain`, `mdbook`
   unchanged. Bundle delta recorded with sha256 **and the gzip level**.
6. **RFC 131 §5 R2b is marked complete**, and its coupling map's figures are
   re-derived rather than carried.

## 8. Baselines, each with its command

| | value | command |
|---|---|---|
| core `MessageKey` variants | **171** | census over `crates/core/src/i18n/mod.rs`, reconciled to 247 raw lines |
| mockup `Msg` variants | **263** | same, over `crates/ui/src/i18n/keys.rs` at `df3d9d0`, reconciled to 363 |
| i18n-using mockup component files | **10** | `grep -rlE 'crate::i18n\|use_locale\|LocaleContext\|Msg::' crates/ui/src/components/` |
| distinct keys those ten use | **47** | `grep -rhoE 'Msg::[A-Z][A-Za-z0-9_]*'` over those files, `sort -u` |
| `auth_shell.rs` keys | **4** | same, that file alone |
| exact-name overlap, the 47 vs 171 | **0** | `comm -12` |
| shell `lang` values emitted | `ja` ×1, `en` ×2 | `grep -rn 'leptos_html_shell(' crates/backend/src/` |
| CSR locale handling today | **none** | `grep -rn "locale" crates/frontend/src/pages crates/frontend/src/components` |
