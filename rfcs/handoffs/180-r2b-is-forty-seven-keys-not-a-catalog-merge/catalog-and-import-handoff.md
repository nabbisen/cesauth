# RFC 180 — finish R2b: ten files, forty-seven keys, and one mechanism to delete

**Governing RFC.** [`rfcs/accepted/180-r2b-is-forty-seven-keys-not-a-catalog-merge.md`](../../accepted/180-r2b-is-forty-seven-keys-not-a-catalog-merge.md)

**Builds on.** `main` at `5b049b9` — tag **`0.92.7`**. Nothing reverted.

**Target release.** **Minor** — which is now simply the **default** under
**RFC 181** (2026-11-07) and needs no argument. It was originally dispatched as
a minor citing R2a's 0.82.0 precedent; that precedent was challenged in RFC 168
§6.1 and **is no longer load-bearing** — the level is correct either way, so do
not relitigate it. **Held until `0.92.7` was tagged** so RFC 179's patch could cut
at its own level; that tag now exists, so this is live.

**Tier.** **P3.** Nothing is broken by R2b staying unbuilt. This is a
blocked-programme cleanup — a programme that was recorded blocked for six weeks
against a question answered on 2026-09-24.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-07.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. The job

Bring ten mockup component files into `crates/frontend/src/components/`, and
**delete their i18n mechanism instead of importing it.** Rewrite their
`t(Msg::X)` call sites against `cesauth_core::i18n`, extending core's catalog
where it genuinely lacks a string.

**The triage is the work.** Forty-seven keys, each needing one decision: does
core already say this, or must core learn to? That is judgement over forty-seven
rows, not a mechanical merge.

## 2. The ten files

From the mockup repository at pin **`df3d9d0`**
(`/home/nabbisen/Desktop/cesauth/cesauth-mockup-git`), under
`crates/ui/src/components/`:

| area | files |
|---|---|
| `shells` | `auth_shell.rs`, `operator_shell.rs`, `personal_shell.rs`, `tenant_admin_shell.rs` |
| `domain` | `role_impact.rs`, `secret_reveal.rs`, `sparkline.rs` |
| `nav` | `topbar.rs` |
| `primitives` | `permission_denied.rs`, `suspended_notice.rs` — **the two R2a excluded** |

`grep -rlE 'crate::i18n|use_locale|LocaleContext|Msg::' crates/ui/src/components/`
returns exactly these ten, matching RFC 131's own coupling map.

## 3. The mechanism — delete, do not import

**Do not bring across** the mockup's `Locale`, its `Msg` enum, or its
`LocaleContext`/`use_locale()` hook. A second catalog is what **ADR-013
declined** when it rejected a separate `cesauth-i18n` crate, and the
two-libraries drift RFC 131 §3 condemns.

**The locale is already in the DOM. Read it; do not invent it.**
`leptos_html_shell(_req, _env, title, lang)` emits `<html lang="{lang}">` and
callers pass `"ja"` (operator) or `"en"` (tenant-admin, invitations) **today**.
So:

- read `document.documentElement.lang` **once at mount** in `app.rs`;
- map it with the semantics `parse_accept_language` already uses;
- hold it as plain state. **No reactive context** — nothing in these ten files
  changes locale after mount.

`LocaleSwitchLabel` is a **label**, not a switch. If a live switcher is ever
wanted it gets its own RFC with its own reason. **Do not build one here**, and
do not build a reactive context "so a switcher is possible later."

## 4. The forty-seven keys

```
ActionBack ActionCopied ActionCopy ActionSignOut AuditorRoleReadOnly AuditTitle
ConfigTitle DeletionRequestsTitle EnvironmentLocal EnvironmentProduction
EnvironmentStaging InvestigateTitle LocaleSwitchLabel OidcClientsTitle
OneTimeRevealNotice OperationsTitle OperatorDashboardTitle PermissionDeniedBody
PermissionDeniedTitle PoweredBy Privacy RoleAssignAuditNotice
RoleAssignPreviewAllowed RoleAssignPreviewNotAllowed RolesCatalogTitle
ScopeSystem ScopeTenant SecurityCentreTitle SessionsTitle SidebarGroupAccess
SidebarGroupApplications SidebarGroupMembers SidebarGroupSettings
SignInVolumeLast24h Status StatusSuspended SuspendedTenantBody
SuspendedTenantTitle TenantAdminGroups TenantAdminInvitations
TenantAdminOrganizations TenantAdminSubscription TenantAdminOverview
TenantAdminUsers TenantAuditTitle Terms TokensTitle
```

Derive this list yourself and reconcile against **47**.

**Exact-name overlap with core's 171 `MessageKey` variants is 0**, so nothing
collides and no rename is needed. Every decision is additive-or-map.

### 4.1 Compare strings, not names. I tried names and it produced noise.

I ran a name-word-overlap heuristic over all 47 to pre-fill this table. **It is
not a usable criterion and you should not repeat it** — it scored
`ConfigTitle ~ SecurityTitle` and `TenantAdminGroups ~ AdminScopeTenant` as
matches, on the shared tokens "Title" and "Tenant". Semantic equivalence is a
judgement over the **rendered strings**.

The strings live in: mockup `crates/ui/src/i18n/{en,ja}.rs` (flat
`Key => "string",` arms) and core `crates/core/src/i18n/mod.rs` (a
`Key => match locale { Ja => …, En => … }` block from ~line 500).

### 4.2 Six worked rows, including one trap

| mockup key | mockup en / ja | core candidate | core en / ja | verdict |
|---|---|---|---|---|
| `SessionsTitle` | "Active sessions" / "アクティブなセッション" | `SessionsPageTitle` | **identical in both locales** | **map.** Do not add a variant. |
| `DeletionRequestsTitle` | "Deletion requests" / "削除リクエスト" | `TenantDeletionPageTitle` | "Deletion **R**equests" / identical ja | **map** — but the en case differs. **Record which casing wins as a decision**; do not silently pick one. |
| `SecurityCentreTitle` | "Security Centre" / "セキュリティセンター" | `SecurityTitle` | "Security" / "セキュリティ" | **judgement.** Same concept, different wording. |
| `AuditTitle` | "Audit browser" / "監査ブラウザ" | `AuditViewerPageTitle` | "Audit log" / "監査ログ" | **judgement.** Arguably different things. |
| `ScopeSystem` | "System" / "システム" | `AdminScopeSystem` | "System scope" / "システム全体" | **judgement.** |
| `ScopeTenant` | "Tenant" / "テナント" | `AdminScopeTenant` | **"Tenant: {slug}" / "テナント: {slug}"** | **TRAP — do NOT map.** Core's is **parameterised**; the caller substitutes `{slug}`. Mapping here renders a literal `{slug}` in the UI. **Add a new variant.** |

That last row is why §4.1 insists on strings: a name-similarity pass maps it
confidently and ships a visible `{slug}`. **Check every candidate for
substitution placeholders before mapping it**, not just this one.

### 4.3 `auth_shell.rs` — four strings, and the server-rendered path

It uses **`PoweredBy`, `Privacy`, `Status`, `Terms`**. Footer chrome, nothing
more. This is the file R2b's entire six-week deferral rested on: it is a
**pre-authentication** shell, RFC 132 classifies pre-auth **`server`**, and
RFC 132 §13 q1's answer (2026-09-24) confirms `/login` is server-rendered
email-first. So these four resolve through
`cesauth_core::i18n::lookup(MessageKey, Locale)` on the **existing per-request
path** — no client mechanism involved at all.

## 5. Do not

- **Do not import the mockup's i18n** — no second `Locale`, no `Msg`, no
  `LocaleContext`. `grep -rn 'Msg::\|use_locale\|LocaleContext' crates/` must
  return **0** when you are done.
- **Do not build a locale switcher** or a reactive locale context.
- **Do not rename or renumber any of core's 171 existing variants.** Overlap is
  0; nothing requires it.
- **Do not wire any of the ten files to a route or a screen.** That is R3. They
  land **dormant**, exactly as R2a's did.
- **Do not commit mock data or fixtures** (RFC 131 §5: never, at any
  intermediate step).
- **Do not touch CSS.** RFC 179 shipped `base.css` with one rule; `components.css`
  is RFC 179 §8's and not this cycle's. These ten files will reference class
  names that have no rule — **that is expected and must not be "fixed" here.**
- **Do not change the RFC 179 census's `DECLARED_STYLED` set.** Your new files
  will raise the census denominator above 96. **That is correct**; report the new
  number with its arithmetic rather than suppressing it.
- **Do not change any route, wire format, schema, cookie or permission slug.**

## 6. Evidence required

1. **The 47-row table**, one row per key, each resolved to *mapped to
   `MessageKey::X`* or *added as `MessageKey::Y`*, with the arithmetic:
   `47 = mapped + added + 0 unresolved`. **This table is the deliverable** — a
   summary count without it is not reviewable.
2. **Every mapping checked for substitution placeholders** (§4.2's trap).
   State that you checked, not just the outcome.
3. **Rendered-string tests for `auth_shell.rs`'s four keys in both locales** —
   assert the strings a caller builds, not that the variants exist. Asserting
   the enum is not asserting the caller.
4. `grep -rn 'Msg::\|use_locale\|LocaleContext' crates/` → **0**, shown.
5. Host test count **risen**, with its command, **summed with awk over the full
   output** — never hand-added.
6. `route-contracts-check.sh`, `drift-scan.sh`, `migration_chain`, `mdbook`
   unchanged. **The RFC 179 census number will change** — report it with its
   arithmetic.
7. Worker bundle with `sha256sum` **and the gzip level stated** (default, not
   `-9` — a 4,221 B difference, RFC 133 §16).
8. RFC 131's R2a exclusion note updated to say `permission_denied.rs` and
   `suspended_notice.rs` are no longer excluded, and **R2b marked complete**,
   with its coupling-map figures **re-derived rather than carried** (RFC 131's
   own "175" was stale; core is **171**).

## 7. Two things you will hit, disclosed in advance

**`trunk` cannot be installed on this machine** — `libdeflate-sys` fails against
GCC 16.2.1, as your RFC 179 cycle found. **It should mostly not matter here**:
these files land dormant, nothing routes them, and §6.3's tests are host tests on
the **server-rendered** path. If you find yourself needing a browser, stop and
say why — it probably means something was wired that §5 says not to wire.

**`wrangler deploy --dry-run` needs `crates/frontend/dist` to exist** or it
refuses outright. An **empty** `crates/frontend/dist/assets/` is enough for a
valid *Worker* measurement, because `LEPTOS_JS`/`LEPTOS_WASM` are hardcoded
consts at `leptos_shell.rs:85-86` and are not read from it. **Say so in the
report if you do that** — it is a substitution, not the real pipeline.

## 8. Stop conditions — report instead of improvising

- A key's core candidate is **parameterised** and you cannot tell whether the
  caller can supply the parameter: stop. Guessing here ships `{slug}` to a user.
- The ten files need a reactive locale context for a reason §3 did not
  anticipate: stop. That is an architecture finding, not an implementation
  detail, and it reopens what RFC 132 §13 q1 closed.
- `df3d9d0` is not the mockup repository's current `HEAD`: the pin moved, which
  is a finding.
- Any of the 47 cannot be resolved either way: **a named unresolved row is a
  correct outcome**; `47 = mapped + added + 0 unresolved` with a row quietly
  dropped is not.

## 9. Baselines at `5b049b9` (tag `0.92.7`), each with its command

| | value | command |
|---|---|---|
| core `MessageKey` variants | **171** | census over `crates/core/src/i18n/mod.rs:162-410`; reconciles `171 + 36 doc + 19 blank + 21 section = 247` raw lines, **0 unaccounted** |
| mockup `Msg` variants | **263** | same shape over `crates/ui/src/i18n/keys.rs` at `df3d9d0`; `263 + 49 + 51 = 363`, **0 unaccounted** |
| i18n-using mockup files | **10** | `grep -rlE 'crate::i18n\|use_locale\|LocaleContext\|Msg::' crates/ui/src/components/` |
| keys those ten use | **47** | `grep -rhoE 'Msg::[A-Z][A-Za-z0-9_]*'` over those files, `sed`, `LC_ALL=C sort -u` |
| `auth_shell.rs` keys | **4** | same, that file alone |
| exact-name overlap, 47 vs 171 | **0** | `LC_ALL=C comm -12` — **`LC_ALL=C` is required**; without it `comm` returned a wrong partition that still summed correctly during RFC 179's cycle |
| host tests | **1,675 / 0 / 4**, 12 result lines | the canonical five-crate command with `--features cesauth-frontend/csr` |
| `migration_chain` | **35** | `cargo test -p cesauth-migrate-test` |
| `route-contracts-check.sh` | clean; E7 `156 = 8 + 31 + 117` | `./scripts/route-contracts-check.sh` |
| `drift-scan.sh` | clean; colour contrast `22 = 19 + 3 + 0` | `./scripts/drift-scan.sh` |
| RFC 179 census | `96 = 1 + 95 + 0` | `npx playwright test stylesheet-presence.spec.ts` — **expected to rise**; report, do not suppress |
| `mdbook` | **82 pages** | `mdbook build docs` |
| Worker bundle | **889,072 B** gzip-default (878,371 wasm + 10,701 `shim.js`) | `wrangler deploy --dry-run`, sha256 `d11c79a9abd2aa4f` / `d840d5ea14574091` |

**Keep the report short except for §6.1's table**, which should be complete.
`CHANGELOG.md` has 11,306 B of headroom; the detail belongs here and in
`.git-exclude/reviewed/`.
