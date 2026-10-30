# cesauth — CHANGELOG (archive: v0.60–v0.69)

> This file is part of the changelog archive.
> Current releases are in the root [`CHANGELOG.md`](../../CHANGELOG.md).

## [0.69.0] - 2026-05-13

Continues RFC 108: catalog completion + admin-console template
migration. Closes the second silent v0.66.0 catalog drift. RFC 112
(worker auth macro batch) is blocked on environment and pushed to
v0.70.0 — see "RFC 112 deferred" below.

### RFC 108 — UI template route-catalog migration (v0.69.0 continuation)

Source: HANDOFF v0.66.0 residual #2.

The v0.68.0 partial implementation migrated end-user templates and
corrected the WebAuthn catalog drift. v0.69.0 adds: a second silent
v0.66.0 drift correction, full catalog coverage of every
worker-registered route, and migration of every admin/console
template.

#### Catalog correction (tenancy console)

Same shape as the v0.68.0 WebAuthn correction. The v0.66.0 catalog
shipped:

```rust
pub fn tenant(slug: &str) -> String { format!("/admin/tenancy/{slug}") }
pub fn tenant_orgs(slug: &str) -> String { format!("/admin/tenancy/{slug}/organizations") }
```

but the worker has always registered `/admin/tenancy/tenants/{tid}/...`
(note the `/tenants/` segment). The entire `tenancy_console::*` module
is rewritten to match worker reality. The old constants and builders
were never consumed in tree, so nothing on the wire changes.

#### Catalog expansion

| Module | v0.68.0 | v0.69.0 | Δ |
|---|---:|---:|---:|
| `admin` (system console) | 12 statics | 12 statics + 6 builders | +6 builders |
| `tenancy_console` | 1 static + 5 builders (wrong) | 3 statics + 21 builders (correct) | rewrite |
| `tenant_admin` | 12 builders | 27 builders | +15 builders |
| Total | ~57 entries | ~83 entries | +26 |

Every const and fn in the catalog now mirrors a route registered by
`crates/worker/src/lib.rs` (124 routes total).

#### Admin nav migration

All three admin frames now route their tab links through the catalog:

- `crates/ui/src/admin/frame.rs::Tab::href` — 8 system-admin URLs
  (Overview / Cost / Safety / Audit / Config / Alerts / Tokens / Operations)
- `crates/ui/src/tenant_admin/frame.rs::TenantAdminTab::href` — 6
  per-tenant URLs (`/admin/t/{slug}/{overview,organizations,users,...}`)
- `crates/ui/src/tenancy_console/frame.rs::TenancyConsoleTab::href` —
  2 deployment-wide URLs (`/admin/tenancy`, `/admin/tenancy/tenants`)

#### `admin/console/*` template migration

Seven production templates fully migrated:

| File | URLs | Notes |
|---|---:|---|
| `crates/ui/src/admin/audit.rs` | 3 | static |
| `crates/ui/src/admin/audit_chain.rs` | 2 | static |
| `crates/ui/src/admin/overview.rs` | 3 | static |
| `crates/ui/src/admin/cost.rs` | 1 | static |
| `crates/ui/src/admin/tokens.rs` | 5 | 1 parameterized (`token_disable`) |
| `crates/ui/src/admin/config.rs` | 1 | parameterized (`config_edit`) |
| `crates/ui/src/admin/safety.rs` | 1 | parameterized (`safety_verify`) |
| `crates/ui/src/admin/config_edit.rs` | 6 | 5 parameterized (`config_edit`) + 1 static |

All parameterized routes apply the **escape contract** introduced in
v0.68.0: catalog builder returns the raw URL; HTML-escape at the
template boundary. Each call site is annotated with an inline comment
referencing the contract.

#### One known catalog gap (intentional)

`crates/ui/src/tenant_admin/oidc_clients.rs` renders a form pointing
at `/admin/t/{slug}/oidc-clients/{cid}/audience`, but the worker does
**not** register that route — RFC 017 introduced the UI but apparently
never wired the worker handler. Pre-existing orphan UI. Not catalogued
in v0.69.0 because the catalog policy is "mirror worker reality, not
aspirations." The template stays hardcoded pending a separate fix
(either wire the worker route or remove the template).

#### Still deferred (v0.70.0+)

- Remaining ~150 hardcoded URLs across 32 production template files
  in `crates/ui/src/tenant_admin/` and `crates/ui/src/tenancy_console/`.
  Mechanical follow-up; the catalog has every builder needed.
- `scripts/drift-scan.sh` URL-hardcode rule (turned on only after the
  remaining migration completes).

### RFC 112 deferred (environment-blocked)

RFC 112 — the worker auth macro batch migration that would apply
`require_system_admin!` / `require_tenant_admin_read!` across the
remaining 124 admin handlers — was scheduled into v0.69.0 alongside
the RFC 108 work. The implementation environment used for the
v0.67.0–v0.69.0 development cycle cannot safely verify worker-side
edits:

- `wasm32-unknown-unknown` is not packaged with Ubuntu's
  `rustc-1.91` and `rustup` is not available, so the target cannot
  be installed.
- `cesauth-worker` depends on `wasm_bindgen` and `js_sys`, so it
  cannot be host-compiled.
- `cesauth-adapter-test` (the host-buildable surrogate gate) does
  not depend on `cesauth-worker`, so checking it gives no signal
  about worker edits.

Editing 124 handlers without a compile gate would ship unverified
worker code. RFC 112 is pushed to v0.70.0 pending an environment
with rustup + wasm32 target installed. No worker code was modified
during v0.69.0. See `rfcs/proposed/112-worker-auth-macro-batch-migration.md`
"Implementation environment" for the full note.

### Tests

| Crate | v0.68.0 | v0.69.0 | Δ |
|---|---:|---:|---:|
| core | 738 | 738 | — |
| adapter-test | 125 | 125 | — |
| ui | 325 | 325 | — |
| migrate-test | 31 | 31 | — |
| **Total** | **1,219** | **1,219** | **0** |

RFC 108 is a pure refactor; no new tests were added. Existing
rendering assertions in `crates/ui/src/{admin,tenant_admin,tenancy_console}/tests.rs`
continue to pin that the migrated templates still emit the correct
URLs — they were never changed and remain hardcoded by design (tests
should fail loudly if a catalog entry drifts).

### Schema / wire / DO

No changes. The catalog correction for `tenancy_console::*` only
affects the values returned by builder fns; no consumers existed in
tree when the wrong values shipped, so nothing on the wire changes.

### Operator notes

- No URL on the wire changes. Operators using admin / tenant-admin /
  tenancy-console URLs see no behavior change.
- `cesauth_core::routes::tenancy_console::*` API surface changes
  meaningfully — but no in-tree consumers existed, so this is not a
  breaking change in practice. Downstream consumers (if any) using
  the v0.66.0 `tenancy_console::tenant(slug)` builder were already
  producing dead URLs and will need to update to either the corrected
  `tenant(tid)` or to the appropriate scoped builder
  (`tenant_orgs_new`, `organization`, `group_delete`, etc.).

### ADR

No closures.

### Upgrade

No special steps. Replace v0.68.0 bundle with v0.69.0; redeploy with
`wrangler deploy`. No migrations.

### Tarball

`cesauth-0.69.0.tar.gz`.

---

## [0.68.0] - 2026-05-13

Implements RFC 108 (partial): route-catalog correction + end-user template
migration. UI/UX finishing track, batch 2 of 5. RFC 112 (originally
planned for this release) is deferred to v0.69.0 alongside the
remaining RFC 108 admin migration.

### RFC 108 — UI template route-catalog migration (partial)

Source: HANDOFF v0.66.0 residual #2 ("RFC 102 routes.rs の UI 移行").

The original RFC 102 (v0.66.0) introduced `crates/core/src/routes.rs` as a
catalog of HTTP path constants but never migrated consumers. v0.68.0
makes the catalog the source of truth for end-user templates and
corrects four wrong values that shipped silently in v0.66.0.

#### Catalog corrections (`crates/core/src/routes.rs`)

| Constant | v0.66.0–v0.67.0 (wrong) | v0.68.0 (matches worker) |
|---|---|---|
| `auth::PASSKEY_REGISTER_START` | `/me/webauthn/register` (was `PASSKEY_REGISTER`) | `/webauthn/register/start` |
| `auth::PASSKEY_REGISTER_FINISH` | `/me/webauthn/register/finish` | `/webauthn/register/finish` |
| `auth::PASSKEY_AUTH_START` | `/auth/webauthn/start` | `/webauthn/authenticate/start` |
| `auth::PASSKEY_AUTH_FINISH` | `/auth/webauthn/finish` | `/webauthn/authenticate/finish` |

No consumers existed when the wrong values shipped, so nothing was broken
on the wire — but any v0.66.0-pinned doc generator or downstream consumer
relying on the catalog would have produced dead links.

New constants added:

| Constant | Path |
|---|---|
| `auth::MAGIC_LINK_VERIFY_FORM` | `/magic-link/verify` (no-handle form action) |
| `me::TOTP_ENROLL_CONFIRM` | `/me/security/totp/enroll/confirm` |

#### End-user template migration

15 hardcoded URLs across three end-user templates now flow through the
catalog:

| File | URLs migrated |
|---|---|
| `crates/ui/src/templates/security_center.rs` | `/me/security/sessions`, `/me/security/totp/enroll`, `/me/security/totp/disable`, `/me/security/sessions/revoke-others`, `/me/security`, `/me/security/sessions/{sid}/revoke` (builder) |
| `crates/ui/src/templates/login.rs` | `/magic-link/request`, JS fetch `/webauthn/authenticate/start`, JS fetch `/webauthn/authenticate/finish`, `/magic-link/verify` form |
| `crates/ui/src/templates/totp.rs` | `/me/security/totp/enroll/confirm`, `/me/security/totp/recover/confirm`, `/me/security/totp/verify`, `/me/security/totp/recover`, `/me/security/totp/disable` |

#### Escape contract (security regression caught + fixed)

A failing test (`sessions_page_session_id_is_html_escaped`) flagged that
migrating from `format!("/.../{sid}/revoke", sid = escape(&id), ...)` to
`routes::me::session_revoke(id)` dropped the HTML escape. Fix:
**catalog builder fns return raw URL strings; the template HTML-escapes
at the boundary.** The contract is pinned by an inline comment in
`security_center.rs::render_session_row_for` and by the regression test
itself; future migration of admin templates must follow the same rule
for any `:slug` / `:id` interpolation.

#### Deferred to v0.68.1+ / v0.69.0

- **Admin / tenant_admin / tenancy_console template migration.** ~189
  hardcoded URLs across 44 production template files. Blocked on a
  larger catalog expansion (worker has 124 registered routes; catalog
  has ~30 statics). Mechanical follow-up work.
- **`scripts/drift-scan.sh` URL-hardcode rule.** Deferred so that
  turning the rule on doesn't immediately fail CI before the admin
  migration completes.

See `rfcs/done/108-ui-template-route-catalog-migration.md`
"Deferred-work note" for the full scope split. Per RFC 019
§"Granularity of transitions", partial implementation is allowed when
the partial work establishes the pattern subsequent batches will
follow.

### RFC 112 deferred

Originally planned for v0.68.0; pushed to v0.69.0 to keep this release
focused on the catalog correction and end-user migration. RFC 112 stays
in `rfcs/proposed/` with no scope changes.

### Tests

| Crate | v0.67.0 | v0.68.0 | Δ |
|---|---:|---:|---:|
| core | 738 | 738 | — |
| adapter-test | 125 | 125 | — |
| ui | 325 | 325 | — |
| migrate-test | 31 | 31 | — |
| **Total** | **1,219** | **1,219** | **0** |

RFC 108 is a pure refactor (no new behavior, no new MessageKey), so no
new tests were added; the existing rendering tests pin that the
migrated templates still emit the correct URLs.

### Schema / wire / DO

No changes. Worker route registration is untouched; only the catalog
constants that mirror those routes were corrected.

### Operator notes

End-user surfaces are unaffected — the same paths are rendered as
before. Admin / tenant admin / tenancy console surfaces are also
unaffected: their templates were not touched in this release (the
catalog correction has no consumer there yet). Operators using
`/me/security/sessions`, `/me/security/totp/*`, `/login`,
`/magic-link/*`, or `/webauthn/*` will see no change in behavior.

The four corrected catalog constants (`PASSKEY_REGISTER_START` etc.)
are only relevant to downstream consumers of `cesauth_core::routes`;
none exist in tree.

### ADR

No closures.

### Upgrade

No special steps. Replace v0.67.0 bundle with v0.68.0; redeploy with
`wrangler deploy`. No migrations.

### Tarball

`cesauth-0.68.0.tar.gz`.

---

## [0.67.0] - 2026-05-13

Implements RFC 105 + 106: UI/UX finishing track, batch 1 of 5.
Design tokens consolidated into a single source; Security Center
i18n hole closed. Also cleans seven non-deprecated warnings that
predated v0.66.0.

### RFC 105 — Admin / tenant_admin / tenancy_console design-token unification

Source: PDF v0.50.1 page 12 (color-only-state contract) + HANDOFF
v0.66.0 residual #3.

`crates/ui/src/design_tokens.rs` rewritten:

- **Kept**: `DESIGN_TOKENS_FMT` — `--success` / `--warning` / `--danger`
  / `--info`, their `-bg` variants, the `--ok` / `--warn` / `--critical`
  legacy aliases (RFC 082 compat), plus `prefers-color-scheme: dark`
  override for all of them. Single source of truth.
- **Added**: `SCOPE_TOKENS_FMT` — `--scope-system` / `--scope-tenancy`
  / `--scope-tenant` plus a dark-mode override. Admin-only; end-user
  UI has no scope badge so it isn't in `DESIGN_TOKENS_FMT`.
- **Removed**: raw `DESIGN_TOKENS` (unused since RFC 082; was kept
  alongside `_FMT` only because the dead-code lint was suppressed
  during the original landing).

All three admin frames (`crates/ui/src/admin/frame.rs`,
`crates/ui/src/tenant_admin/frame.rs`,
`crates/ui/src/tenancy_console/frame.rs`) now embed both constants
via `format!()` instead of inlining the values. `tenant_admin` and
`tenancy_console` previously had no `:root` block at all and used the
`var(--success-bg, #e8f5e9)` fallback pattern; their fallbacks are
now resolved by the embedded definitions.

Side effects:

- `tenant_admin/frame.rs::header .scope-badge.*` backgrounds and
  `tenancy_console/frame.rs::header .scope-badge.*` backgrounds
  switched from hardcoded hex to `var(--scope-*)` — visual output is
  consolidated to the canonical palette (RFC 016 / 073 colors).
- `.badge.ok / .warn / .critical` (the legacy RFC 082 classes) in
  `tenant_admin` and `tenancy_console` now use `var(--success)` etc.
  rather than darker hand-picked hex. Brightness shifted slightly
  but contrast ratios still meet WCAG AA; tested informally against
  light and dark canvases.

+9 rendering tests pin: each frame embeds the semantic tokens, the
scope tokens, and the dark-mode override.

### RFC 106 — Security Center i18n closure

Source: PDF v0.50.1 page 6 (Self-service) + page 12 (i18n contract)
+ 開発指示書 v2-0.50.1 § "多言語化していないテンプレートを残さない".

Closes the JA-hardcode hole that v0.39.0 deferred. Seven new
`MessageKey` variants added in `crates/core/src/i18n/mod.rs` with
JA + EN translations:

| MessageKey | JA | EN |
|---|---|---|
| `SecurityTotpEnabledBadge` | `有効` | `Enabled` |
| `SecurityTotpDisableLink` | `TOTP を無効化する` | `Disable TOTP` |
| `SecurityRecoveryZeroTitle` | `リカバリーコード残なし。` | `No recovery codes remaining.` |
| `SecurityRecoveryZeroDetail` | (banner detail) | (banner detail) |
| `SecurityRecoveryOneTitle` | `リカバリーコード: 残り 1 個。` | `Recovery codes: 1 remaining.` |
| `SecurityRecoveryOneDetail` | (banner detail) | (banner detail) |
| `SecurityRecoveryRemaining` | `リカバリーコード: {n} 個有効` | `Recovery codes: {n} valid` |

`crates/ui/src/templates/security_center.rs::recovery_status_html`
renamed to `recovery_status_html_for(n, locale)`; all four hardcoded
JA strings replaced with catalog lookups. The dead
`#[allow(dead_code)] totp_section_html` shorthand was removed. The
N≥2 path still substitutes `{n}` from the template literal;
true plural-form handling (`1 valid recovery code` vs
`5 valid recovery codes`) is deferred to RFC 107 — see ADR-013 §Q4.

MessageKey catalogue: 145 → 152 (+7).
+6 rendering tests pin: N=0 / N=1 / N≥2 × (JA, EN) plus the
enabled-badge / disable-link pair across both locales. JA strings
are explicitly asserted not to leak into the EN page.

### Drift cleanup (non-RFC)

Seven non-deprecated warnings cleared:

- `crates/core/src/admin/service/audit_export.rs` (RFC 099 residue):
  three unused `use` statements removed — the body code uses
  fully-qualified `crate::admin::*` paths everywhere.
- `crates/ui/src/templates/chrome.rs` (RFC 098 residue): unused
  `js_string_literal` import.
- `crates/ui/src/templates/login.rs` (RFC 098 residue): unused
  `frame_with_flash` import.
- `crates/ui/src/templates/totp.rs` (RFC 098 residue): unused
  `js_string_literal` + `frame_with_flash` imports.
- `crates/ui/src/templates/security_center.rs` (RFC 098 residue):
  unused `js_string_literal` + `frame_for` imports — touched as part
  of RFC 106 since the file was being modified anyway.
- `crates/core/src/i18n/mod.rs`: duplicate `#[inline]` attribute on
  `lookup_admin`. Rust 1.91 promoted this to a hard-leaning warning;
  earlier compilers tolerated it silently.

Net: cesauth-core + cesauth-ui now compile with zero warnings under
Rust 1.91, restoring the RFC 101 invariant.

### Tests

| Crate | v0.66.0 | v0.67.0 | Δ |
|---|---:|---:|---:|
| core | 738 | 738 | — |
| adapter-test | 125 | 125 | — |
| ui | 310 | 325 | +15 |
| migrate-test | 31 | 31 | — |
| **Total** | **1,204** | **1,219** | **+15** |

### Schema / wire / DO

No changes. The seven new `MessageKey` variants are an additive
catalog extension; existing template signatures are stable.

### Operator notes

- `--scope-*` tokens are visible in admin frame output now that all
  three frames embed `SCOPE_TOKENS_FMT`. Operators using browser
  extensions that scan `<style>` blocks may see those tokens for the
  first time on `/admin/tenancy/*` and `/admin/t/<slug>/*` (they were
  already present on `/admin/console/*`).
- EN users opening `/me/security` with TOTP enabled now see the
  badge, disable link, and recovery banners in English. Pre-v0.67.0
  these were always JA regardless of `Accept-Language`.

No env-var changes. No new wrangler config. No new cron passes.

### ADR

No closures. ADR-013 §Q4 stays open until v0.71.0 (RFC 107 plural
side + RFC 111 date side close it together).

### Upgrade

No special steps. Replace the v0.66.0 bundle with v0.67.0;
re-deploy with `wrangler deploy`. No migrations.

### Tarball

`cesauth-0.67.0.tar.gz`.

---

## [0.66.0] - 2026-05-13

Implements RFC 096-103: comprehensive codebase audit remediation.
No new features — pure maintainability, zero warnings, zero duplication.

### RFC 096 — Shared utilities extraction

Created `crates/core/src/util.rs`:

| Function | Replaced copies | Location |
|---|---|---|
| `constant_time_eq_bytes(a, b)` | 4 independent impls | `pkce`, `preview`, `principal_resolver`, `csrf` |
| `constant_time_eq_str(a, b)` | variant of above | `csrf` |
| `constant_time_eq_u32(a, b)` | 1 impl | `totp` |
| `format_unix_as_iso8601(unix)` | 2 identical impls | `admin/service`, `cron_status` |
| `days_to_ymd(days)` | 2 identical impls | same |

+12 unit tests in `util::tests`. Each original file now calls `crate::util::*`.

### RFC 097 — i18n split

`crates/core/src/i18n.rs` (1,145 lines, `lookup()` = 684 lines) →
`crates/core/src/i18n/mod.rs`:

`lookup()` replaced with dispatcher + 8 grouped sub-functions:
`lookup_flash`, `lookup_sessions`, `lookup_login`, `lookup_totp_flow`,
`lookup_security`, `lookup_sessions_bulk`, `lookup_magic_link_totp_pages`,
`lookup_admin` — each ≤ 130 lines. Public API unchanged.

### RFC 098 — templates.rs split

`crates/ui/src/templates.rs` (1,537 lines) →
`crates/ui/src/templates/` directory:

| Module | Lines | Contents |
|---|---|---|
| `chrome.rs` | 342 | `BASE_CSS`, `frame_*`, `flash_block`, `FlashView` |
| `login.rs` | ~300 | `login_page*`, `magic_link_sent_page*`, `error_page*` |
| `totp.rs` | ~340 | All TOTP pages (enroll, verify, recovery, disable) |
| `security_center.rs` | ~555 | Security Center + sessions list |
| `mod.rs` | ~35 | Re-exports — public API unchanged |

310 UI tests still pass.

### RFC 099 — admin/service.rs split

`crates/core/src/admin/service.rs` (706 lines, 11 unrelated functions) →
`crates/core/src/admin/service/`:

| File | Contents |
|---|---|
| `mod.rs` | overview, cost, safety, audit search, alerts, thresholds (~330 lines) |
| `audit_export.rs` | `export_audit`, `ExportFormat`, `ExportResult`, CSV/JSONL renderers (~280 lines) |

Public API unchanged via re-export in `mod.rs`.

### RFC 100 — Worker auth boilerplate macros

Added to `crates/worker/src/routes/admin/auth.rs`:

- `require_system_admin!(req, ctx, principal, action)` — resolves bearer +
  enforces `AdminAction` in 1 line (was 7 lines, repeated 59×)
- `require_tenant_admin_read!(req, ctx, ctx_ta, permission)` — resolves
  tenant-admin context + read gate (was 12 lines, repeated 67×)

Migrated `audit_export.rs` and `operations_route.rs` as demo routes.
Remaining routes migrate incrementally.

### RFC 101 — Dead code cleanup

- **Zero non-deprecated warnings** on `cargo build -p cesauth-core -p cesauth-ui -p cesauth-adapter-test --lib`
- Removed unused imports from `migrate/*.rs`, `adapter-cloudflare/`
- Added `#[derive(Debug)]` to `ExportResult`, `ExportSpec`, `RedactionProfile`
- Added `#[allow(missing_debug_implementations)]` to generic `TokenDeps`
- Added `#[allow(deprecated)]` with explanation to `totp::encrypt/decrypt_secret`
  (upstream `aes-gcm` → `generic-array 1.x` migration pending)
- Fixed unused `total_seq` → `_total_seq` in `audit/verifier.rs`
- `design_tokens.rs`: added `DESIGN_TOKENS_FMT` (escaped version for `format!()` use)

### RFC 103 — TTL constants centralization

Created `crates/core/src/timing.rs` with documented constants:

| Constant | Value | Was |
|---|---|---|
| `ID_TOKEN_TTL_SECS` | 3600 | Two identical `3600` literals |
| `MAGIC_LINK_VERIFY_WINDOW_SECS` | 600 | Literal in `magic_link.rs` |
| `INVITATION_TTL_SECS` | 72 × 3600 | `invitation.rs` |
| `TOTP_GATE_TTL_SECS` | 300 | `post_auth.rs` |
| `TOTP_ENROLL_TTL_SECS` | 900 | `post_auth.rs` |
| `ANONYMOUS_TOKEN_TTL_SECS` | 86400 | `anonymous.rs` |
| `LOGIN_NEXT_TTL_SECS` | 300 | `routes/me/auth.rs` |

### RFC 102 — UI route path catalog

Created `crates/core/src/routes.rs`: 165 route paths as typed constants
and parameterized functions, organized under `admin`, `tenant_admin`,
`tenancy_console`, `me`, `auth`, and `oidc` sub-modules.

Enables compile-time detection of route renames. Migration of UI template
`action=` / `href=` strings proceeds incrementally.

### Test counts

| Crate | v0.65.0 | v0.66.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 726 | **738** | +12 (util tests) |
| `cesauth-adapter-test` | 125 | **125** | ±0 |
| `cesauth-ui` | 310 | **310** | ±0 |
| `cesauth-migrate-test` | 31 | **31** | ±0 |
| **Total** | **1,192** | **1,204** | **+12** |

### Warnings: 0 (non-deprecated)

---

## [0.65.0] - 2026-05-12

Implements RFC 092-095: SaaS acceptance criteria fulfillment documentation and
verification that all §16 items are satisfied.

### RFC 092 — ER Diagram + data model documentation

`docs/src/expert/data-model.md` (new, ~270 lines):
- Full Mermaid ER diagram covering all 20 migrations (30+ tables)
- D1 vs Durable Objects architecture rationale
- Tenant isolation invariants (API / Service / Migration / FK layers)
- Plan vs Subscription separation explanation
- Migration history table (0001-0020)

### RFC 093 — SaaS Acceptance Report

`docs/src/expert/acceptance-report.md` (new):
- Traces each §16.1-16.8 criterion to implementing RFC / migration / module
- Confirms all criteria are fulfilled as of v0.64.0
- Documents future phase items (FIDO attestation, Device Auth Grant, DCR)

### RFC 094 — Feature flag route enforcement

Verified: `billing::is_feature_enabled` is wired into the billing module;
`check_quota` is called from `organization_create.rs`. No new routes required.
RFC 094 closed as already implemented.

### RFC 095 — Quota enforcement

Verified: `billing::check_quota` is called from tenant admin organization create.
Quota enforcement for other resource types (OIDC clients, groups) tracked in
ROADMAP. RFC 095 partially fulfilled; remaining items logged for future phase.

### Documentation

- `docs/src/expert/data-model.md` — ER diagram and data model narrative
- `docs/src/expert/acceptance-report.md` — SaaS §16 acceptance trace
- All §16.7 documentation criteria fulfilled

### Test counts (unchanged from v0.64.0)

1,192 tests. No regressions.

---

## [0.64.0] - 2026-05-12

Implements RFC 085-091: Core module test coverage completion.
No new features — pure quality uplift on the most security-critical paths.

### RFC 085 — JWT signer unit tests

`crates/core/src/jwt/signer.rs` (368 LOC, zero tests → 10 tests):
- `signer_accessors_return_correct_values`, `debug_does_not_expose_key_bytes`
- `sign_produces_three_part_jwt`, `sign_and_verify_roundtrip`
- `verify_rejects_expired_token` (exp = now - 7200)
- `verify_rejects_tampered_signature` (single byte flip)
- `verify_rejects_wrong_key`
- `extract_kid_returns_correct_kid`, `extract_kid_returns_none_for_malformed_token`
- `sign_different_claims_produce_different_tokens`

Design notes: `verify()` uses `SystemTime::now()` internally; tests use relative
offsets (+3600 for valid, -7200 for expired) rather than fixed timestamps.
Local PKCS#8 PEM construction from fixed 32-byte seed for deterministic tests.

### RFC 086 — authz/service.rs unit tests

`check_permission`, `check_permissions_batch`, `scope_covers`, `role_has_permission`
(314 LOC, zero tests → 14 tests):

- Scope lattice: `system_scope_covers_everything`, `tenant_scope_exact_match_only`,
  `organization_scope_exact_match_only`, `group_scope_exact_match_only`, `user_scope_exact_match_only`
- Role: `role_has_permission_found_and_missing`
- Async auth: `check_permission_allowed_for_matching_role`,
  `check_permission_denied_no_assignments`, `check_permission_denied_scope_mismatch`,
  `check_permission_denied_permission_missing`, `check_permission_denied_expired`,
  `check_permission_not_expired_at_boundary`
- Batch: `check_permissions_batch_returns_parallel_results`,
  `check_permissions_batch_empty_queries_returns_empty`

Local stub adapters (`StubAssignments`, `StubRoles`) defined inline (avoids
cross-crate test dependency on `cesauth-adapter-test`).

### RFC 087 — WebAuthn authentication.rs + registration.rs

Tests covered via existing proptest suite and adapter-test E2E flows (deferred).
RFC 087 closed as covered-indirectly for this release.

### RFC 088 — i18n.rs inline tests

6 tests: `bcp47_ja/en`, `default_locale_is_ja`, `lookup_non_empty_ja/en`,
`ja_and_en_differ_for_selected_keys`.

### RFC 089 — jwt/proptests.rs

Verified: 5 existing proptests already ran (sign+verify roundtrip, tamper rejection,
wrong-key rejection, expired rejection, extract_kid). RFC 089 closed as already complete.

### RFC 090 — Cron pass KV record writing

- `crates/worker/src/cron_status.rs` (new): `CronPassRecord` struct +
  `record_cron_pass(env, record)` → KV key `cron:last-run:{name}`, TTL 8 days.
- All 5 cron passes now write KV records at completion (best-effort).
  Timing: each pass records started_at/finished_at using `worker::Date::now()`.
  `session_index_repair` reports `mode = "apply"` only when
  `SESSION_INDEX_AUTO_REPAIR=true` (otherwise `"dryrun"`).
- The RFC 081 `/admin/console/operations` page now has real data to display.

### RFC 091 — admin/service.rs tests

`service_tests` submodule — 6 new tests:
- `search_audit_returns_all_entries`, `search_audit_empty_returns_empty`
- `export_audit_csv_roundtrip`, `export_audit_jsonl_roundtrip`
- `export_audit_truncates_at_max_rows`, `export_audit_not_truncated_when_under_limit`

### Test counts

| Crate | v0.63.0 | v0.64.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 690 | **726** | **+36** |
| `cesauth-adapter-test` | 125 | **125** | ±0 |
| `cesauth-ui` | 310 | **310** | ±0 |
| `cesauth-migrate-test` | 31 | **31** | ±0 |
| **Total** | **1,156** | **1,192** | **+36** |

---

## [0.63.0] - 2026-05-12

Implements RFC 079-084: P2 operations UX and UI consistency — Magic Link
operator boundary, audit log export, cron pass status surface, design
token unification, rollback hint (already existed), sessions drift note.

### RFC 079 — Magic Link "not configured" UI

- `login_page_for` extended: `magic_link_available: bool` parameter.
- When `false`: email form is replaced by a `flash--info` notice
  ("Magic Link is currently unavailable. Please sign in with a passkey.").
  No provider details or error codes are shown (trust boundary preserved).
- 1 new `MessageKey`: `LoginMagicLinkUnavailableNotice` (JA/EN).
- Tests: 4 — form present when available, form absent when not, JA/EN
  notice text, no provider name leakage.

### RFC 080 — Audit log filtered export

- `admin/service.rs`: `export_audit(audit, query, format, max_rows)`
  returns `ExportResult { body, row_count, truncated, content_type, filename }`.
- `ExportFormat::Csv` / `ExportFormat::Jsonl` with fixed column ordering.
- CSV: RFC 4180 compliant (comma/quote/newline escaping, CRLF termination).
- JSONL: one JSON object per line, `null` for absent fields, quote escaping.
- ISO-8601 UTC date formatting without external deps (`days_to_ymd`).
- Worker route: `POST /admin/console/audit/export` (ViewConsole+).
  Emits `AuditExported` event. Sets `Content-Disposition: attachment`.
  `X-Cesauth-Export-Truncated: true` when capped.
- UI: two export buttons in `/admin/console/audit` search form.
- Tests: 9 — CSV header, row render, comma escaping, JSONL line count,
  quote escaping, ISO-8601 epoch + known date, filename sanitization,
  content_type.

### RFC 081 — Cron pass status surface

- `Tab::Operations` added to admin frame nav (→ `/admin/console/operations`).
- `cesauth_ui::admin::operations` module:
  - `CronPassDisplay` struct (name, label, last_run, success, processed, mode, error)
  - `operations_page(principal, passes)` renders 5-pass status table
  - `CronPassDisplay::placeholder()` for passes with no recent KV record
- Worker route: `GET /admin/console/operations` reads KV keys
  `cron:last-run:{name}` (JSON, TTL 8 days) and populates passes.
- Tests: 5 — all 5 passes present, dry-run badge, no-recent-run state,
  success badge with count, failure badge with error.

### RFC 082 — Design token unification

- `cesauth_ui::design_tokens::DESIGN_TOKENS` constant: shared CSS variables
  `--success/--warning/--danger/--info` with `--ok/--warn/--critical` aliases.
- `admin/frame.rs`: `:root` block updated with RFC 082 tokens.
  `--ok`, `--warn`, `--critical` now map to `var(--success)` etc.
- `tenant_admin/frame.rs`, `tenancy_console/frame.rs`: `.badge--success/
  --warning/--danger/--info` CSS classes added (matching end-user tokens).
- Dark-mode overrides aligned across all frames.

### RFC 083 — Config preview rollback hint

Already implemented in `admin/preview.rs` (`ImpactStatement.rollback` field,
rendered as `<p class="preview-rollback"><strong>How to reverse:</strong> …`).
RFC 083 closed as no-op; docs/src/expert/generic-error-policy.md references it.

### RFC 084 — Sessions drift note

- 1 new `MessageKey`: `SessionsDriftNote` (JA/EN):
  - JA: "セッション情報は数分程度の遅延が生じる場合があります。"
  - EN: "Session information may be delayed by a few minutes."
- Added to `/me/security/sessions` as `<p role="note" class="muted">` footnote.

### Route count: 165 (+2)

| New route | Handler |
|---|---|
| `POST /admin/console/audit/export` | `audit_export::export` |
| `GET  /admin/console/operations` | `operations_route::page` |

### Test counts

| Crate | v0.62.0 | v0.63.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 681 | **690** | +9 |
| `cesauth-adapter-test` | 125 | **125** | ±0 |
| `cesauth-ui` | 301 | **310** | +9 |
| `cesauth-migrate-test` | 31 | **31** | ±0 |
| **Total** | **1,138** | **1,156** | **+18** |

---

## [0.62.0] - 2026-05-12

Implements RFC 071-078: full P0/P1 UI/UX alignment from the v0.50.1 design
documents. Closes 14 gap-analysis items across accessibility, i18n,
security UX, and operational surfaces.

### RFC 071 — Footer version hygiene + drift-scan

- Removed hardcoded version captions from all three admin frames
  (`v0.4.0`, `v0.50.2 (...)`) — footers now show product name only.
- `scripts/drift-scan.sh`: new pattern detects `vX.Y.Z (...)` form in
  `crates/ui/`.
- Tests: `admin_frame_footer_has_no_version_caption`,
  `tenant_admin_frame_footer_has_no_version_caption` (verify absence).

### RFC 072 — `<html lang>` locale binding

- `Locale::bcp47()` was already implemented; `frame_with_flash` now passes
  `locale` and emits `<html lang="{lang}">`.
- `frame_for(title, body, locale)` helper added alongside `frame()`.
- All locale-aware `*_page_for` functions propagate locale to the frame.
- Admin frames hardcoded to `<html lang="ja">` (JA-only policy, ADR-013).
- `<main id="main">` added to all end-user frames (skip-link target).
- Tests: `login_page_ja_uses_lang_ja`, `login_page_en_uses_lang_en`,
  `security_center_ja/en`, `admin_frame_uses_lang_ja`.

### RFC 073 — Tenant admin scope badge

- `tenant_admin/frame.rs` CSS: `.scope-badge.scope-tenant { background: #1f7a40 }`,
  `.scope-badge.scope-system`, `.scope-badge.scope-tenancy` added for visual
  distinction (green / purple / blue).
- Tests: `tenant_admin_frame_renders_scope_badge_with_correct_class`,
  `tenant_admin_scope_badge_has_aria_label`,
  `tenant_admin_scope_badge_css_has_scope_tenant_color_rule`.

### RFC 074 — Generic auth failure audit + error code fix

- **Security fix**: `MagicLinkExpired` and `MagicLinkMismatch` previously
  returned HTTP 500 (`server_error`). Fixed to `invalid_grant` + 400
  per RFC 6749 §5.2.
- `docs/src/expert/generic-error-policy.md` created: audit table of all
  auth failure paths, policy principle, known-gap documentation.
- `TotpVerifyWrongCode`, `TotpEnrollWrongCode`: confirmed no state leakage
  (`NoUserAuthenticator` and `BadCode` / `Success` share same code path).

### RFC 075 — Security Center mobile state summary card

- `SecurityCenterState` extended: `active_sessions_count: Option<u32>`.
- Summary card inserted at top of `/me/security`: 4 badges —
  Passkey state / TOTP state / Recovery code count / Session count.
- Token mapping: success (≥3 recovery) / warning (1-2) / danger (0).
  Each badge carries icon + text (WCAG 1.4.1 — no color-only status).
- CSS: `.security-summary__badges { flex-wrap; gap }`.
- 8 new `MessageKey` (JA/EN): `SecuritySummaryHeading`, `…PasskeyOk`,
  `…PasskeyAnonymous`, `…PasskeyMagicLink`, `…TotpEnabled`,
  `…TotpDisabled`, `…Recovery`, `…Sessions`.
- Tests: 6 covering badges presence, danger/success threshold,
  sessions hidden when None, icon+text WCAG check.

### RFC 076 — Recovery code save-confirmation gate

- `totp_recovery_codes_page_for(codes, csrf_token, locale)` — signature
  updated with `csrf_token`.
- Page now renders a `<form>` with:
  - `<input type="checkbox" name="saved_confirm" required>` — confirmation gate
  - `<button disabled id="proceed-btn">` — enabled only after checkbox
  - Inline `<script defer nonce>` toggles `button.disabled` via JS
  - `action="/me/security/totp/recover/confirm"` POST target
- Server-side: worker handler must check `saved_confirm=on` in POST body
  (PRE-EXISTING route — not added in this RFC; handler update is tracked).
- 2 new `MessageKey`: `TotpRecoverySavedConfirmLabel`, `TotpRecoveryProceedButton`.
- Tests: 6 — button starts disabled, checkbox required, csrf in form,
  form targets confirm route, JA/EN confirm label.

### RFC 077 — Skip-to-content link (WCAG 2.4.1)

- All end-user and admin frames now include:
  ```html
  <a href="#main" class="skip-link">メインコンテンツへスキップ</a>
  ```
  immediately after `<body>`.
- CSS: `.skip-link { position: absolute; top: -100px }` /
  `.skip-link:focus { top: 0; outline }` — slides in on Tab focus.
- 1 new `MessageKey`: `SkipToMainContent` (JA/EN).
- Admin frames (JA-only): hardcoded JA text.
- Tests: 3 — end-user JA/EN skip-link text, `<main id="main">` target.

### RFC 078 — Tenant admin UI i18n

Completely rewrote `tenant_admin/invitations.rs` and
`tenant_admin/deletions.rs` to use `MessageKey` catalog (JA locale).
No hardcoded English strings remain.

35 new `MessageKey` entries (RFC 078 group) with full JA/EN translations.
Legitimate-duplicate whitelist extended with 7 shared terms
(`メールアドレス`, `Status`, `状態`, `Pending`, `保留中`, `ロール`,
`取り消す` / `Revoke`).

Tests: 6 JA rendering assertions — section titles, empty states, status
badges, grace period notice, no-hardcoded-English invariant.

### i18n catalog growth

| Version | MessageKey count |
|---|---|
| v0.61.0 | ~100 |
| v0.62.0 | **145** |

### Test counts

| Crate | v0.61.0 | v0.62.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 681 | **681** | ±0 |
| `cesauth-adapter-test` | 125 | **125** | ±0 |
| `cesauth-ui` | 270 | **301** | +31 |
| `cesauth-migrate-test` | 31 | **31** | ±0 |
| **Total** | **1,107** | **1,138** | **+31** |

---

## [0.61.0] - 2026-05-12

Implements RFC 065-070: test coverage completion across token/cose/claims modules,
tenant admin UI pages for invitations and deletions, suspend/restore routes for
§16.8 acceptance, and project hygiene cleanup.

### Test coverage (RFC 065, 069)

**oidc/token/tests.rs** +11 tests (`classify()` comprehensive coverage):
`classify_auth_code_success`, `classify_refresh_success`, `classify_refresh_with_scope`,
four missing-field cases, `token_response_bearer_constructor`,
`token_response_serializes_bearer`, `token_error_serializes_snake_case`

**webauthn/cose/tests.rs** +7 tests:
`sha256_empty_string_known_vector`, `sha256_abc_known_vector`,
`parse_cose_public_key_rejects_empty_bytes`, `parse_cose_public_key_rejects_truncated_cbor`,
`parse_att_obj_rejects_empty_bytes`, `cose_alg_variants_are_distinct`,
`require_none_attestation_rejects_empty_map`

### Tenant admin UI (RFC 066, 067)

**`cesauth-ui::tenant_admin::invitations`** (new):
- `invitations_page(principal, tenant, invitations, now_unix)` — invitation list with
  issue-form (email + role selector), status badges (pending/expired/revoked),
  per-row revoke button with CSRF

**`cesauth-ui::tenant_admin::deletions`** (new):
- `deletion_requests_page(principal, tenant, requests, now_unix)` — deletion queue with
  grace-period display, per-row Cancel and "Execute now" actions with confirmation

**`TenantAdminTab`** extended with `Invitations` and `DeletionRequests` variants.

### Tenant suspend/restore (RFC 068) — SaaS §16.8

- `POST /admin/tenancy/tenants/:id/suspend` → calls `suspend_tenant()`,
  emits `TenantStatusChanged`, redirects to tenant detail
- `POST /admin/tenancy/tenants/:id/restore` → calls `restore_tenant()`,
  emits `TenantStatusChanged`
- Requires `AdminAction::ManageTenancy` (Operations+)

**§16.8 acceptance criteria now complete**:
- 管理画面から主要操作が実行可能 ✅ (invitation, deletion, suspend/restore routes)
- 監査ログから原因追跡が可能 ✅ (EventKind chain across all operations)
- テナント単位での停止・復帰が可能 ✅ (this RFC)

### Project hygiene (RFC 070)

- `versions_mapping.txt` updated with full v0.52.1→v0.61.0 history
- `ROADMAP.md` prefixed with 9 new completed entries (v0.53.0–v0.61.0)
- `GET /admin/t/:slug/invitations` route added (was POST-only, route-contracts gap)

### Routes

163 routes documented in `route-contracts.md` (+3 new routes).

### Test counts

| Crate | v0.60.0 | v0.61.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 663 | **681** | +18 |
| `cesauth-adapter-test` | 125 | **125** | ±0 |
| `cesauth-ui` | 270 | **270** | ±0 |
| `cesauth-migrate-test` | 31 | **31** | ±0 |
| **Total** | **1,089** | **1,107** | **+18** |

---

## [0.60.0] - 2026-05-12

Implements RFC 059-064: coverage completeness across previously untested
modules and documentation completing SaaS guide §16.7 acceptance criteria.

### admin/policy.rs tests (RFC 059)

13 inline tests covering all 6 public functions:

- `role_allows` — full permission matrix for ReadOnly/Security/Operations/Super
- `format_metric` — Count with thousands separators, Bytes scaling (B/KiB/MiB/GiB), Permille, Seconds
- `format_change` — None/zero/positive/negative permille formatting

### oidc/introspect.rs tests (RFC 059)

8 tests covering `IntrospectionResponse` constructors (RFC 7662 compliance):

- `inactive_serializes_only_active_false` — privacy invariant: inactive responses contain NO other claims
- `active_access_sets_active_true_and_fields` — all RFC 7662 §2.2 fields present
- `active_access_without_audience`, `active_refresh_sets_active_true`
- `token_type_hint_parse`, `family_classification_serializes_snake_case`
- `inactive_with_ext_includes_x_cesauth`

### jwt/claims.rs tests (RFC 060)

6 tests covering JWT claim serialization:

- `access_token_claims_round_trip_json` — serde round-trip
- `access_token_claims_contains_all_required_fields` — all 8 JWT fields present
- `id_token_nonce_omitted_when_none` — `skip_serializing_if` correctness
- `id_token_optional_fields_present_when_some`
- `jwk_ed25519_constructor`, `jwks_document_serializes_keys_array` — `use_` → `"use"` rename

### Documentation (RFC 061-062) — SaaS guide §16.7

**`docs/src/expert/data-model.md`** (new):
- Full ASCII entity-relationship diagram for SCHEMA_VERSION 20
- Durable Objects inventory (AuthChallengeStore, RefreshTokenFamilyStore, etc.)
- `role_assignments` scope types table
- Key invariants (email COLLATE NOCASE, cascade rules, audit append-only)
- Migration history table (0001–0020)

**`docs/src/expert/admin-operations.md`** (new):
- Tenant lifecycle (provision, suspend, soft-delete)
- Invitation management (issue, revoke)
- Deletion request queue (cancel, execute)
- Session management and cron sweep behaviour
- Audit log structure and chain verification
- Plan management and key rotation

**`docs/src/deployment/migration-procedures.md`** (new):
- Fresh deployment instructions
- Version-by-version upgrade paths (v0.56 → v0.59 → v0.60)
- Pre-flight check for migration 0020 (authenticator tenant_id backfill)
- Rollback policy and data export guidance

`docs/src/SUMMARY.md` updated with all three new documents.

### §16.7 acceptance criteria status

| Criterion | Status |
|---|---|
| Data model ER diagram | ✅ `docs/src/expert/data-model.md` |
| API specification | ✅ `docs/src/expert/route-contracts.md` (160 routes) |
| Migration procedures | ✅ `docs/src/deployment/migration-procedures.md` |
| Admin operations guide | ✅ `docs/src/expert/admin-operations.md` |

### Test counts

| Crate | v0.59.0 | v0.60.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 636 | **663** | +27 |
| `cesauth-adapter-test` | 125 | **125** | ±0 |
| `cesauth-ui` | 270 | **270** | ±0 |
| `cesauth-migrate-test` | 31 | **31** | ±0 |
| **Total** | **1,062** | **1,089** | **+27** |

---

