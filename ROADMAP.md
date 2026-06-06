# Roadmap

cesauth is in active development. This file tracks what ships today,
what is planned, and what is deliberately out of scope.

Format inspired by [Keep a Changelog](https://keepachangelog.com/) and
the [Semantic Versioning](https://semver.org/) naming for priorities.

---

## Versioning policy

cesauth follows SemVer. The major number stays at `0` while the
public surface continues to evolve. Within `0.x.y`:

- **Bump the minor (`0.x → 0.x+1`) when** a release introduces a new
  HTTP route surface, a new schema migration, a new public type or
  trait in `cesauth-core`, a new permission slug, a new operator-visible
  configuration knob (`wrangler.toml` `[triggers]`, new env var),
  or a renamed/removed URL. Anything an integrator or operator could
  observe by reading the release notes and going "I need to do
  something" earns a minor bump.
- **Bump the patch (`0.x.y → 0.x.y+1`) when** the change is
  internal-only: bug fixes that preserve existing behavior, doc
  updates, dependency upgrades that don't shift any visible
  behavior, refactors. Security fixes that preserve wire compatibility
  also count as patch (the v0.15.1 RUSTSEC fix is the canonical
  example — `Cargo.toml` features narrowed, no surface change).

A few historical 0.4.x releases (notably 0.6.0 through 0.11.0 and
0.13.0-0.15.0, 0.16.0-0.17.0) by this rubric should arguably have
been minor bumps rather than patches. We accept that as historical
debt rather than rewriting bundles already shipped — those releases
are immutable artifacts. Going forward (from 0.18.0 onward) the rule
above is the policy.

A future `1.0` will be cut when the public surface settles. There
is no fixed timeline; the bar is "what shipped is what we want"
across the OIDC, tenancy, and operator surfaces.

---

## Shipped

The following subsystems are implemented end-to-end and covered by
host tests.  Each row links to the canonical CHANGELOG entry;
full narrative is in the [archive](docs/changelog-archive/README.md).

> **Full shipped narrative** for v0.31.0–v0.52.1 is in
> [`docs/changelog-archive/ROADMAP-shipped-0.31-to-0.52.md`](docs/changelog-archive/ROADMAP-shipped-0.31-to-0.52.md).

| Area | Shipped at | CHANGELOG |
|---|---|---|
| Five-crate workspace + ports/adapters | v0.1.0 | [archive](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md) |
| D1 schema, DOs, OIDC core, WebAuthn, Magic Link | v0.1.0–v0.3.0 | [archive](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md) |
| Tenancy data model + admin console | v0.6.0–v0.15.0 | [archive](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md) |
| Anonymous trial promotion (ADR-004) | v0.16.0–v0.18.0 | [archive](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md) |
| Data migration tooling (ADR-005) | v0.19.0–v0.22.0 | [archive](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md) |
| HTTP security headers (ADR-007) | v0.23.0 | [archive](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md) |
| Security track: CSRF audit + email verification | v0.24.0–v0.25.0 | [archive](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md) |
| TOTP MFA full track (ADR-009) | v0.26.0–v0.30.0 | [archive](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md) |
| UI/UX iteration: flash, Security Center, next-param | v0.31.0–v0.32.1 | [archive](docs/changelog-archive/CHANGELOG-0.31-to-0.40.md) |
| Audit log hash chain (ADR-010) | v0.32.0–v0.33.0 | [archive](docs/changelog-archive/CHANGELOG-0.31-to-0.40.md) |
| Refresh token reuse hardening (ADR-011) | v0.34.0 | [archive](docs/changelog-archive/CHANGELOG-0.31-to-0.40.md) |
| Session hardening (ADR-012) | v0.35.0 | [archive](docs/changelog-archive/CHANGELOG-0.31-to-0.40.md) |
| i18n infrastructure + migration (ADR-013) | v0.36.0–v0.39.0 | [archive](docs/changelog-archive/CHANGELOG-0.31-to-0.40.md) |
| Session-index drift detection | v0.40.0 | [archive](docs/changelog-archive/CHANGELOG-0.31-to-0.40.md) |
| Multi-key access-token introspection | v0.41.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| RFC 7009 token revocation conformance | v0.42.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| Introspection rate limit (ADR-014 §Q2) | v0.43.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| Drop `jsonwebtoken` (RUSTSEC-2023-0071) | v0.44.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| Bulk session revoke (ADR-012 §Q4) | v0.45.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| Refresh-token introspection extensions | v0.46.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| i18n-2 continuation | v0.47.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| Audit retention policy (ADR-014 §Q3) | v0.48.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| D1 session-index repair (ADR-012 §Q1.5) | v0.49.0 | [archive](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md) |
| Per-client introspection audience (ADR-014 §Q1) | v0.50.0 | [#v0500](CHANGELOG.md#0500) |
| OTP audit fix + introspect aud correctness (RFC 008/009) | v0.50.3 | [CHANGELOG](CHANGELOG.md) |
| MagicLinkMailer port + provider adapters (RFC 010) | v0.51.0 | [CHANGELOG](CHANGELOG.md) |
| WebAuthn typed errors + proptest (RFC 003/004) | v0.51.1 | [CHANGELOG](CHANGELOG.md) |
| `cargo fuzz` for JWT parser (RFC 005) | v0.51.2 | [CHANGELOG](CHANGELOG.md) |
| CSP nonces + RFC lifecycle policy (RFC 006/019) | v0.52.0 | [CHANGELOG](CHANGELOG.md) |
| Doc/repo hygiene + drift-scan (RFC 007/012) | v0.52.1 | [CHANGELOG](CHANGELOG.md) |
| OIDC `id_token` issuance, ADR-008 §Q1-Q11 (RFC 001) | v0.54.0 | [CHANGELOG](CHANGELOG.md) |
| Workers operational readiness + route contracts (RFC 013/025/027) | v0.53.0 | [CHANGELOG](CHANGELOG.md) |
| `/introspect` hot path, rustfmt removal (RFC 026/029) | v0.53.0 | [CHANGELOG](CHANGELOG.md) |
| CHANGELOG/ROADMAP volume, audit request traceability (RFC 015/028) | v0.53.0 | [CHANGELOG](CHANGELOG.md) |
| Admin scope badge, OIDC audience editor, preview-and-apply (RFC 016/017/018) | v0.53.0 | [CHANGELOG](CHANGELOG.md) |
| Admin frame design tokens + Security Center i18n closure (RFC 105/106) | v0.67.0 | [CHANGELOG](CHANGELOG.md) |
| Route-catalog correction + end-user template migration (RFC 108 partial) | v0.68.0 | [CHANGELOG](CHANGELOG.md) |
| Route-catalog completion + admin/console template migration (RFC 108 continued) | v0.69.0 | [CHANGELOG](CHANGELOG.md) |
| RFC 108 closure (tenant_admin + tenancy_console migration + drift-scan rule) | v0.70.0 | [CHANGELOG](CHANGELOG.md) |

---

## Planned (0.x)

Approximate priority order. Items near the top are closer to being
started.

> **Engineering specs**: as of v0.50.1, items in this section that
> are ready to be implemented have a corresponding RFC under
> [`rfcs/`](../rfcs/). RFCs are the implementation handover spec
> (what to build, how to test it); this ROADMAP tracks the theme;
> ADRs in `docs/src/expert/adr/` track the design decisions.

### Next minor releases

- ✅ **v0.67.0 — RFC 105 + 106 (UI/UX finishing — design tokens + Security Center i18n).**
  RFC 105: admin / tenant_admin / tenancy_console frame design-token unification —
  `DESIGN_TOKENS_FMT` is now the single source of truth; `SCOPE_TOKENS_FMT` added
  for admin-only scope colors; raw `DESIGN_TOKENS` deleted. RFC 106: Security
  Center i18n closure — 7 new MessageKey variants (EN + JA) close the JA-hardcode
  hole that v0.39.0 deferred for the TOTP enabled badge, the disable link, and
  the N=0 / N=1 / N≥2 recovery banners. Also clears 7 non-deprecated warnings
  that predated v0.66.0 (RFC 098/099 import residue + a duplicate `#[inline]`
  attribute the new Rust 1.91 compiler flagged). 1,219 tests (+15). 0 warnings.
  MessageKey catalogue: 145 → 152.

- ✅ **v0.68.0 — RFC 108 partial (route-catalog correction + end-user migration).**
  Catalog corrected: four WebAuthn paths (`PASSKEY_REGISTER_START`,
  `PASSKEY_REGISTER_FINISH`, `PASSKEY_AUTH_START`, `PASSKEY_AUTH_FINISH`)
  that never matched the worker's registered routes — silently wrong since
  v0.66.0 — now match `/webauthn/register/*` and `/webauthn/authenticate/*`.
  Added `MAGIC_LINK_VERIFY_FORM` and `TOTP_ENROLL_CONFIRM` static paths.
  End-user template migration: 15 hardcoded URLs in
  `templates/{security_center,login,totp}.rs` flow through
  `cesauth_core::routes::{me,auth}::*`. HTML-escape contract for catalog
  builder fns established (caught and fixed a regression where
  `session_revoke(id)` dropped escaping). Admin/tenant_admin/tenancy_console
  migration (~189 URLs across 44 files) + RFC 112 deferred to v0.69.0.
  1,219 tests (no change — pure refactor). 0 warnings.

- ✅ **v0.69.0 — RFC 108 catalog completion + admin/console migration.**
  Second silent v0.66.0 catalog drift caught and fixed: `tenancy_console::*`
  returned `/admin/tenancy/{slug}/...` but the worker has always registered
  `/admin/tenancy/tenants/{tid}/...`. Catalog expanded from ~57 to ~83 entries
  to cover every URL family the production templates need; every const and
  fn now mirrors a worker-registered route. Admin nav migration across all
  three frames (16 URLs). `admin/console/*` templates fully migrated (~22
  URLs across 8 files), including all parameterized routes via builder fns
  with the v0.68.0 escape contract applied. Remaining ~150 URLs in
  `tenant_admin/` and `tenancy_console/` (32 files) pushed to v0.70.0 along
  with the `scripts/drift-scan.sh` URL-hardcode rule. **RFC 112 (worker
  auth macro batch) pushed to v0.70.0** — the development environment used
  for this release cycle cannot install wasm32 or compile-verify worker
  edits; see `rfcs/proposed/112-...md` "Implementation environment". 1,219
  tests (no change — pure refactor). 0 warnings.

- ✅ **v0.70.0 — RFC 108 closure (tenant_admin + tenancy_console + drift-scan).**
  Closes the route-catalog migration begun in v0.68.0. All production
  templates in `crates/ui/src/tenant_admin/` (6 top-level + 8 forms) and
  `crates/ui/src/tenancy_console/` (5 top-level + 11 forms) now construct
  URLs via `cesauth_core::routes::*` builders — ~150 URL literals replaced
  this release; ~190 across the three-release migration. `scripts/drift-scan.sh`
  gains a per-file URL-hardcode rule that stops at `#[cfg(test)]` / `mod tests`
  markers and skips dedicated `tests.rs` files (those exist to fail on
  catalog drift). Two pre-existing orphan UIs surfaced and are intentionally
  left out of scope with module-docstring `# RFC 108 orphan UI exemption`
  notes: `tenant_admin/oidc_clients.rs` (RFC 017 wired the form but never
  the worker handler) and `tenancy_console/forms/membership_add.rs` (form
  actions POST to `.../memberships`, worker only registers `.../memberships/new`).
  **RFC 112 (worker auth macro batch) remains environment-blocked** — the
  sandbox where this release was prepared cannot install rustup / wasm32
  and so cannot verify worker edits. Pushed to v0.71.0+ contingent on
  environment. 1,219 tests (no change — pure refactor). 0 warnings.

- 📅 **v0.71.0 — RFC 109 (Audit log viewer UI surface).** New `/admin/console/audit`
  interactive viewer with actor / event / tenant / date filtering and pagination.
  Inherits filter state into existing `POST /admin/console/audit/export` (RFC 080).
  System-admin scoped, JA-only per ADR-013. Source: v0.50.1 deck page 9.
  (Originally planned for v0.69.0; pushed by the v0.68.0–v0.70.0 partial splits.)

- 📅 **v0.72.0 — RFC 110 + 113 (Acceptance alignment).** RFC 110: verify and fill
  Safety controls dashboard alignment with deck page 9 (rate-limit status,
  Turnstile, refresh reuse, TOTP key, runbook link). RFC 113: UI rendering
  acceptance harness — CI gate asserting scope badge / flash region / skip-link /
  footer version / `<html lang>` across all browser-facing routes. Source: deck
  pages 9, 12, 14.

- 📅 **v0.73.0 — RFC 107 + 111 (ADR-013 §Q4 closure).** RFC 107: plural-aware
  catalog lookup using CLDR-minimal `Plural::{One, Other}` enum (no `icu` dep —
  WASM size budget). RFC 111: confirm UTC ISO-8601 as the canonical date rendering
  policy and document per-user timezone as separate future work. Both close
  ADR-013 §Q4 ("date / plural deferred"). Source: ADR-013 §Q4 + deck page 12.

- ✅ **v0.66.0 — RFC 096-103 (codebase audit remediation).**
  Zero non-deprecated warnings. Shared util.rs (5 constant_time_eq → 1, 3 ISO-8601 → 1).
  timing.rs (7 TTL constants). routes.rs (165 paths). i18n/mod.rs split (lookup 684 lines → 8 groups).
  templates/ split (1537 lines → 4 files). admin/service/ split. Auth boilerplate macros.
  1,204 tests (+12 util).

- ✅ **v0.65.0 — RFC 092-095 (SaaS acceptance criteria + docs).** ER diagram,
  acceptance report, feature flag verification. 1,192 tests.

- ✅ **v0.64.0 — RFC 085–091 (Core test coverage).** JWT signer 10 tests,
  authz/service 14 tests, i18n inline 6 tests, admin/service 6 tests. Cron pass KV
  record writing (RFC 090). Total: 1,192 tests (+36).

- ✅ **v0.63.0 — RFC 079–084 (P2 operations UX + UI consistency).**
  RFC 079: Magic Link not-configured notice (operator boundary). RFC 080: audit log
  filtered export CSV/JSONL with AuditExported event. RFC 081: cron pass status
  surface (/admin/console/operations, KV-backed). RFC 082: design token unification
  (--success/--warning/--danger aliases). RFC 083: rollback hint (already existed).
  RFC 084: sessions drift note. 1,156 tests. Routes: 165.

- ✅ **v0.66.0 — RFC 096-103 (codebase audit remediation).**
  Zero non-deprecated warnings. Shared util.rs (5 constant_time_eq → 1, 3 ISO-8601 → 1).
  timing.rs (7 TTL constants). routes.rs (165 paths). i18n/mod.rs split (lookup 684 lines → 8 groups).
  templates/ split (1537 lines → 4 files). admin/service/ split. Auth boilerplate macros.
  1,204 tests (+12 util).

- ✅ **v0.65.0 — RFC 092-095 (SaaS acceptance criteria + docs).** ER diagram,
  acceptance report, feature flag verification. 1,192 tests.

- ✅ **v0.64.0 — RFC 085–091 (Core test coverage).** JWT signer 10 tests,
  authz/service 14 tests, i18n inline 6 tests, admin/service 6 tests. Cron pass KV
  record writing (RFC 090). Total: 1,192 tests (+36).

- ✅ **v0.63.0 — RFC 079–084 (P2 operations UX + UI consistency).**
  Magic Link not-configured notice, audit log export CSV/JSONL, cron pass status surface,
  design token unification, sessions drift note. 1,156 tests. Routes: 165.

- ✅ **v0.62.0 — RFC 071–078 (UI/UX alignment from design specification).**
  P0: footer version hygiene, html lang locale binding, scope badge CSS, generic auth
  failure audit + MagicLinkMismatch→400 fix. P1: Security Center mobile summary card
  (8 MessageKey, WCAG 1.4.1), recovery code save-confirmation gate (CSRF form, server
  validation), skip-to-content link (WCAG 2.4.1 all frames), tenant admin UI full i18n
  (35 MessageKey, JA-only rendering tests). 1,138 tests. MessageKey catalog: 145.

- ✅ **v0.61.0 — RFC 059–070 (test coverage completion + §16.7/§16.8 docs + UI pages).**
  RFC 059: admin/policy.rs (13 tests) + oidc/introspect.rs (8 tests).
  RFC 060: jwt/claims.rs (6 tests). RFC 065: oidc/token.rs (13 tests).
  RFC 069: webauthn/cose.rs (7 tests). RFC 061-062: data-model.md,
  admin-operations.md, migration-procedures.md (§16.7 complete).
  RFC 066-067: tenant admin UI — invitation page + deletion requests page.
  RFC 068: POST /admin/tenancy/tenants/:id/suspend and /restore (§16.8).
  RFC 070: versions_mapping.txt update. Total: **1,100+ tests**.

- ✅ **v0.60.0 — RFC 059-064 (coverage + SaaS §16.7 documentation).**
  admin/policy.rs tests (13), oidc/introspect.rs tests (8), jwt/claims.rs
  tests (6). data-model.md ER diagram, admin-operations.md, migration-
  procedures.md. SUMMARY.md updated. 1,089 tests.

- ✅ **v0.59.0 — RFC 054-058 (OIDC/PKCE, tenancy tests, soft-delete, TOTP, E2E).**
  PKCE tests (+9), authorization tests (+4), tenancy/service.rs tests (12),
  soft-delete service (soft_delete_tenant/org/group + suspend/restore), TOTP
  storage.rs tests (6), E2E onboarding scenarios (5 — §16.2/16.4/16.6). 1,062 tests.

- ✅ **v0.58.0 — RFC 049-053 (accept-invite, SQL validation, tenant_id, authz, sessions).**
  /accept-invite full CloudflareInvitationRepository implementation. migrate-test
  SQL queries validated (8 tests). authenticators.tenant_id added (migration 0020,
  SCHEMA_VERSION 20). authz hardening (8 security tests). SessionCreated/Revoked/
  Expired/MfaVerified EventKind. 1,023 tests.

- ✅ **v0.57.0 — RFC 045-048 (audit events, worker layers, D1 adapters, billing).**
  6 new EventKind (Invitation×3 + Deletion×3). Invitation + deletion worker routes.
  CloudflareInvitationRepository + CloudflareDeletionRequestRepository D1 adapters.
  InMemory adapters. sweep_pending_deletions cron. billing change_plan / is_feature_
  enabled / check_quota (9 tests). 1,005 tests.

- ✅ **v0.56.0 — RFC 040-044 (OIDC userinfo, token refactor, invitations, deletions).**
  GET/POST /userinfo endpoint (10 tests). TokenDeps + TokenConfig refactor.
  Preview-and-apply LOG_LEVEL adoption. invitation_tokens table (migration 0018,
  11 tests). deletion_requests table (migration 0019, 8 tests). CoreError::Conflict.
  996 tests, SCHEMA_VERSION 19.

- ✅ **v0.55.0 — RFC 030-039 (P0/P1 review fixes: security, CSP nonces, id_token nonce,
  mailer security, /userinfo discovery, CI hardening).**
  Category::Magic, MagicLinkMailer dyn-free, id_token nonce, auth_time in
  FamilyState, /introspect tenant boundary, request_id audit chain,
  docs cleanup, CI test/clippy/wasm/deny gates. 963 tests.

- ✅ **v0.54.0 — RFC 001 + RFC 013/025/027 + RFC 020-029 (SaaS multi-tenancy core).**
  id_token issuance (OIDC Core §3.1.2.2). schema_meta, 0004 FK repair, COLLATE
  NOCASE fix. Permission catalog sync. ON DELETE CASCADE. Tenant boundary integrity.
  migration 0001-0017. WebAuthn tenant isolation. Batch authz. Admin console
  preview-and-apply. TOTP unconfirmed sweep. Introspect rate limit. 958 tests.

- ✅ **v0.53.0 — RFC 014-018 (audit hash chain, id_token ADR, RFC 018 preview infra).**
  Audit hash chain (DO-serialized). id_token design (ADR-008). Preview-and-apply
  infrastructure (mint_preview_token / verify_preview_token). 888 tests.

- ✅ **v0.52.1 — RFC 012 + RFC 007 (doc/repo hygiene + attack surface review cadence).**
  Patch release. README and intro.md factual errors corrected (admin console
  existence, audit→D1 not R2). `migrate.rs` 2568-line monolith split into
  7 focused submodules (facade re-exports unchanged public API; all 29 tests
  pass). `scripts/drift-scan.sh` + `.github/workflows/drift-scan.yml` added
  for stale-phrase detection on every PR. `wrangler.toml` RATE_LIMIT=DO
  comment added. RFC 007 process doc at
  `docs/src/expert/attack-surface-review-cadence.md`. Both RFCs moved to
  `rfcs/done/`. 888 tests pass.

- ✅ **v0.52.0 — RFC 006 + RFC 019 (CSP nonces + RFC lifecycle policy).**
  Minor bump because RFC 006 changes the observable CSP header for all HTML
  responses. `CspNonce` type + `build_csp_with_nonce` in cesauth-core.
  `set_render_nonce` / `render_nonce` thread-local in cesauth-ui (no public
  API change). Per-request nonce injected into all inline `<style>` and
  `<script defer>` tags via 5 frame functions. Worker HTML handlers generate
  nonce and call `set_render_nonce` before rendering. Per-route CSP strings:
  `'unsafe-inline'` → `'nonce-{n}'`. 15 core + 5 UI nonce tests. 859 tests
  pass. RFC 019: `rfcs/` 4-folder lifecycle structure (proposed/ / done/ /
  archive/), written policy in done/019-rfc-lifecycle-policy.md.

- ✅ **v0.51.2 — RFC 005 (`cargo fuzz` for JWT parser).**
  Patch release. `fuzz/` crate (NOT workspace member) + one fuzz target
  (`jwt_parse`) exercising `verify` and `verify_for_introspect` under
  libFuzzer. 10-file seed corpus. GH Actions one-shot job (60 s) on PRs
  touching JWT or fuzz code. `.gitignore` and workspace comment updated.
  Zero production code change.

- ✅ **v0.51.1 — RFC 004 + RFC 003 (WebAuthn typed errors + proptest).**
  Patch release. Additive wire change (`kind` field on WebAuthn errors)
  + dev-dep addition only.

  **RFC 004**: `cesauth_core::webauthn::error` — `WebAuthnErrorKind` enum
  with six variants and `classify(detail) -> WebAuthnErrorKind`. Worker
  `oauth_error_response` surfaces `kind` in the JSON body for WebAuthn
  failures only; diagnostic detail stays server-side (audit + logs).
  10 unit tests + 3 worker error-shape pins.
  **RFC 003**: `proptest = "1"` as workspace dev-dep. Two new property-based
  test modules: `jwt/proptests.rs` (5 properties — sign/verify round-trip,
  single-byte tamper, wrong-key rejection, magic-link round-trip, tamper
  rejection) and `oidc/authorization/redirect_uri_proptests.rs` (7 properties
  — exact-match, no-trailing-slash, no-suffix, port-explicit-vs-default,
  http-vs-https, case-sensitive). 481 core tests pass (was 459).

- ✅ **v0.51.0 — RFC 010 + RFC 002 (MagicLinkMailer port + schema drift fix).**
  Minor bump because RFC 010 introduces operator-visible configuration knobs
  (three optional env vars for the HTTPS provider adapter).

  **RFC 010**: `MagicLinkMailer` trait (`cesauth-core::magic_link::mailer`)
  with `MagicLinkPayload`, `MagicLinkReason`, `DeliveryReceipt`, `MailerError`.
  Four reference adapters in `cesauth-adapter-cloudflare::mailer`:
  `DevConsoleMailer` (local dev only, never logs OTP), `UnconfiguredMailer`
  (default fallback, audits misconfig), `ServiceBindingMailer` (CF service
  binding to operator mail worker — preferred), `HttpsProviderMailer`
  (SendGrid v3-compatible POST). Worker factory `crate::adapter::mailer::from_env`
  selects the adapter from env. Both Magic Link issuance routes
  (`routes::magic_link::request`, `routes::api_v1::anonymous` promote path)
  now call the mailer port instead of writing to the audit log. Two new audit
  kinds: `MagicLinkDelivered`, `MagicLinkDeliveryFailed` (keyed on `kind`
  field: `transient` / `permanent` / `not_configured`). ADR-015 Accepted.
  New operator chapter `docs/src/deployment/email-delivery.md`.
  **RFC 002**: `migrations/0001_initial.sql` column comment corrected from
  `argon2id(secret)` to `sha256_hex(secret)`. `service::client_auth` module
  doc updated with RFC 002 resolution rationale. 820 tests pass (was 817).
  No schema migration; new env vars are all optional; existing behavior
  unchanged for deployments that don't configure a provider.

- ✅ **v0.50.3 — RFC 008 + RFC 009 + RFC 011 (security hardening patch).**
  Ships the Tier-0 production-blocker and Tier-1 hardening items from the
  external codebase review that do not require new operator-visible
  configuration knobs.

  **RFC 008 (P0)**: OTP plaintext removed from audit log on every Magic
  Link issuance. `code_plaintext` renamed to `delivery_payload`. Static-
  grep pin test prevents reintroduction. Operator runbook for purging
  already-persisted rows and re-baselining the hash chain added to
  `docs/src/deployment/runbook.md`. **RFC 009 (P0)**: `introspect_token`
  no longer takes `expected_aud` — access tokens carry `aud = client.id`
  not `aud = issuer`; the pre-v0.50.3 verifier rejected every valid
  production access token. New `verify_for_introspect()` in jwt/signer
  is the introspect-only relaxed path. Audience-gate client lookup is now
  fail-closed: `Ok(None)` → HTTP 401 + `IntrospectionRowMissing` audit
  event; `Err(_)` → HTTP 503. Test fixture corrected to `AUD = "client_X"`.
  Three regression tests added. **RFC 011 (P1)**: `csrf::mint()` → `Result`,
  fail HTTP 500 on CSPRNG failure; `var_u32_bounded` helper rejects negative
  rate-limit env values (previously silently disabled limits via `as u32`
  wrap); duplicate session-route block removed from `lib.rs`;
  `no_duplicate_route_registrations` test added; `012-session-hardening.md`
  marked Superseded. 817 tests pass (was 814). No schema/wire/DO changes;
  `/introspect` behavior change: now returns correct `active: true` for
  valid access tokens.

- **v0.50.2 production-blocker sweep — external review remediation.**
  An external Rust + Cloudflare codebase review of v0.50.1
  surfaced three production blockers, three security
  hardening items, and four quality-and-operations items.
  Independently verified against the source tree. Triaged
  into RFCs 008-014 in [`rfcs/`](../rfcs/) for handover to
  implementer.

  **Production blockers (Tier 0, ship in v0.50.2)**:

  - ✅ **RFC 008 — Eliminate plaintext OTP in audit log
    [P0]** — shipped in v0.50.3. `worker/src/routes/magic_link/request.rs:170-178`
    and `worker/src/routes/api_v1/anonymous.rs:254-264`
    write the Magic Link OTP plaintext into
    `EventKind::MagicLinkIssued` audit `reason` on every
    issuance, violating the project's own self-declared
    "No token material ever" invariant from
    `worker/src/audit.rs`. Anyone with audit-read access
    (operator D1 read role, Logpush forwarder, SIEM
    operator, anyone running `cesauth-migrate export`,
    backup restorer) can log in as any user who used Magic
    Link or anonymous-promote during the retention
    window. Fix: drop `code_plaintext` from both audit
    sites; add static-grep pin test to prevent
    reintroduction; rename `code_plaintext` →
    `delivery_payload` to signal intent; ship operator
    runbook for purging already-leaked rows + chain
    re-baseline. RFC 008 details all 6 implementation
    steps.

  - ✅ **RFC 009 — Introspection access-token `aud`
    correctness + audience-gate fail-closed [P0 + P1]** — shipped in v0.50.3.
    Tokens minted with `aud = client.id`
    (`core/src/service/token.rs:115,277`); verifier uses
    `expected_aud = issuer`
    (`worker/src/routes/oidc/introspect.rs:202-208`).
    **Tests pass because fixture sets `ISS == AUD` (line
    78-79 of `service/introspect/tests.rs`)**, masking
    the production bug. Result: `/introspect` returns
    `{"active":false}` for every valid access token in
    production. ADR-014 §Q1's audience gate
    consequently never fires (it gates on active
    responses that never come back). Companion P1: the
    audience-gate's client lookup
    (`introspect.rs:97-117`) silently fails open on D1
    storage error, defeating the security boundary
    operators opted into. Fix: remove `expected_aud`
    from `introspect_token` (audience gate becomes
    canonical aud check); update test fixture to
    `AUD = "client_X"`; harden gate to fail-closed (HTTP
    503 on storage error, HTTP 401 on row missing with
    new audit kind `IntrospectionRowMissing`); amend
    ADR-014 §Q1 with v0.50.2 tightening note. RFC 009
    details all 9 implementation steps.

  - ✅ **RFC 010 — Magic Link real delivery (mailer port +
    provider adapters) [P0]** — shipped in v0.51.0. The development
    directive declares a `MagicLinkMailer` trait that
    operators implement; **workspace-wide grep returns
    zero hits** — no such trait exists. The audit log
    IS the OTP delivery mechanism in cesauth today
    (which is why RFC 008's plaintext-leak exists at
    all). Without a real mailer contract, RFC 008's fix
    will not stay fixed: the next operator under
    deadline pressure reintroduces the audit-as-delivery
    hack. Fix: build the trait the directive claims
    exists (`MagicLinkMailer` in `cesauth-core` with
    audit-disjoint crate boundary); ship 4 reference
    adapters (Cloudflare service binding, HTTPS
    provider, dev console with `WRANGLER_LOCAL=1` gate,
    `UnconfiguredMailer` fallback that surfaces misconfig
    via audit); new audit kinds `MagicLinkDelivered` /
    `MagicLinkDeliveryFailed`; new operator chapter
    `docs/src/deployment/email-delivery.md`; ADR-015
    drafted alongside graduating to Accepted on ship.
    RFC 010 details all 6 implementation PRs.

  - ✅ **RFC 011 — Worker-layer hardening [P1 + P2]** — shipped in v0.50.3. Bundle
    of four mechanical fixes:
    (1) `csrf::mint()` swallows `getrandom` error with
    `let _ =` — RNG failure produces a constant predictable
    token. Fix: `Result`-ize, audit `CsrfRngFailure`
    kind, fail HTTP 500.
    (2) `var_parsed_default(...)? as u32` in `config.rs:126,134`
    silently wraps negative values to huge u32, disabling
    rate limits. Fix: `var_parsed_u32_bounded` with
    explicit non-negative + sane upper bound check.
    (3) `worker/src/lib.rs:161-168` and `:193-200`
    register the same three `/me/security/sessions` routes
    twice (merge-conflict residue from v0.35.0). Fix:
    delete second block; uniqueness pin test.
    (4) `docs/src/expert/adr/012-session-hardening.md`
    (older draft) and `012-sessions.md` (canonical) both
    exist. Fix: header `012-session-hardening.md` as
    Superseded. May ride along v0.50.2 or land in
    v0.50.3 depending on PR review bandwidth.

  **Quality / scaling work (Tier 3, defer behind v0.50.2)**:

  - **RFC 012 — Doc and repo hygiene**. README claims
    "No management GUI" (false — admin console since
    v0.3.0) and "land in R2" (false — R2 audit removed
    v0.32.0); `crates/core/src/migrate.rs` is 2568
    lines (development directive's 800-line cap);
    development directive itself describes rate-limit as
    KV (actually DO); inline comments reference removed
    R2 audit subsystem. Fix: README rewrite, mechanical
    `migrate.rs` split into 9 submodules under 500 lines
    each, dev directive corrections + move into
    `docs/src/expert/development.md`, drift-scan CI
    workflow with stale-phrase pattern list.

  - **RFC 013 — Operational envelope**. Cesauth has
    implicit Cloudflare plan assumptions never
    documented: cron passes walk 1000 rows × DO call
    each (Free plan subrequest cliff at 50);
    `/introspect` hot path issues multiple D1 reads +
    DO calls (Free plan D1 query cliff at 50);
    monolithic worker bundle never measured against
    Free 3 MB / Paid 10 MB ceiling; `nodejs_compat`
    enabled despite no Node API runtime use. Fix:
    ADR-016 declares Paid plan as floor; bundle-size CI
    gate at 7 MB gzipped (70% of Paid ceiling);
    configurable cron batch sizes for each pass;
    `nodejs_compat` removal or in-tree justification;
    new `docs/src/deployment/operational-envelope.md`
    chapter with per-request budget tables; new
    `docs/src/deployment/bundle-history.md` trend
    record.

  - **RFC 014 — Audit append performance**. D1
    contention concern under high-rate audit events
    (`/introspect`-heavy deployments). Path A
    (acceptance + telemetry): instrument
    `audit::append` with latency / retry warnings,
    document ~100/s sustained ceiling, ship operator
    runbook. Path B (DO-serialized append, ADR-017):
    deferred until Path A telemetry triggers — single
    new DO class + adapter + migration; chain integrity
    preserved.

  - **RFC 015 — Request traceability**. Operator
    follow-up question on logging completeness: log
    framework is well-designed (categorized,
    level-gated, sensitivity-gated) but no
    correlation across log lines from the same
    request, no cross-link between log and audit, no
    consistent HTTP request lifecycle log. Adds:
    `cf-ray`-derived `request_id` threaded through
    `LogConfig` and `NewAuditEvent`; one HTTP
    lifecycle log per request as middleware
    (replaces ad-hoc per-handler `Category::Http`
    emissions, net log volume same or fewer); new
    nullable `audit_events.request_id` column
    (SCHEMA_VERSION 10 → 11; non-chained, additive).
    **Deliberately documents the absence of a
    file-writing logger** as ADR-018: Cloudflare
    Workers has no filesystem; persisting per-line
    to KV/R2/D1 contradicts the security posture and
    duplicates audit/log governance — operator
    question on this is answered by ADR-018, not by
    implementation. Coordinates with RFC 013
    (operational envelope) since both touch
    observability.

  **Tier 4 — Admin UX hardening (defer behind P0
  sweep + Tier 3)**: a third source — an external
  UI/UX design update reviewing v0.50.1 — surfaced
  three admin-surface gaps not covered by the
  external code review or operator logging
  follow-up. Triaged into RFCs 016-018:

  - **RFC 016 — Admin scope badge standardization**.
    Currently the three admin frames
    (`/admin/console/*` system, `/admin/tenancy/*`
    tenancy, `/admin/t/<slug>/*` tenant) have
    visually distinct chrome but no semantic "you
    are operating in scope X" badge consistent
    across all three. Adds `ScopeBadge` enum
    (System/Tenancy/Tenant(slug)) + 3 colour tokens
    (purple/blue/green, deliberately distinct from
    semantic success/warning/danger/info) + 3
    MessageKey variants. Single-place chrome change
    that lets operator + screenshot-reviewer read
    scope as a first-class element rather than
    incidental styling.

  - **RFC 017 — OIDC client audience-scoping admin
    editor**. v0.50.0 shipped the audience-scoping
    schema + gate but explicitly deferred the
    admin UI ("Admin console UI for this is out
    of v0.50.0 scope"). Operators currently must
    run `wrangler d1 execute "UPDATE oidc_clients
    SET audience = ? WHERE id = ?"` against
    production. RFC 017 adds the tenant admin
    editor surface with explicit 3-state form
    (Unscoped/Scoped+empty/Scoped+value)
    distinguishing NULL vs `""` vs `"value"`
    semantics, per-tenant uniqueness check with
    `?force=1` override, new audit kind
    `OidcClientAudienceChanged` with before/after
    payload, audit-trail section showing recent
    changes for the client.

  - **RFC 018 — Preview-and-apply pattern for
    destructive admin operations**. The deck's
    "状態 → 影響 → 実行 → 監査" framing; current
    admin console largely lacks the explicit
    impact step (config_edit, token rotation, etc.
    apply directly on submit). Establishes
    reusable infrastructure (`ImpactStatement`,
    HMAC-signed `PreviewToken` with 5-min TTL,
    paired `OperationPreviewed`/
    `OperationApplied` audit events). First
    adopters: LOG_LEVEL change, token rotation,
    audience editor (RFC 017 ideally rides on
    this). ADR-019 establishes the convention.

  All three Tier 4 RFCs ship after Tiers 0-3
  (production blockers + worker hardening +
  quality + operations). Recommended placement:
  v0.52.x or 0.53.0 in the order RFC 016 (chrome,
  ships anywhere) → RFC 018 (pattern infra) → RFC
  017 (rides on the pattern).

- **Security track — phased rollout.** Eleven releases of focused
  security work, ordered by impact-vs-effort. Each is small
  enough to ship cleanly without overlap. Originally framed as
  eight phases; v0.27.0 split into 2a (storage) + 2b (routes)
  mid-implementation, then v0.28.0 split again into 2b
  (presentation) + 2c (routes) + 2d (polish) — adding three
  phases total. Each split keeps releases review-able rather
  than shipping a giant change-set.

  - **0.24.0** ✅ — `SECURITY.md` improvements (severity table,
    known-limitations subsection, see-also cross-links;
    pre-existing policy was already comprehensive) + CSRF
    audit deliverable (`docs/src/expert/csrf-audit.md`,
    per-route inventory with mechanism per route, test
    coverage, re-audit cadence) + CSRF gap fill on
    `/magic-link/verify` (token check, JSON-path exempt) +
    dependency-scan automation review (verified the existing
    `.github/workflows/audit.yml` is comprehensive, documented
    the alert path in `docs/src/expert/security.md`'s new
    "Dependency vulnerability scanning" section). 6 new tests
    pinning the CSRF field contract on `VerifyBody` and
    `RequestBody`. Total 413 passing.
  - **0.25.0** ✅ — Email verification flow audit + gap fill +
    OIDC discovery doc honest reset. Audit deliverable
    (`docs/src/expert/email-verification-audit.md`) documents the
    9-row per-path table, the meaning of `email_verified=true`,
    and the discovered OIDC `id_token` issuance gap. **Concern 2
    fix**: returning-user Magic Link verify now flips
    `email_verified=true` when previously false (best-effort
    UPDATE; skip-write optimization for already-verified rows).
    **Discovery doc honest reset**: `id_token_signing_alg_values_supported`
    and `subject_types_supported` fields removed from wire output,
    `openid` removed from `scopes_supported` (now
    `["profile", "email", "offline_access"]`). Discovery is now
    RFC 8414 (OAuth 2.0 metadata), not OIDC Discovery 1.0 —
    accurate to what the implementation actually delivers.
    **`magic_link_sent_page()` UX bug fix** (folded in from
    v0.24.0 audit): template now takes `handle` and `csrf_token`
    parameters, both rendered as escaped hidden inputs; both
    callers in `/magic-link/request` (rate-limited path with
    placeholder UUID handle, happy path with real handle)
    updated. **ADR-008 drafted**: `id_token` issuance design,
    queued for implementation when scheduling permits (currently
    deferred behind TOTP track per security-track sequencing —
    see below). 14 new tests (8 discovery shape, 6 templates).
    Total 451 passing.
  - **0.26.0** ✅ — TOTP Phase 1: ADR-009 Draft + schema
    migration 0007 + `cesauth_core::totp` library skeleton
    (RFC 6238 generator and verifier with skew tolerance,
    recovery code generator, AES-GCM encryption helpers).
    SCHEMA_VERSION bumped 6 → 7. No HTTP routes, no
    enrollment UI, no verify wire-up — those are Phase 2.
    51 new tests including 5 RFC 6238 reference vectors.
    Total **502 passing**.
  - **0.27.0** ✅ — TOTP Phase 2a: storage layer.
    `cesauth_core::totp::storage` port traits, in-memory
    adapters, D1 adapters, `Challenge::PendingTotp` variant,
    `TOTP_ENCRYPTION_KEY`/`TOTP_ENCRYPTION_KEY_ID` env-var
    parsing in worker config. The original v0.27.0 plan
    bundled storage + routes; mid-implementation the
    storage layer alone proved review-able as its own
    release. 24 new tests. Total **526 passing**.
  - **0.28.0** ✅ — TOTP Phase 2b: presentation layer.
    Three new `cesauth_ui::templates` (enroll page,
    recovery-codes page, verify page) with 18 tests pinning
    CSRF inclusion / escape behavior / `<details>` placement
    of the recovery alternative form / no-email-leak from
    the verify page. New `cesauth_core::totp::qr` module
    with `otpauth_to_svg` using `qrcode` 0.14 at EcLevel::M,
    240 px, deterministic black-on-white. New
    `cesauth_worker::routes::me::auth::resolve_or_redirect`
    centralizing the cookie → session → 302-to-/login
    pipeline for `/me/*` routes. Workspace dep added:
    `qrcode = 0.14`. The original v0.28.0 plan bundled
    presentation + routes; mid-implementation the
    presentation layer alone proved review-able. 25 new
    tests. Total **551 passing**.
  - **0.29.0** ✅ — TOTP Phase 2c: HTTP routes + verify gate.
    Five new routes wired in `worker::lib::main`: `GET` and
    `POST` enroll, `GET` and `POST` verify, `POST` recover.
    Verify gate insertion in `post_auth::complete_auth` —
    for `AuthMethod::MagicLink` after step 1 (AR taken),
    checks `find_active_for_user`, on Some carries AR
    fields inline into `Challenge::PendingTotp` (no chained
    handle) and 302s to verify page. WebAuthn paths bypass.
    `complete_auth_post_gate` extracted from the original
    `complete_auth` body so both no-gate and post-verify
    paths share the same session-start/AuthCode-mint logic.
    Two new short-lived cookies introduced: `__Host-cesauth_totp`
    (5 min, SameSite=Strict, gate handle) and
    `__Host-cesauth_totp_enroll` (15 min, SameSite=Strict,
    enrollment row id). 12 new cookie-shape tests pinning
    Max-Age preservation, prefix integrity, TTL bounds, and
    distinct-cookie-name property. ~800 lines of route
    handlers covering enroll / verify / recover. 12 new
    tests. Total **563 passing**.
  - **0.30.0** ✅ — TOTP Phase 2d: polish + ADR Accepted.
    Disable flow (`GET/POST /me/security/totp/disable`) with
    minimal single-page confirmation. Cron sweep extension —
    drops `confirmed_at IS NULL AND created_at < now - 24h`
    rows after the existing anonymous-trial sweep on the same
    cron tick. `RedactionProfile.drop_tables` field; both
    built-in profiles (`prod-to-staging`, `prod-to-dev`) drop
    both TOTP tables (ADR-009 §Q5/§Q11). New
    `TotpAuthenticatorRepository::delete_all_for_user` trait
    method + adapters. New chapter
    `docs/src/deployment/totp.md` (~270 lines) covering
    encryption key provisioning, key rotation procedure with
    explicit caveat that dual-key resolution is not yet
    implemented (workaround: re-enroll users), admin reset
    path for lockout recovery, cron sweep semantics,
    operational invariants, diagnostic queries. Pre-prod
    release gate updated. **ADR-009 graduates `Draft` →
    `Accepted`** — design validated end-to-end across 5
    releases. 10 new tests (3 redaction + 5 disable template
    + 2 adapter delete_all_for_user). Disable flow is
    intentionally minimal — single-page confirm, silent
    redirect, no flash messages. The UX work (flash
    infrastructure, `/me/security` index, error-slot in
    enroll template, CSS for warning/danger states, handler
    integration tests) consolidates in the next release per
    the user-stated project value. **TOTP track
    feature-complete for the 0.x series.** Total **573
    passing**.

  After this track completes (now 11 phases instead of the
  original 8 — the v0.27.0 split added one and the v0.28.0
  split added two more), the schedule reverts to the
  feature track AFTER one UI/UX-focused release per the
  user-stated project value:

- **UI/UX iteration release.**
  - **0.31.0** ✅ — UI/UX improvements at TOTP-track-completion
    boundary, per user-stated project value "重要な予定が完了
    したタイミングで、UI/UX 改善に取り組みます". Shipped:
    P0-A `/me/security` Security Center index page (primary
    auth method label, TOTP enabled/disabled badge, recovery
    code remaining count with 4-tier rendering N=10/2-9/1/0,
    conditional enroll/disable link, anonymous-suppression
    variant); P0-B flash-message infrastructure
    (`__Host-cesauth_flash` cookie with HMAC + closed token
    table, `flash_block` template, all 4 success/info/warning
    paths wired: TOTP enabled/disabled/recovered + logged-out);
    P0-C `error: Option<&str>` slot on `totp_enroll_page` with
    autofocus on the code input; P0-D 8 design tokens
    (`--success`, `--success-bg`, `--warning`, `--warning-bg`,
    `--danger`, `--danger-bg`, `--info`, `--info-bg`) + dark-mode
    `@media` overrides + `.flash--*` and `.badge--*` modifier
    classes + `button.danger` / `button.warning` rules +
    `.visually-hidden` utility (this fixed a latent bug — the
    class was already referenced but the rule was missing);
    P1-A `validate_next_path` allowlist (`/me/*` + `/`)
    + `__Host-cesauth_login_next` cookie + threading through
    `complete_auth` → `complete_auth_post_gate`; new
    `docs/src/expert/cookies.md` (privacy notice covering all
    7 cookies, EDPB Guidelines 5/2020 rationale for "strictly
    necessary"). 614 → ~680 tests. Plan v2 §6.4 split policy
    invoked: P1-B (TOTP handler integration tests) deferred to
    v0.31.1 — see entry below. The pure-helper extracts
    (`attempts_exhausted`, `DISABLE_SUCCESS_REDIRECT`) shipped
    here as honest minimum coverage at this layer.

  - **0.31.1** ✅ shipped as **v0.32.1** — TOTP handler
    integration tests (P1-B split from v0.31.0) landed via
    Approach 2 (decision-extraction refactor) on top of the
    v0.32.0 audit-log hash-chain release rather than as a
    separate v0.31.x branch. Six handlers were refactored into
    pure-ish `decide_*` functions plus thin Env-touching
    wrappers: `disable::post_handler`, `recover::post_handler`,
    `verify::get_handler`, `verify::post_handler`,
    `enroll::get_handler`, `enroll::post_confirm_handler`.
    Each `decide_X` takes trait-bounded `&impl AuthChallengeStore`
    / `&impl TotpAuthenticatorRepository` /
    `&impl TotpRecoveryCodeRepository` references, returns an
    enum capturing the decision outcome plus any data the
    handler needs to build the response. Tests construct
    in-memory adapters from `cesauth-adapter-test` and exercise
    the full branch table per handler (3-10 tests each, 40
    total). Production wiring unchanged — handler signatures
    are signature-compatible. `unimplemented!()` stub repos
    used to pin port-surface regressions: a passing test
    confirms the decision didn't widen its port contract.
    Released as v0.32.1 because the user explicitly authorized
    "(α) v0.32.0 の上に v0.32.1 として出す" during the
    planning conversation; CHANGELOG entry frames it as
    "deferred from v0.31.0, landing on v0.32.x line". 717 →
    757 tests (+40).

- **Audit log integrity track.**
  - **0.32.0** ✅ — Audit log hash chain Phase 1 (ADR-010 Draft).
    Audit events moved from R2 NDJSON objects to a D1 table
    `audit_events` with SHA-256 hash chain over rows; case C
    (D1 source-of-truth) chosen during planning over case B
    (R2 + parallel D1 chain ledger) because the two-store
    design would have forked the chain under concurrency,
    permanently exposed cross-store consistency hazards, and
    forced N+1 reads on every verifier and admin search. R2
    `AUDIT` binding removed entirely from `wrangler.toml`; no
    backward-compat code left in the repo. New schema
    migration `0008_audit_chain.sql` introduces the table,
    three indexes (`(ts)`, `(kind, ts)`, partial
    `(subject) WHERE NOT NULL`), and a genesis row at `seq=1`.
    `cesauth_core::audit::chain` provides pure hash
    calculation; `cesauth_core::ports::audit::AuditEventRepository`
    is the trait; in-memory adapter and D1 adapter implement
    it. Worker `audit::write` rewritten internally (signature
    unchanged, all 90 call sites work). Admin search rewritten
    to D1 SELECT; `r2_metrics` removed in favor of
    `row_count.audit_events`. `/__dev/audit` rewritten.
    Documentation: ADR-010 Draft, new operator chapter
    `audit-log-hash-chain.md`, R2 audit references purged
    across deployment docs. Project-status framing softened
    across all docs (removed "pre-1.0" / "production-ready"
    claims) per user instruction during planning. 678 → 717
    tests (+39: 25 chain-hash tests in core, 14 in-memory
    repository tests in adapter-test). No verification cron
    yet — that is Phase 2.
  - **0.33.0** ✅ — Audit log hash chain Phase 2 shipped
    (ADR-010 Draft → **Accepted**). Daily cron at 04:00 UTC
    (piggybacked on the existing sweep schedule) walks the
    chain incrementally, resuming from the last checkpoint
    via the new `AuditEventRepository::fetch_after_seq`
    method (page size = 200) and verifying every link's
    payload_hash, chain_hash, and previous_hash linkage.
    New port `AuditChainCheckpointStore` with two records:
    `AuditChainCheckpoint` (resume + cross-check) and
    `AuditVerificationResult` (admin UI surface). KV adapter
    in `cesauth-adapter-cloudflare` stores them under the
    reserved `chain:` prefix in the existing `CACHE`
    namespace — no new wrangler binding, no schema migration.
    The dual-store design is the wholesale-rewrite defense:
    an attacker who compromises D1 still has to compromise
    KV synchronously to evade detection. Pure-ish verifier
    in core (`cesauth_core::audit::verifier::verify_chain`
    incremental + `verify_chain_full` operator-triggered);
    same Approach 2 pattern as v0.32.1 TOTP handlers
    (port-bound IO in scope, Env touching not). Admin UI at
    `/admin/console/audit/chain` renders status badge +
    checkpoint metadata + CSRF-guarded "verify now" button;
    cross-linked from the existing audit search page;
    six rendering tests pin status / tamper / wholesale-
    rewrite / growth-since-checkpoint / CSRF wiring. Tamper
    detection persists the failing result to KV (admin UI
    surfaces the alarm), logs at `console_error!` level, and
    does NOT advance the checkpoint — investigation gate
    before the chain advances past suspect rows. cesauth
    keeps writing audit events on tamper detection (chain is
    forensic, not runtime gating; ADR-010 §Q3). 757 → **777**
    tests (+20: 4 fetch_after_seq + 10 verifier tamper-
    detection scenarios + 6 UI rendering). Open Questions
    Q1 (checkpoint location) and Q3 (in-flight write
    behavior on tamper) closed in this release; Q2/Q4/Q5
    remain open. Rust dev-dep cycle workaround surfaced and
    documented: verifier integration tests live in
    `cesauth-adapter-test::audit_chain::tests` rather than
    `cesauth-core` itself, because dev-depending core on
    adapter-test would produce duplicate trait artifacts.
  - **0.34.0** ✅ — Refresh token reuse hardening shipped
    (ADR-011 Accepted). The structural rotation invariant
    from RFC 9700 §4.14.2 was already implemented and atomic
    since v0.4 (single-writer `RefreshTokenFamily` DO with
    a current_jti + retired_jtis ring; first reuse atomically
    revokes the family). v0.34.0 closes the **observability**
    gaps surfaced by an audit of the v0.33.0 baseline against
    the BCP §4.13 monitoring expectations. **`FamilyState`
    gains** `reused_jti` / `reused_at` / `reuse_was_retired`
    — all `#[serde(default)]` so existing DO storage records
    deserialize unchanged (no migration). **`RotateOutcome::
    ReusedAndRevoked` carries forensic payload** so the
    service layer doesn't need to peek the family again.
    **New `CoreError::RefreshTokenReuse` variant** distinct
    from `InvalidGrant`; service layer `rotate_refresh`
    dispatches by outcome. **Same wire response** for both
    error variants (`error: "invalid_grant"`, HTTP 400) —
    distinguishing externally would let attackers probe
    family state via error-code differentiation, the BCP-
    flagged side channel. The `(code, status)` decision is
    extracted as `oauth_error_code_status` so wire-equivalence
    can be unit-tested without constructing a wasm-backed
    `worker::Response`. **New audit event
    `EventKind::RefreshTokenReuseDetected`** with JSON payload
    `{family_id, client_id, presented_jti, was_retired}`;
    family_id decoded via audit-only lossy decoder so audit
    writes don't fail-close on malformed tokens.
    **`reuse_was_retired`** distinguishes recognized-retired
    jti (= real leaked token, classic case) from unknown jti
    (= forged or shotgun); operators can prioritize alerts on
    the higher-signal subcase. **Schema unchanged** from
    v0.33.0 (still SCHEMA_VERSION 8). **No DO migration.**
    **Wire format unchanged** for OAuth clients. 777 → **783**
    tests (+6: 3 forensic-field tests in adapter-test, 3
    error-mapper wire-equivalence tests in worker). ADR-011
    documents the audit findings + design + 3 deferred items
    (per-family rate limiting at `/token` — **resolved in
    v0.37.0**, user notification on reuse, tenant admin
    aggregate view).
  - **0.35.0** ✅ — Session management hardening shipped
    (ADR-012 Accepted). v0.34.x baseline audited against
    BCP guidance; five gaps closed: idle timeout enforcement
    (default 30 min, `SESSION_IDLE_TIMEOUT_SECS` env, 0
    disables), `me::auth::resolve_or_redirect` switched
    from `status()` to `touch()` (the load-bearing change —
    without it the new gates would be dormant; this also
    fixes a structural bug where `last_seen_at` was never
    advancing past `created_at` in v0.34.x), `SessionStatus`
    gains `IdleExpired` / `AbsoluteExpired` variants
    populated atomically with the DO state mutation,
    `ActiveSessionStore::list_for_user` port method backed
    by a new D1 `user_sessions` index (SCHEMA_VERSION 8 →
    9, migration 0009; per-session DO remains source of
    truth, D1 row is denormalized index for the user-facing
    list page), `/me/security/sessions` page renders one
    card per active session with auth method label /
    timestamps / client_id / shortened session id and a
    "取り消す" button per non-current row, current session
    shows "この端末" badge with disabled button (revoking
    your own session would surprise the user — the explicit
    logout flow is the right path), `POST /me/security/
    sessions/:session_id/revoke` handler with CSRF guard +
    ownership check (refuses revoke of another user's
    session via 403, defense in depth), four new audit
    event kinds: `SessionRevokedByUser`,
    `SessionRevokedByAdmin`, `SessionIdleTimeout`,
    `SessionAbsoluteTimeout`. Legacy `SessionRevoked` kind
    retained for backward-compatibility with v0.4-v0.34.x
    audit chain rows. **Session-id rotation on login** was
    already correct in v0.34.x via `complete_auth_post_gate`
    minting `Uuid::new_v4` per successful auth — preserved
    unchanged. **"New device" notification deferred** —
    requires general transactional email infrastructure
    cesauth doesn't yet have; would entangle two changes;
    documented in ADR-012 §"Considered alternatives". 783 →
    **801** tests (+18: 11 timeout/list tests in adapter-test,
    7 sessions_page rendering tests in ui). **Schema
    migration required**: operators must run `wrangler d1
    migrations apply` before serving v0.35.0 traffic.
    Without the migration `start()` fails on D1 INSERT and
    new sessions can't be created (existing sessions
    continue working through touch/revoke).

  After all of this — security track complete plus the
  UX iteration — the schedule reverts to the feature
  track (RFC 7662 Token Introspection, etc.).

- **Internationalization (i18n) track.** **Status:
  infrastructure shipped in v0.36.0 (ADR-013); migration
  partial.** cesauth's user-facing UI was language-mixed
  without negotiation pre-v0.36.0: the end-user TOTP /
  Security Center / login surfaces carried hardcoded Japanese
  strings (e.g., "TOTP を有効にしました。", "二段階認証 (TOTP)",
  the wrong-code re-render error
  "入力されたコードが一致しませんでした。…"), the admin console
  carried hardcoded English, and machine-emitted error bodies
  were English. There was no `Accept-Language` handling, no
  locale negotiation, no message catalog, no fallback chain.
  The v0.31.0 flash module carried a TODO at
  `crates/worker/src/flash.rs:215` ("Translations are out of
  scope for v0.31.0; future i18n would replace this lookup
  with one keyed by Accept-Language") — this track is the
  payment of that debt.

  Phasing is open; the track may run in parallel with feature
  work because the surface area is small and discrete:

  - **i18n-1** ✅ — message-catalog infrastructure shipped
    in v0.36.0 (ADR-013 Accepted). `cesauth_core::i18n`
    module: closed `Locale` enum (Ja, En), closed
    `MessageKey` enum (22 variants in v0.36.0), `lookup`
    function with compile-time exhaustive coverage of both
    axes (adding a key without a translation in every locale
    is a build error), RFC 7231 §5.3.5 q-value-aware
    `parse_accept_language` parser. `cesauth_worker::i18n::
    resolve_locale(&Request)` is the per-request
    negotiation entrypoint. Migration pattern: each call
    site adds a `_for(..., locale)` variant alongside the
    existing function; the plain function becomes a
    default-locale shorthand so existing callers continue
    to work unchanged. **20 unit tests** in
    `cesauth_core::i18n::tests`: locale parsing
    (case-insensitive, region-stripping, unknown returns
    None), Accept-Language parsing edge cases (empty,
    q-value priority, q=0 dropped per RFC 7231, wildcard,
    malformed q treated as 1.0 lenient, all-unsupported
    falls through, tie-breaking in document order,
    browser-typical headers), catalog completeness (every
    key resolves to nonempty in every locale, no two keys
    share text within a locale).
  - **i18n-2** 🚧 partial through v0.39.0 — surfaces migrated
    to date: flash banners (5 keys, v0.36.0),
    `/me/security/sessions` chrome (16 keys, v0.36.0), TOTP
    enroll wrong-code error (1 key, v0.36.0), **login page**
    (10 keys, v0.39.0), **TOTP enroll page** (11 keys,
    v0.39.0), **TOTP verify page** (12 keys including new
    `TotpVerifyWrongCode`, v0.39.0), **Security Center
    index** (13 keys, v0.39.0). MessageKey total 22 → 70.
    Catalog completeness tests refactored from hardcoded
    `all_keys` arrays to `for_each_key(closure)` — adding a
    new variant without adding it to the iterator is now a
    build error, not a missed-test silent gap. New
    `cesauth_ui::js_string_literal` helper introduced for
    safe interpolation of catalog strings into inline
    `<script>` blocks (login page passkey-failed JS error
    message); 8 dedicated tests for the helper covering
    UTF-8 multi-byte passthrough, `</script>` defense,
    control-char `\uXXXX` fallback. Disabled-state
    Security Center TOTP rendering goes through the
    catalog; **enabled-state + recovery-codes status row
    intentionally still hardcoded JA** pending v0.39.1+
    (recovery messages need pluralization — ADR-013 §Q4).
    `PrimaryAuthMethod::label()` independently localized
    (used by admin console too) — separable thread, not
    in v0.39.0 scope. Remaining for v0.39.1+: TOTP
    recovery codes display, TOTP disable confirm, magic
    link request + sent, error pages,
    `PrimaryAuthMethod::label`, Security Center
    enabled-state recovery-codes row.

  - **i18n-3** — additional locales added on demand. Pull
    requests welcome.

  - **i18n-4** — RFC 5646 / IETF-BCP-47 language tag
    parsing edge cases (script subtags like `zh-Hant`,
    region subtags like `pt-BR`). Defer until i18n-2 ships
    and real demand surfaces.

  Acceptance for i18n-1 + i18n-2 (the MVP): every
  user-visible string in the v0.33.0+ end-user surfaces
  comes through a `MessageKey` lookup; tests pin the table
  shape; both `ja` and `en` resolve every key. No
  template-side hardcoded prose surviving in the
  end-user templates after the migration.

- **Real mail provider for Magic Link delivery.** The current
  `dev-delivery` audit line containing the plaintext OTP must be
  replaced with a transactional mail HTTP call keyed by
  `MAGIC_LINK_MAIL_API_KEY` before any production deployment.
  (Release gate — see [Security → Pre-production release gates](docs/src/expert/security.md).)

  **Implementation choice (chosen 2026-04)**: use `wasm-smtp v0.6`
  with the `wasm-smtp-cloudflare` adapter. Both crates released
  in 2026-04. The integration point is
  `cesauth-worker/src/routes/magic_link/request.rs` (the
  `dev-delivery` line at line ~157 — the audit-write that today
  carries the plaintext OTP must split into (a) an audit-write
  with handle only, and (b) a `wasm-smtp` send call). Operator
  config flows through `wrangler.toml` `[vars]` for the SMTP
  endpoint + `[secrets]` for credentials. Scope: ~1 release,
  most of it operator-doc work in `docs/src/deployment/`.

- **Discoverable-credential (resident-key) WebAuthn flows.**
  Currently cesauth requires the user to start from an identifier;
  resident keys would allow true username-less login.

- **`prompt=consent` with a real consent screen.** Requires a
  consent-record table, consent-screen UI template, and handler
  wiring. Until then the value is rejected with `invalid_request`.

- **Conditional UI for WebAuthn** (`mediation: "conditional"`) —
  autofill-assisted sign-in.

- **Admin Console hot-path counters (0.3.2).** The Cost Dashboard
  reads `counter:workers:requests:YYYY-MM-DD` and
  `counter:turnstile:{verified,rejected}:YYYY-MM-DD` but nothing
  writes them yet, so fresh deployments report zero for Workers and
  Turnstile. The missing piece is a per-request KV increment, and the
  open design question is at what granularity to count:
    - every fetch (including 404s and preflight)?
    - only requests that land on a real handler?
    - by HTTP method / response class?
  The answer shapes what operators see in the dashboard, and the
  spec is silent on it — defer until the counting policy is settled.
  A related open question: how to handle the read-modify-write race
  (KV has no atomic increment; concurrent requests will lose
  increments). Likely acceptable for a "proxy" metric, but worth
  recording explicitly.

- **Tenancy-service HTTP routes (shipped in 0.7.0).** The
  `/api/v1/...` surface ships JSON CRUD for tenants, organizations,
  groups, memberships, role assignments, and subscriptions. Plan-
  quota enforcement (max_users / max_organizations / max_groups)
  runs on org-create and group-create paths. The remaining design
  question — admin bearer vs session cookie for the tenant-scoped
  console — is now scoped to the v0.8.0 admin console, since the
  0.7.0 surface uses the existing 0.3.x admin-bearer model
  exclusively. The `check_permission` integration is also still
  pending: 0.7.0 routes go through `ensure_role_allows` (admin-side
  capability) because admin tokens have no `users` row to feed into
  `check_permission`. The two converge in 0.8.0+ when user-as-bearer
  arrives.

- **Read-only SaaS console (shipped in 0.8.0).** The
  `/admin/saas/*` HTML surface gives cesauth's operator staff a
  navigable view of tenancy state — tenants, organizations,
  members, subscriptions, role assignments — without having to
  curl the JSON API. Five pages, all read-only by design;
  mutations remain on `/api/v1/...`. The footer carries an
  explicit "read-only" marker so operators don't mistake this
  surface for the writable v0.9.0 follow-up.

- **SaaS console mutation forms (shipped in 0.9.0).** Wraps the
  v0.7.0 JSON API in HTML forms following a risk-graded preview/
  confirm pattern: one-click submit for additive operations
  (creates), v0.4.0-style preview/confirm for destructive ones
  (status changes, group deletes, plan changes). Eight forms ship:
  tenant create / set-status, organization create / set-status,
  group create / delete, subscription set-plan / set-status.
  Affordance buttons gate on `Role::can_manage_tenancy()` so
  ReadOnly operators don't see broken-link buttons. Auth caveat:
  forms POST same-origin and the bearer rides on the
  `Authorization` header — operators must use a tool that sets
  the header (curl, browser extension, or the future cookie-auth
  path).

- **Membership / role-assignment forms (shipped in 0.10.0).** The
  HTML console reaches feature parity with the v0.7.0 JSON API:
  three flavors of membership add (one-click submit) and remove
  (one-step confirm), plus role-assignment grant (full Scope
  picker) and revoke (one-step confirm). Reachable from the
  affordance buttons on tenant detail, organization detail, and
  user role-assignments pages. Operations+ only — ReadOnly
  continues to see the read pages with no mutation buttons.

- **Tenant-scoped admin surface — design settled (0.11.0).** The
  three open design questions from the v0.10.0 deferred list have
  been answered as ADRs at `docs/src/expert/adr/`:
  - **ADR-001**: path-based URLs (`/admin/t/<slug>/...`).
    Single cert, single origin, tenant identity visible.
  - **ADR-002**: user-as-bearer extends `admin_tokens` with an
    optional `user_id` column. `Authorization: Bearer` stays as
    the wire format. No new CSRF surface; no new cryptographic
    key.
  - **ADR-003**: complete URL-prefix separation between
    `/admin/saas/*` (system-admin) and `/admin/t/<slug>/*`
    (tenant-admin). No mode switch. Tenant-boundary leakage is
    structurally impossible.

  The 0.11.0 release shipped the foundation reflecting these
  decisions: migration `0005`, the `AdminPrincipal::user_id`
  field, the `is_system_admin()` helper, and Cloudflare D1
  adapters that read the new column. No UI yet — the surface
  implementation lands in 0.13.0.

- **Project-hygiene release with naming-debt cleanup (shipped in
  0.12.0).** Two threads landed together:
  - **Metadata** — author / license / repository now match
    reality (`nabbisen`,
    `https://github.com/nabbisen/cesauth`). Project framing
    language tightened: "Commercial SaaS" / "商用 SaaS" replaced
    with "tenancy service" or equivalent functional
    descriptions across docs and comments. `.github/` gains
    `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1),
    `CONTRIBUTING.md`, and four `ISSUE_TEMPLATE/*` files.
  - **Naming-debt cleanup** — the `saas/` module path under
    both `crates/ui/` and `crates/worker/src/routes/admin/`,
    the `/admin/saas/*` URL prefix, the `SaasTab` public type,
    and the `via=saas-console` audit reason marker have all
    been renamed to `tenancy_console` / `/admin/tenancy/*` /
    `TenancyConsoleTab` / `via=tenancy-console`. Operator-
    visible — bookmarks and scripts targeting the old prefix
    need updating. No compatibility-redirect routes were
    added; the SemVer caveat documented in the policy section
    permits the hard rename.

- **Buffer / follow-up release (shipped in 0.12.1).** Reserved
  as a placeholder slot for any issues the 0.12.0 rename would
  surface in real-world use. The shippable content turned out
  to be two small but worthwhile threads:
  - **Stale-narrative cleanup** — three docstrings carried
    forward-references and historical claims that the 0.12.0
    rename and intervening release-slot reshuffles
    invalidated. Fixed in `crates/ui/src/tenancy_console.rs`
    (the false "URL prefix preserved" claim and the wrong
    "since v0.18.0" marker) and
    `crates/core/src/tenancy/types.rs` (`AccountType::Anonymous`
    forward-ref to 0.18.0 → 0.14.0; `ExternalFederatedUser`
    forward-ref to 0.18.0 → unscheduled).
  - **Dependency audit** — manual review of every direct
    workspace dependency. No bumps. `getrandom 0.2` and
    `rand_core 0.6` are intentionally pinned at the older
    line for wasm32-unknown-unknown + Cloudflare Workers
    integration; bumping is gated on the workers-rs
    ecosystem aligning on the corresponding 0.3 / 0.9 lines.
    Every other direct dep is current.

- **Tenant-scoped admin surface — read pages shipped (0.13.0).**
  The 0.11.0 foundation lands as a working surface. Six read
  pages under `/admin/t/<slug>/...` (overview, organizations,
  organization detail, users, role assignments, subscription),
  a per-route auth gate that enforces ADR-003's three
  invariants (principal is user-bound, slug resolves, user
  belongs to the slug's tenant), and `check_permission`
  integration via a new `gate::check_read` helper that wraps
  the spec §9.2 scope-walk for the worker layer. New port
  methods: `AdminTokenRepository::create_user_bound` (mints
  tokens with `admin_tokens.user_id` populated) and
  `UserRepository::list_by_tenant` (powering the tenant-scoped
  users page). 245 tests passing (+26): 9 in
  `core::tenant_admin::tests` for the gate, 4 in
  `adapter-test` for `create_user_bound`, 13 in
  `ui::tenant_admin::tests` for chrome and per-page rendering.
  Read pages only — mutation forms in 0.14.0 mirror the
  v0.8.0 → v0.9.0 split for the system-admin surface.

- **Tenant-scoped high-risk mutations + token-mint UI
  (shipped in 0.14.0).** Six tenant-scoped form pairs at
  `/admin/t/<slug>/...` (organization create + status,
  group create + delete, role-assignment grant + revoke), plus
  one system-admin form pair at
  `/admin/tenancy/users/:uid/tokens/new` exposing
  `AdminTokenRepository::create_user_bound`. Each handler
  composes the v0.13.0 gate (`auth::resolve_or_respond` →
  `gate::resolve_or_respond` → `gate::check_action`) with the
  appropriate write permission slug; preview/confirm gating on
  the `confirm` form field; audit emission with
  `via=tenant-admin,tenant=<id>` to distinguish from
  `via=tenancy-console`. Defense-in-depth invariants enforced
  per-handler:
  - `organization_set_status`: re-verifies
    `org.tenant_id == ctx_ta.tenant.id`.
  - `group_delete`: walks `GroupParent` to verify either
    `group.tenant_id` or the parent organization's tenant_id.
  - `role_assignment_grant`: rejects `Scope::System` outright
    (per ADR-003), forces tenant scope's scope_id to the
    current tenant, and `verify_scope_in_tenant` walks
    storage to confirm Organization / Group / User scopes
    belong to this tenant before granting.
  - `role_assignment_revoke`: re-verifies the assignment's
    user belongs to this tenant.

  The `gate::check_read` from 0.13.0 is now a thin wrapper
  around a more general `gate::check_action(permission, scope, ctx)`
  that accepts an explicit `ScopeRef` (mutations need narrower
  scopes than reads). 257 tests pass (+12), zero warnings.

- **Tenant-scoped additive mutations + affordance gating
  (shipped in 0.15.0).** Six membership form pairs at
  `/admin/t/<slug>/...` (`memberships/`,
  `organizations/<oid>/memberships/`, `groups/<gid>/memberships/`
  — each with new + delete flavors). Two new permission slugs
  added to fill the symmetry gap: `TENANT_MEMBER_ADD` and
  `TENANT_MEMBER_REMOVE`. Defense-in-depth: target user_id is
  verified to belong to the current tenant before any add
  proceeds.

  Affordance gating: every read page and form page now renders
  mutation links/buttons only when the current user holds the
  relevant permission at tenant scope. Implementation:
  - **`check_permissions_batch`** new in
    `cesauth_core::authz::service` — evaluates N (permission,
    scope) queries with one `list_for_user` call + cached role
    lookups. The scope-walk is in-memory; the cost is one D1
    round-trip total, not N.
  - **`Affordances` struct** in `cesauth_ui::tenant_admin` —
    twelve boolean flags. `Default` is all-false (the safe
    default); `all_allowed()` is provided for tests.
  - **`gate::build_affordances`** in worker — issues the batch
    check and maps results to the struct.
  - Each read/form template now takes `&Affordances` and emits
    HTML conditionally for "+ New organization", "Change
    status", "+ New group", "delete", "+ Add member",
    "+ Grant role", "revoke", etc.

  The route handlers behind each affordance still re-check on
  submit (defense in depth). The affordance gate is the
  operator's first signal — clicking what they can't do already
  returned 403 since v0.13.0, but they shouldn't have to find out
  by clicking. 276 tests pass (+19), zero warnings.

  This release brings the tenant-scoped surface to feature
  parity with what the system-admin tenancy console reached at
  v0.10.0.

- **Anonymous trial → human user promotion — design + foundation
  (shipped in 0.16.0).** ADR-004 settles the five design
  questions (provenance / token issuance / retention / conversion
  ceremony / audit trail). Foundation in this release:
  - **Migration `0006_anonymous.sql`** — `anonymous_sessions`
    table with `token_hash` PK, FK CASCADEs to `users` and
    `tenants`, indexes for the retention sweep and per-user
    revocation paths.
  - **`cesauth_core::anonymous`** — `AnonymousSession` value
    type with `is_expired()` (boundary inclusive — pinned by
    test), `AnonymousSessionRepository` port (4 methods),
    `ANONYMOUS_TOKEN_TTL_SECONDS` (24h) and
    `ANONYMOUS_USER_RETENTION_SECONDS` (7d) constants.
  - **In-memory adapter** in `cesauth-adapter-test`, **D1
    adapter** in `cesauth-adapter-cloudflare` — both behind
    the same trait; the adapter test that runs both will
    catch divergence early in 0.17.0.
  - **`EventKind`** gains `AnonymousCreated`,
    `AnonymousExpired`, `AnonymousPromoted` so v0.17.0's
    emit calls don't force an audit-schema bump on the
    downstream side.

  286 tests pass (+10 over v0.15.1); zero warnings. The
  HTTP surface and existing audit kinds are untouched —
  this is a pure additive release. ADR-004 is in `Draft`
  status until v0.17.0 ships the routes that exercise it.

- **Anonymous trial — HTTP routes (shipped in 0.17.0).**
  ADR-004 graduates from `Draft` to `Accepted`. Two routes
  land:
  - `POST /api/v1/anonymous/begin` — unauthenticated (per-IP
    rate limit only). Mints fresh `users` row +
    `anonymous_sessions` row, returns plaintext bearer once.
    Strict rate limit: 20 over 5 minutes per IP, with
    Turnstile-style escalation at 10. The 7-day daily
    retention sweep (0.6.05) is the second line of defense.
  - `POST /api/v1/anonymous/promote` — anonymous-bearer
    authenticated. Two-step body shape (no `code` =
    issue-OTP step; with `code` = verify-OTP+apply step)
    distinguishes phases under one URL. Magic Link
    infrastructure reused unchanged. UPDATEs the user row
    in place (preserving `User.id`); revokes the anonymous
    bearer at promotion time. Email collisions return a
    distinguishable error (`email_already_registered`) so
    the client can render the right guidance vs OTP-failure.

  Defense-in-depth invariants pinned by adapter-level tests:
  revoke-before-update fail-safe ordering, per-user revoke
  isolation, idempotent double-promote (the racy second
  submit's revoke returns `Ok(0)`, then the route's
  `account_type == Anonymous` re-check refuses with
  `not_anonymous`). 289 tests pass (+3 over v0.16.0);
  zero warnings.

- **Anonymous trial — daily retention sweep (shipped in 0.18.0).**
  ADR-004 Phase 3, the final piece. The flow is now
  feature-complete. New `[triggers]` block in `wrangler.toml`
  (operator-visible config change — first cron trigger in
  cesauth) fires the new `#[event(scheduled)]` handler at
  04:00 UTC daily. The sweep handler runs:
  ```sql
  SELECT id, ... FROM users
   WHERE account_type='anonymous' AND email IS NULL
     AND created_at < ?  -- now - 7d
  ```
  emits one `AnonymousExpired` audit event per row, then
  deletes the row (FK CASCADEs clean up
  `anonymous_sessions`, memberships, role assignments).
  Best-effort failure semantics: per-row failures log `Warn`
  and continue; the next day's sweep retries the survivors.

  **Operator-visible**: cron invocation history in the
  Cloudflare dashboard, `wrangler tail` for live streaming,
  one `Info` summary line per sweep:
  `"anonymous sweep complete: X/Y rows deleted"`. Operator
  runbook gains "Verifying the anonymous-trial retention sweep
  ran" with a residual-count diagnostic query.

  Schema additions: `UserRepository::list_anonymous_expired`
  and `delete_by_id` port methods; in-memory + D1 adapters;
  `EventKind::AnonymousExpired` was pre-added in 0.16.0. 294
  tests pass (+5 over v0.17.0); zero warnings.

- **Data migration tooling (server-to-server moves) — Phase 4:
  polish (shipped in 0.22.0).** All four phases of ADR-005 are
  now shipped; the data-migration tooling is feature-complete
  for the design's scope. Phasing summary:

  - **0.19.0** — design + foundation (ADR-005, library value
    types, CLI skeleton).
  - **0.20.0** — real export + verify, the source side.
  - **0.21.0** — real import, the destination side; ADR-005
    graduated to Accepted.
  - **0.22.0** (this release) — polish: `--tenant <id>`
    filter on `export` (with `TenantScope::Global` vs
    `OwnColumn` per-table classification + manifest scope
    record), `cesauth-migrate refresh-staging` single-command
    combinator (export + redaction + import in one
    invocation, opinionated for single-operator runs, `--yes`
    for unattended use), email-uniqueness-within-tenant
    invariant check (redaction-aware, case-insensitive,
    `users.email` `COLLATE NOCASE`-matching), per-row import
    progress via `ProgressSink` decorator. 379 tests pass
    (+21 over v0.21.0).

  **Deferred to post-1.0 polish** — these were originally on
  the v0.22.0 list but are reclassified because they don't
  change the design and don't have known operator demand:

  - **Resume on interruption** — checkpoint-file format is
    real new design surface. The current Ctrl-C-then-restart-
    from-zero workflow is acceptable for the dump sizes the
    tool targets.
  - **Native Cloudflare HTTP API client** — wrangler shell-out
    works. A native client would avoid subprocess spawn costs
    and the wrangler dependency, but it adds a non-trivial
    HTTP auth surface to the binary.
  - **Custom invariant registration via CLI** — the library
    accepts a slice of `InvariantCheckFn` already; the CLI
    just hardcodes `default_invariant_checks()`. When an
    operator hits a case the defaults miss, the surface to
    expose this is straightforward.

- **OAuth 2.0 Token Introspection (RFC 7662).** `POST /introspect`.
  RFC 7009 (`/revoke`) shipped with the OIDC core; the
  introspection counterpart is the gap. RPs that want to
  validate opaque access tokens stateful-style (instead of
  parsing JWTs themselves) need this. Implementation lifts
  the existing `ActiveSessionStore::status` lookup and wraps
  it in the RFC 7662 response shape (`active`, `client_id`,
  `username`, `exp`, etc.) gated on client authentication.
  The discovery doc gains an `introspection_endpoint`
  declaration. Estimated scope: ~150 lines + tests.

- ✅ **Property-based tests (`proptest`)** — shipped in v0.51.1 (RFC 003). ~~for round-trip and
  matcher invariants.** Two surfaces benefit most:
  1. **Crypto round-trips**: `EncodingKey::from_ed_pem` →
     `DecodingKey::from_ed_der` → JWT sign → JWT verify →
     equal claims; magic-link token gen → verify →
     equal subject. Pure-deterministic, well-defined
     invariants — proptest catches the pathological inputs
     that example-based tests don't reach.
  2. **`redirect_uri` matcher**: OAuth's redirect-URI
     matching is historically the most bug-prone piece of
     a provider (open-redirect via prefix-match, port
     stripping, percent-encoding, IDN). proptest can
     generate adversarial URI pairs and assert the match
     decision matches the spec.

  Modest dep cost (proptest is dev-dep only). Target slot:
  any maintenance window.

- ✅ **`cargo fuzz` for the JWT parser surface** — shipped in v0.51.2 (RFC 005). cesauth
  receives potentially adversarial JWTs on every
  `Authorization: Bearer ...` request. The `jsonwebtoken`
  crate itself is upstream-fuzzed, but cesauth's wrappers
  (`jwt::signer.rs` PEM/DER parsing, claim extraction
  helpers) are independent code paths. Fuzz them for panics,
  OOM, and DoS. Layer-1 setup (single fuzz target,
  GitHub Actions one-shot run) is cheap; long-term continuous
  fuzzing is parked under "Later" for now. Note: CIDR
  parser is **not** a fuzz target — cesauth has no IP
  allowlist code path (Cloudflare dashboard handles
  IP-level controls). Config parser is `Config::from_env`
  reading discrete env vars, surface too small to fuzz
  productively.

- ✅ **WebAuthn error → typed client responses** — shipped in v0.51.1 (RFC 004). ~~The current
  `CoreError::WebAuthn(&'static str)` carries diagnostic
  strings (`"rpIdHash mismatch"`, `"signature invalid"`,
  etc.) that surface only in server-side logs. The HTTP
  response shape collapses them into a generic 400. Client
  UX would benefit from a small `WebAuthnErrorKind` enum
  exposed in the JSON body — distinguishing "wrong
  authenticator", "user cancelled", "credential not
  registered", "RP id mismatch (likely subdomain
  misconfiguration)" so RPs can render specific guidance.
  Server-side strings stay as today (the typed variant is
  the *category*, the string is the *detail*).

- **Domain-metric observability.** Cloudflare Analytics
  already covers HTTP-level metrics (request rate, error
  rate, p50/p95/p99 latency). The gap is **domain-specific**
  counters: `auth_attempts_total{result, method}`,
  `tokens_issued_total{kind}`, `webauthn_ceremony_failures_total{stage}`.
  Architecturally, Prometheus pull is a poor fit for
  Workers (stateless, horizontally scaled — `/metrics` would
  return single-instance values). The native path is to
  emit metric events through the existing `log.rs`
  channel and aggregate downstream via Logpush →
  ClickHouse / BigQuery / Datadog, **or** use the
  Cloudflare `cloudflare:analytics-engine` binding which
  is purpose-built for this. Target slot: any maintenance
  window once the operator-facing dashboarding requirement
  becomes concrete.

- **`cargo audit` integration (shipped in 0.15.1).** Three
  layers landed at once:
  1. **Initial sweep**: ran against the rustsec/advisory-db
     `main` checkout on 2026-04-28. One finding —
     RUSTSEC-2023-0071 in `rsa 0.9.10` (Marvin Attack timing
     side-channel), pulled in transitively by `jsonwebtoken`'s
     `rust_crypto` feature. cesauth never exercised the RSA
     path (EdDSA-only), but the dep would have shipped in the
     workspace lock anyway. Fixed by narrowing `jsonwebtoken`
     features from blanket `rust_crypto` to explicit
     `ed25519-dalek` + `rand`. Post-fix sweep clean; dep count
     186 → 176.
  2. **`.github/workflows/audit.yml`** using
     `rustsec/audit-check@v2.0.0`. Triggers: push, PR,
     weekly cron (Mondays 06:00 UTC), manual dispatch.
     New advisories fail the workflow.
  3. **Operator documentation**: `docs/src/deployment/production.md`
     gains a "Step 7 — Verify dependencies" pre-deploy
     check; the operator runbook in
     `docs/src/expert/tenancy.md` documents the same command
     under "Verifying dependencies before an upgrade".

  Layer 4 (Makefile / xtask wrapper) is **not planned** —
  the cost-vs-value isn't there for a workspace with no
  Makefile today.

- **Login → tenant resolution.** Today `users.email` is globally
  unique. Multi-tenant login flows need either
  tenant-scoped email uniqueness (schema change) or a tenant-picker
  step in the login flow. Spec §6.1 mentions tenant-scoped auth
  policies; the precise UX is open. Tracked here so the change is
  not made silently.

- **External IdP federation.** `AccountType::ExternalFederatedUser`
  is reserved in 0.5.0 but no IdP wiring exists. SAML / OIDC
  federation surface; specific protocols TBD.

### Later

- ✅ **`oidc_clients.client_secret_hash` documentation drift** — resolved in v0.51.0 (RFC 002).
  ~~The schema comment in `migrations/0001_initial.sql` describes
  `client_secret_hash` as "argon2id(secret) or NULL", but no
  Argon2 implementation exists~~ in cesauth as of v0.26.0 — the
  hashing path for client_secret falls back to whatever the
  adapter does, which currently is plaintext comparison or
  unimplemented. (Discovered during the v0.26.0 TOTP work.)
  Two paths to resolve: either implement Argon2id hashing of
  client_secret on write + verify on read (matches the schema
  comment, adds a real password-stretching dependency for the
  one input type that's user-chosen), OR relax the schema
  comment to "SHA-256(secret) or NULL" and route client_secret
  through the same hashing path as admin_tokens (matches what
  cesauth actually does for similar bearer secrets). The
  former is more rigorous; the latter is more honest. Either
  is fine; the current state — schema lying — is not.

- ✅ **OIDC `id_token` issuance** — shipped v0.54.0 (RFC 001, ADR-008).
  cesauth now fully implements OIDC Core §3.1.2.2.
  Discovery doc restored to OIDC posture.
  See `docs/src/expert/adr/008-id-token-issuance.md`.
  Closes the OIDC compliance gap surfaced by the v0.25.0 email
  verification audit: `exchange_code` and `rotate_refresh`
  currently return `id_token: null`, and the discovery doc was
  honestly reset to RFC 8414 OAuth 2.0 metadata until id_token
  ships. Implementation requires:
  - `UserRepository` injected into `cesauth_core::service::token`
    (generic-parameter addition).
  - `auth_time` plumbed through `Challenge::AuthCode` and
    `RefreshTokenFamily` DO state.
  - `build_id_token_claims` pure function with scope-driven
    population (`email`/`email_verified` iff `email` scope;
    `name` iff `profile` scope).
  - Discovery doc restored to OIDC Discovery 1.0 shape with
    `claims_supported` field added.
  - End-to-end test: authorize → token exchange → id_token
    decoded and claims verified.
  - 8 v0.25.0 discovery shape tests inverted/extended to OIDC
    posture.

  **Scheduled when**: TOTP track (v0.26.0 - v0.30.0) is now
  complete. The schedule continues with the UI/UX iteration
  (v0.31.0) and the audit-log-hash-chain track (v0.32.0+)
  before the feature track resumes. Likely v0.36.0 or later.
  Not blocking 1.0 unless a deployment requires OIDC compliance
  for an identity-federation integration. The audit doc and
  ADR-008 keep the design ready for whoever picks it up.

- **`prompt=select_account`.** Requires multi-session / account-picker
  UX. Rejected today.

- **Full FIDO attestation verification** (`packed`, `tpm`,
  `android-key`, `android-safetynet`, `fido-u2f`, `apple`).
  Requires a FIDO Metadata Service (MDS) implementation and a CA
  trust store. Useful if a deployment needs AAGUID-gated access
  control.

- **Device Authorization Grant** (RFC 8628) for CLI / smart-TV
  clients.

- **Dynamic Client Registration** (RFC 7591 / 7592) if multi-tenant
  deployments become a target.

- **Request Objects** (`request` / `request_uri` parameters, JAR).

- **Pushed Authorization Requests** (RFC 9126 PAR).

- **Rate-limit bucket tuning** based on production telemetry.

- **FIDO Alliance conformance certification.** Costs real money and
  assumes full attestation support is already in.

- **OIDC `client_secret` brute-force lockout (per-client).**
  Per-client failure tracking on `oidc_clients` for
  `client_secret_basic` / `client_secret_post` authentication
  failures at `/oauth/token`. **Trigger condition for adoption**:
  production telemetry shows non-trivial volume of failed
  `client_secret` attempts against existing clients. As of
  v0.23.0 (the canonical release), the prior v0.23.0-withdrawn
  attempt assumed user-account lockout, which is inapplicable
  to cesauth's password-less authentication model — Magic Link
  and WebAuthn are the only credential paths and both have
  cryptographic brute-force resistance. Per-client lockout
  would have a different data model (lockout state on
  `oidc_clients`, no per-tenant policy override since clients
  are tenant-scoped, no Magic Link/WebAuthn interaction). A
  future ADR (probably -010) would re-design from the
  per-client angle if the threat materializes. The withdrawn
  artifact (`cesauth-0.23.0-account-lockout-withdrawn.tar.gz`)
  is preserved for reference; ADR-006 number is not reused.

- **CSP without `'unsafe-inline'` (nonces or template
  refactor).** ADR-007 §Q3 documents the v0.23.0 limitation:
  cesauth's HTML templates embed `<style>` and `<script>`
  inline, requiring per-route CSPs to use `'unsafe-inline'`.
  Two paths to remove this: extract inline content to
  same-origin files, or generate per-request nonces and
  attach them to every inline block. The latter is the
  modern best practice. Either path is real refactor work
  (templates module + every render path); track separately
  from the security headers shipped in v0.23.0.

- **Cesauth-specific attack surface review.** A periodic
  audit (ideally before each major milestone, and at minimum
  before any 1.0 release) of cesauth-specific attack
  surfaces. Initial 2026 review identified the following as
  worth examining; this list is not exhaustive and the
  reviewer should look broader:
  - **Open redirect via OAuth `redirect_uri` matcher**: the
    matcher implementation should be exercised with proptest-
    generated adversarial URI pairs. (Already on roadmap as
    "Property-based tests".)
  - **JWT alg confusion attack**: confirm the verifier
    rejects `alg: none`, and never verifies `alg: HS256`
    against a public key.
  - **Confused deputy in tenant scoping**: tenant A's admin
    operating tenant B's resources via global `/api/v1/...`
    routes. (Already on roadmap as "`check_permission`
    integration".)
  - **Subdomain takeover**: if a deployment surfaces
    tenants on `<slug>.example.com`, retired tenants must
    have DNS reclaimed.
  - **PKCE enforcement**: confirm public clients are
    rejected without PKCE.
  - **Cookie security**: SameSite, Secure, HttpOnly attrs
    on every cookie; Path scope; rotation on session id.
  - **Timing side-channels** in token comparison and
    secret verification (constant-time comparison
    everywhere).
  - **Open registration paths**: anonymous trial creation
    rate limit, abuse vectors.

  **Maintainer TODO**: schedule the next review by 2026-Q4
  or before v0.30.0, whichever is sooner. Outcomes either
  feed into the security-track minor releases or become
  individual hardening releases.

---

## Explicitly out of scope

The following are not planned for any future release. If a deployment
needs one of these, cesauth is the wrong choice.

- **Password-based authentication.** No password-hash table, no
  "forgot password" flow, no password reset endpoint. Magic Link
  and passkey cover the equivalent UX without the password's
  problems.

- **SAML 2.0**, **WS-Federation**, **OAuth 1.0**. Out of scope in
  both directions (not as IdP, not as consumer).

- **LDAP directory integration.** Not blocked on LDAP specifically;
  blocked on the entire concept of federating identity from an
  external directory. cesauth is a primary identity source.

- **Management GUI.** The admin surface is an API (`/admin/*`). If
  you need a dashboard, build one on top.

- **Implicit flow** / **hybrid flow**. Deprecated by OAuth 2.1 for
  good reasons.

- **Docker / container-based production deployment.** cesauth
  targets the Cloudflare Workers runtime (V8 isolate, wasm32
  + the `cf::*` API surface, Durable Objects, R2, D1). None of
  these are available inside a generic container. Production
  deployment is `wrangler deploy`; local development is
  `wrangler dev`. A "build environment" container (containing
  `cargo-1.91`, `wrangler`, `node`) for developer onboarding
  would be a pure ergonomics win, but is not on the roadmap —
  the supported install paths in `docs/src/beginner/prerequisites.md`
  cover the same ground.

- **Prometheus `/metrics` endpoint.** Architecturally a poor
  fit for Workers' stateless / horizontally-scaled execution
  model — a scrape would return single-instance values that
  don't aggregate. See "Domain-metric observability" in
  Planned for the alternative path (Logpush + downstream
  aggregation, or `cloudflare:analytics-engine`).

- **A generic `KeyValueStore` trait.** See [Storage responsibilities](docs/src/expert/storage.md)
  for the reasoning.

- **`mod.rs` module files.** See [Crate layout](docs/src/expert/crate-layout.md).

---

## How to propose changes

Open an issue describing the use case. If it aligns with cesauth's
scope, we'll discuss the design tradeoffs before code. A formal
`CONTRIBUTING.md` is planned but not yet written.
