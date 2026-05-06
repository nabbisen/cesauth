# Roadmap

cesauth is pre-1.0 software. This file tracks what ships today, what
is planned, and what is deliberately out of scope.

Format inspired by [Keep a Changelog](https://keepachangelog.com/) and
the [Semantic Versioning](https://semver.org/) naming for priorities.

---

## Versioning policy

cesauth follows SemVer with one pre-1.0 caveat: the major number stays
at `0` until the public surface settles. Within `0.x.y`:

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

The first `1.0` release will be cut when:

- The OIDC ceremony surface is stable across at least one minor
  cycle without breaking changes.
- The tenancy-service API has been exercised by at least one
  external integrator without protocol-level surprises.
- The operator surface (admin console, tenant-scoped admin) has
  reached the "what shipped is what we want" point.

---

## Shipped (pre-1.0)

The following subsystems are implemented end-to-end and covered by
host tests. "Initial" here means the happy path and the documented
failure modes are in place; it does not imply production-ready with
zero remaining issues.

| Area                                   | Status   | Where                                             |
|----------------------------------------|----------|---------------------------------------------------|
| Five-crate workspace + ports/adapters  | ✅       | `crates/core`, `crates/adapter-*`, `crates/worker` |
| D1 schema                              | ✅       | `migrations/0001_initial.sql`                      |
| Durable Objects: 4 classes             | ✅       | `crates/adapter-cloudflare/src/objects/*`          |
| OIDC discovery document                | ✅       | `/.well-known/openid-configuration`                |
| JWKS endpoint                          | ✅       | `/jwks.json`                                       |
| `/authorize` with PKCE S256, `prompt`, `max_age` | ✅ | `crates/worker/src/routes/oidc.rs`             |
| `/token` code exchange + refresh rotation | ✅    | Reuse-burns-family rule enforced                   |
| `/revoke` (RFC 7009)                   | ✅       |                                                   |
| WebAuthn EdDSA + ES256, `none` attestation | ✅   | Pure-Rust via `core::webauthn::cose`               |
| Magic Link (dev delivery; see caveat)  | ✅       | `routes::magic_link::*`                            |
| Post-auth code minting                 | ✅       | `post_auth::complete_auth` across all auth paths    |
| Signed session cookies (`__Host-cesauth_session`) | ✅ | HMAC-SHA256 with `SESSION_COOKIE_KEY`        |
| Session revocation (`ActiveSessionStore`) | ✅    | Admin + user-initiated (`/logout`)                 |
| CSRF protection (double-submit cookie) | ✅       | Form POSTs; JSON bypasses                          |
| Operational logger (JSON Lines)        | ✅       | Categorized, level-gated, sensitivity-gated         |
| Turnstile integration (flag-based)     | ✅       | Fires on `RateLimitDecision.escalate`              |
| Admin API (`POST /admin/users`, `DELETE /admin/sessions/:id`) | ✅ | Role-gated (0.3.0), bearer auth             |
| Audit log (R2, NDJSON per event)       | ✅       | Covered by `/__dev/audit` browser + searchable via admin console (0.3.0) |
| **Cost &amp; Data Safety Admin Console** | ✅     | `/admin/console/*` — Overview, Cost, Safety, Audit, Config, Alerts (0.3.0); HTML two-step edit UI for bucket-safety + admin-token CRUD (0.4.0) |
| Dev-only routes (`/__dev/*`)           | ✅       | Gated on `WRANGLER_LOCAL="1"`                      |
| **Tenancy-service data model + authz** | ✅       | Tenants, organizations, groups, memberships, role/permission engine, plans, subscriptions (0.18.0). Cloudflare D1 adapters for every port + `users` table tenant-aware (0.6.0). `/api/v1/...` HTTP routes for tenant / org / group / membership / role-assignment / subscription CRUD with plan-quota enforcement (0.7.0). Read-only HTML console at `/admin/tenancy/*` (0.8.0, originally `/admin/saas/*`). Mutation forms with preview/confirm pattern (0.9.0) for tenant / organization / group / subscription. Membership add/remove + role grant/revoke forms (0.10.0) bring the HTML console to feature parity with the v0.7.0 JSON API. ADR-001/002/003 settle the tenant-scoped admin surface design (0.11.0) and ship the schema + type foundation (`admin_tokens.user_id`, `AdminPrincipal::user_id`, `is_system_admin()`). Project-hygiene release with naming-debt cleanup (0.12.0) — `saas/` → `tenancy_console/`, `/admin/saas/*` → `/admin/tenancy/*`, plus author/license metadata and `.github/` community documents. Buffer/follow-up release with stale-narrative cleanup + dependency audit (0.12.1). Tenant-scoped admin surface read pages shipped at `/admin/t/<slug>/*` with auth gate + `check_permission` integration (0.13.0). High-risk mutation forms plus a system-admin token-mint UI shipped (0.14.0). Additive membership forms (× 3 flavors) plus affordance gating shipped (0.15.0) — the tenant-scoped surface reaches feature parity with the system-admin tenancy console. Security-fix and audit-infrastructure release (0.15.1): RUSTSEC-2023-0071 in transitive `rsa` removed via `jsonwebtoken` feature narrowing, `cargo audit` integrated via initial sweep + GitHub Actions workflow + operator docs. Anonymous-trial promotion design (ADR-004) plus foundation (migration `0006_anonymous.sql`, `AnonymousSession` type + repository, in-memory + D1 adapters, 3 new audit event kinds) shipped (0.16.0). Anonymous-trial HTTP routes (`POST /api/v1/anonymous/begin` and `/promote`) shipped (0.17.0); ADR-004 graduates to `Accepted`. Anonymous-trial daily retention sweep (Cloudflare Workers Cron Trigger, `[triggers]` block in `wrangler.toml`, sweep handler with audit-before-delete ordering, operator runbook diagnostic) shipped (0.18.0); ADR-004 feature-complete. **Note: versioning was retroactively re-aligned with the [versioning policy](#versioning-policy) at 0.18.0; the version numbers shown for 0.5.0 through 0.18.0 in this row are the re-aligned values, not the original tarball numbers — see the [Versioning history note](../CHANGELOG.md#versioning-history-note) section in CHANGELOG for the full mapping.** Deployment guide build-out shipped (0.18.1) — eight new operator-facing chapters (pre-flight, cron, custom domains, multi-environment, backup/restore, observability, day-2 runbook, disaster recovery) covering the operational surface previously held in tribal knowledge. |
| **Data migration tooling**             | ✅       | ADR-005 + foundation shipped (0.19.0): `cesauth_core::migrate` library value types (`Manifest`, `TableSummary`, `PayloadLine`), redaction profile registry with two built-ins, `FORMAT_VERSION` + `SCHEMA_VERSION` constants, CLI skeleton with `list-profiles` implemented. Real export + verify shipped (0.20.0): typed `MigrateError` (8 kinds), `Exporter<W>` with single-use `ExportSigner` (per-export Ed25519 keypair, fingerprint handshake), streaming `verify` with per-table + whole-payload SHA-256 checks, `apply_redaction` with deterministic `HashedEmail` (preserves UNIQUE invariant). CLI's `export` subcommand wires `WranglerD1Source` → `Exporter` (refuses to clobber, prints fingerprint to stderr at start, walks `MIGRATION_TABLE_ORDER` of 18 tables in topological order, prints secrets-coordination checklist at end). CLI's `verify` subcommand has no D1 dependency. Real import shipped (0.21.0): `Violation` + `ViolationReport`, `InvariantCheckFn` + `SeenSnapshot` + four default checks (user→tenant, membership→user, membership→container, role_assignment→role+user), `ImportSink` trait with `WranglerD1Sink` impl (batched-INSERT-per-table commits, full rollback on decline). CLI's `import` subcommand walks five gates (verify → fingerprint handshake → `JWT_SIGNING_KEY` pre-flight → invariant checks → final commit confirmation) — destination D1 untouched until final yes. **ADR-005 graduated to Accepted (0.21.0)**. New deployment chapter `data-migration.md` makes the legacy `sed`-script prod→staging refresh pattern obsolete; new runbook section "Operation: cross-account data migration"; disaster-recovery Scenario 4 (account compromise) rewritten with concrete `cesauth-migrate` invocations. Polish phase shipped (0.22.0): `--tenant <id>` filter on `export` (with manifest scope record + `TenantScope::Global` vs `OwnColumn` per-table classification), `cesauth-migrate refresh-staging` single-command combinator (export + redaction + import in one invocation, opinionated for single-operator runs, `--yes` for unattended use), email-uniqueness-within-tenant invariant check (redaction-aware, case-insensitive), per-row import progress via `ProgressSink` decorator. **Feature-complete for ADR-005's scope as of 0.22.0.** Deferred items (resume support, native Cloudflare HTTP API client, custom invariant registration via CLI) are tracked as post-1.0 polish — they don't change the design and don't have known operator demand. |
| **HTTP security response headers**     | ✅       | ADR-007 (`Accepted`, 0.23.0): unified middleware replaces ad-hoc per-response `harden_headers`. Adds three previously-missing headers (`Strict-Transport-Security`, `Permissions-Policy`, plus `X-Frame-Options` now gated to HTML responses). Pure-function library `cesauth_core::security_headers` produces header lists; worker shim reads operator env (`SECURITY_HEADERS_CSP`/`STS`/`DISABLE_HTML_ONLY`) and applies via `worker::Headers::set`. Library tracks `already_set` so per-route CSPs (login, OIDC authorize, admin console — all use `'unsafe-inline'` for current template constraints) are preserved; "don't clobber" is a library responsibility with case-insensitive header-name matching. 28 new tests cover defaults pinning, content-type detection (rejects `text/htmlx` partial-match), env override parsing (strict `"true"` matching for the disable knob), don't-clobber semantics. New operator chapter `docs/src/deployment/security-headers.md`. **Note (v0.23.0 supersedes a withdrawn release)**: a prior v0.23.0 attempt added per-account lockout based on the incorrect premise that cesauth has password authentication; withdrawn before canonical, artifact preserved as `cesauth-0.23.0-account-lockout-withdrawn.tar.gz`. CSP without `'unsafe-inline'` (nonces or template extraction) tracked as future work in the security track. |
| **Security track Phase 1: SECURITY.md + CSRF audit + dep scan automation review** | ✅       | Shipped 0.24.0. Documentation- and audit-heavy with one small CSRF gap fill. **`.github/SECURITY.md` improvements**: severity-based response-target table (Critical 24h/72h/7d, scaled), known-limitations subsection (CSP `'unsafe-inline'`, no per-account lockout, `/admin/*` Authorization-only), see-also cross-links. **CSRF audit** (`docs/src/expert/csrf-audit.md`) per-route inventory with mechanism per route (4 mechanisms: token, Origin/Referer check, CORS preflight, `Authorization: Bearer`), cookies+SameSite audit, token-binding analysis, decision tree for new routes, test coverage summary, re-audit cadence. **CSRF gap fill on `/magic-link/verify`**: form-encoded path now validates the CSRF token (mirrors `/magic-link/request`); JSON path remains exempt (CORS preflight); `csrf_mismatch` audit event. **Dep scan automation review**: verified `.github/workflows/audit.yml` is comprehensive (push to main + every PR + weekly cron + manual dispatch; `rustsec/audit-check@v2.0.0`; opens GitHub issues automatically); documented the alert path in new "Dependency vulnerability scanning" section in `docs/src/expert/security.md`. **Discovered UX bug**: `magic_link_sent_page()` template missing `handle`/`csrf` hidden inputs — fixed in v0.25.0. 6 new tests pin the CSRF field contract on `VerifyBody` and `RequestBody`. Total 437 passing (worker tests now broken out — see CHANGELOG note on the historical undercount). |
| **Security track Phase 2: email verification audit + OIDC discovery honest reset** | ✅       | Shipped 0.25.0. Audit deliverable (`docs/src/expert/email-verification-audit.md`) per-path table with 9 rows + meaning of `email_verified=true` + the discovered OIDC `id_token` issuance gap. **Concern 2 fix**: returning-user Magic Link verify flips `email_verified=true` when previously false (best-effort UPDATE, skip-write optimization for already-verified rows). **Discovery doc honest reset** (breaking wire change): `id_token_signing_alg_values_supported` and `subject_types_supported` removed from struct + JSON output; `openid` removed from `scopes_supported` (now `["profile", "email", "offline_access"]`); discovery is now RFC 8414 OAuth 2.0 metadata, not OIDC Discovery 1.0 — accurate to what the implementation delivers. **`magic_link_sent_page()` UX bug fix** (folded in from v0.24.0 audit): template takes `handle: &str, csrf_token: &str` parameters, both render as escaped hidden inputs; both callers in `/magic-link/request` updated. **ADR-008 drafted**: `id_token` issuance design queued for "Later" — TOTP track (v0.26.0/v0.27.0) goes first per security-track sequencing. 14 new tests (8 discovery shape, 6 templates). Total 451 passing. |
| **Security track Phase 3: TOTP Phase 1 (ADR + schema + library)** | ✅       | Shipped 0.26.0. Foundation work for TOTP as a 2nd factor (RFC 6238). **ADR-009 Draft** (`docs/src/expert/adr/009-totp.md`) settles 11 design questions: SHA-1/6/30/160 algorithm parameters locked (Q1, universal authenticator-app compatibility); ±1 step skew tolerance (Q2); per-secret `last_used_step` replay protection (Q3); separate `totp_authenticators` table not WebAuthn's (Q4 — they share zero columns); AES-GCM-256 encryption at rest with AAD bound to row id (Q5); 10 SHA-256-hashed recovery codes per user matching cesauth's existing high-entropy bearer pattern (Q6); always-2nd-factor composition (Q7 — Magic Link → TOTP if configured, WebAuthn → no TOTP, Anonymous → no TOTP); QR code + manual base32 enrollment (Q8); cron sweep extension for unconfirmed pruning (Q9, lands in v0.27.0); per-tenant policy / admin TOTP / backup-code import / WebAuthn-backed TOTP / name-editing all out of scope (Q10); SCHEMA_VERSION 6 → 7 with prod→staging redaction dropping both new tables (Q11). **Migration 0007** adds `totp_authenticators` and `totp_recovery_codes` tables with full comments. **`cesauth_core::totp` library** ~700 lines: `Secret` newtype with debug redaction, `compute_code` with HMAC-SHA1 + RFC 4226 §5.3 truncation, `verify_with_replay_protection` with constant-time-eq and replay gate, `RecoveryCode` newtype with redacting Debug, `encrypt_secret`/`decrypt_secret` with AAD binding, `otpauth_uri` builder. Workspace deps added: `sha1`, `aes-gcm`, `data-encoding`. **No HTTP routes, no UI, no verify wire-up** — Phase 2 (v0.27.0). Discovered: `oidc_clients.client_secret_hash` schema comment claims Argon2 but no Argon2 implementation exists; ROADMAP "Later" item tracks resolution. 51 new tests (5 RFC 6238 reference vectors, 8 verify replay/skew, 8 encryption with AAD, 8 recovery codes, etc.). Total **502 passing**. |
| **Security track Phase 4: TOTP Phase 2a — storage layer** | ✅       | Shipped 0.27.0. Storage adapters between v0.26.0's pure-function library and v0.28.0's HTTP routes. The original v0.27.0 plan combined storage and routes; mid-implementation the storage layer alone proved substantial enough to deserve its own review-able release. **`cesauth_core::totp::storage`** submodule with `TotpAuthenticator` and `TotpRecoveryCodeRow` value types and `TotpAuthenticatorRepository` (7 methods: create, find_by_id, find_active_for_user, confirm — idempotent via `WHERE confirmed_at IS NULL`, update_last_used_step, delete, list_unconfirmed_older_than for the cron sweep) and `TotpRecoveryCodeRepository` (5 methods: bulk_create — atomic, find_unredeemed_by_hash, mark_redeemed — idempotent, count_remaining, delete_all_for_user). **`Challenge::PendingTotp`** variant for the post-MagicLink intermediate state. **In-memory adapters** in `cesauth-adapter-test` with 19 tests pinning `find_active`-picks-most-recently-confirmed semantic, atomic `bulk_create` rollback, idempotency, user-scoped delete. **D1 adapters** in `cesauth-adapter-cloudflare` mirroring in-memory shape; BLOB columns bind via `Uint8Array`; recovery code `bulk_create` uses D1's `batch()` for transactional atomicity; unconfirmed-row sweep query uses partial index from migration 0007. **`load_totp_encryption_key()` and `load_totp_encryption_key_id()`** in worker config, with pure helper `parse_totp_encryption_key` factored out for testability + 5 unit tests covering whitespace stripping, base64 errors, length validation. **No HTTP routes, no verify gate, no UI** — Phase 2b (v0.28.0). ADR-009 remains Draft pending end-to-end validation. 24 new tests. Total **526 passing**. |
| **Security track Phase 5: TOTP Phase 2b — presentation layer** | ✅       | Shipped 0.28.0. Templates + QR generator + `/me/*` auth helper between v0.27.0's storage layer and v0.29.0's HTTP routes. The v0.28.0 plan originally combined presentation + routes; mid-implementation the presentation layer alone proved review-able as its own slice. The TOTP track is now a **five-release split**: library (0.26), storage (0.27), presentation (0.28), routes (0.29), polish (0.30 — ADR Accepted). **Three new UI templates**: `totp_enroll_page(qr_svg, secret_b32, csrf)` renders the QR + manual-entry secret + confirmation form; `totp_recovery_codes_page(codes)` shows the plaintext codes once with strong "save now" warning; `totp_verify_page(csrf, error)` is the post-MagicLink prompt with a `<details>`-collapsed recovery alternative form. **18 template tests** pinning CSRF inclusion across both forms, escape behavior on every variable input, error-block conditional rendering, `<details>` placement of the recovery alternative (UX-habituation defense), no-email-leak from the verify page. **`cesauth_core::totp::qr` module** with `otpauth_to_svg(uri) -> Result<String>` using the `qrcode` 0.14 crate at `EcLevel::M` (15% recovery — pragmatic balance), 240 px min-dimension, deterministic black-on-white SVG. **7 QR tests** pinning determinism, color emission, long-URI handling, output structure. **`cesauth_worker::routes::me`** parent module with `me::auth::resolve_or_redirect` centralizing the cookie → `SessionCookie::verify` → `ActiveSessionStore::status` → 302-to-/login pipeline; `redirect_to_login()` 302 helper. **Workspace dep added**: `qrcode = { version = "0.14", default-features = false, features = ["svg"] }`. **No HTTP routes still** — the presentation layer renders in unit tests and the QR generator runs pure-function; the wire-up is v0.29.0. 25 new tests. Total **551 passing**. |
| **Security track Phase 6: TOTP Phase 2c — HTTP routes + verify gate** | ✅       | Shipped 0.29.0. Wires v0.26.0–v0.28.0's library + storage + presentation into operator-visible behavior at last. **Five new routes** in `cesauth_worker::routes::me::totp`: `GET /me/security/totp/enroll` mints a fresh secret with CSPRNG, encrypts via `aad_for_id(row_uuid)`-bound AES-GCM, parks an unconfirmed `totp_authenticators` row, sets `__Host-cesauth_totp_enroll` short-lived (15 min) cookie, builds the otpauth URI via `cesauth_core::totp::otpauth_uri`, generates QR via `cesauth_core::totp::qr::otpauth_to_svg`, renders `totp_enroll_page`. `POST /me/security/totp/enroll/confirm` validates CSRF, looks up the unconfirmed row + verifies user_id ownership, decrypts the secret, verifies the submitted code via `verify_with_replay_protection`, on success calls `confirm()` (idempotent flip + step advance + last_used_at), then iff this is the user's first confirmed authenticator (recovery_repo.count_remaining=0) mints 10 recovery codes, hashes each via `hash_recovery_code`, bulk-creates the rows, renders `totp_recovery_codes_page` with plaintexts. `GET /me/security/totp/verify` peeks `Challenge::PendingTotp`, mints CSRF, renders `totp_verify_page`. `POST /me/security/totp/verify` takes the challenge (consume), decrypts the user's authenticator secret, verifies code with replay protection, on success persists advanced `last_used_step` then calls `complete_auth_post_gate` to resume the original session-start + AuthCode-mint + redirect. On failure: re-parks with bumped attempts (MAX_ATTEMPTS=5 then bounces to /login), preserves original deadline rather than refreshing TTL, generic error message. `POST /me/security/totp/recover` canonicalizes + SHA-256-hashes the submitted recovery code, looks up via `find_unredeemed_by_hash`, marks redeemed, resumes via `complete_auth_post_gate`. **TOTP gate insertion** in `post_auth::complete_auth`: for `AuthMethod::MagicLink` only, after step 1 (AR taken), checks `find_active_for_user`; on Some(confirmed) calls `park_totp_gate_and_redirect` which carries AR fields **inline** into PendingTotp (eliminates race where the original AR handle could expire between gate-park and verify-resume — distinct improvement over the chained-handle approach considered in earlier ADR drafts), sets `__Host-cesauth_totp` (SameSite=Strict, distinct from pending-authorize's Lax), clears `__Host-cesauth_pending`, 302 to verify page. WebAuthn paths (Passkey AuthMethod) bypass the gate — WebAuthn is itself MFA-strong per ADR-009 §Q7. Storage failure on TOTP lookup fails closed with 500 rather than silently bypassing. **`complete_auth_post_gate` extracted** as `pub(crate)` from the original `complete_auth` body so both no-gate and post-TOTP-verify paths share session-start/AuthCode-mint/redirect logic. **`__Host-cesauth_totp_enroll`** (15 min TTL, generous for app-context-switch cost during enrollment scan) and **`__Host-cesauth_totp`** (5 min TTL, short to avoid abandoned prompts tying up state) cookies introduced; both SameSite=Strict (no cross-site flow involved); helpers `set_*_cookie_header`, `clear_*_cookie_header`, `extract_*` follow the same pattern as `__Host-cesauth_pending`. Routing wired in `worker::lib::main` (5 new routes). 12 new tests in `post_auth::tests` pinning cookie shape (Max-Age preserved, HttpOnly + Secure + SameSite=Strict, `__Host-` prefix), TTL bounds (gate 1-10 min, enroll 5-30 min), distinct-cookie-name property between gate and enroll (must-not-cross-context defense). The route handlers themselves (~800 lines across 3 files) are integration-tested via the existing webauthn / magic-link patterns; v0.30.0 will add explicit handler tests after the disable + cron + redaction work consolidates the test fixture surface. 12 new tests. Total **563 passing**. |
| mdBook documentation                   | ✅       | `docs/`                                            |

---

## Planned (0.x)

Approximate priority order. Items near the top are closer to being
started.

### Next minor releases

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
  - **0.30.0** — TOTP Phase 2d: polish + operations.
    Disable flow (`POST /me/security/totp/disable`), cron
    sweep extension (drops unconfirmed rows older than
    24h), `cesauth-migrate` redaction profile drops both
    TOTP tables for prod→staging, new chapter
    `docs/src/deployment/totp.md` documenting encryption
    key configuration / rotation / admin reset path,
    `TOTP_ENCRYPTION_KEY` added to pre-production release
    gate in `docs/src/expert/security.md`. **ADR-009
    graduates from `Draft` to `Accepted`** at this point —
    the design has been validated end-to-end by the prior
    releases.
  - **0.31.0** — Audit log hash chain Phase 1: ADR-010 +
    chain design + values (previous_hash column, computed
    hash on insert) + transition strategy for existing
    pre-chain rows. No automated integrity sweep yet.
  - **0.32.0** — Audit log hash chain Phase 2: integrity
    sweep cron + admin verification UI (display "chain
    valid through row N" + flag unexpected gaps).
  - **0.33.0** — Refresh token reuse detection hardening:
    audit current `RefreshTokenFamily` DO behavior against
    OAuth 2.0 Security BCP (RFC 6749 §10.4 / draft-ietf-
    oauth-security-topics §4.13), close any gaps. The
    "use a refresh token twice → revoke the entire family"
    invariant is the load-bearing one.
  - **0.34.0** — Session management hardening + `/me/security`
    self-service UI: session-id rotation on login, idle and
    absolute timeouts, "new device" notification path,
    user-facing list of active sessions with revoke buttons.

  After this track completes (now 11 phases instead of the
  original 8 — the v0.27.0 split added one and the v0.28.0
  split added two more), the schedule reverts to the feature
  track (RFC 7662 Token Introspection, etc.).

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
    added; the pre-1.0 SemVer caveat permits the hard rename.

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

- **Property-based tests (`proptest`) for round-trip and
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

- **`cargo fuzz` for the JWT parser surface.** cesauth
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

- **WebAuthn error → typed client responses.** The current
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

- **`oidc_clients.client_secret_hash` documentation drift.**
  The schema comment in `migrations/0001_initial.sql` describes
  `client_secret_hash` as "argon2id(secret) or NULL", but no
  Argon2 implementation exists in cesauth as of v0.26.0 — the
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

- **OIDC `id_token` issuance.** Drafted as ADR-008 in v0.25.0.
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

  **Scheduled when**: TOTP track (v0.26.0 - v0.30.0) completes.
  Likely v0.31.0 or later, deferred behind the audit-log-hash-
  chain track which currently has the next-up slots.
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
